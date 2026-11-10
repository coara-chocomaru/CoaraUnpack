package com.coara.unpack;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Properties;

public final class Avb1Signer {
    private static final byte[] RSA_SHA256_ALGORITHM = sequence(
            oid(new int[]{1, 2, 840, 113549, 1, 1, 11}),
            new byte[]{0x05, 0x00}
    );
    private static final byte[] RSA_ENCRYPTION_OID = oid(new int[]{1, 2, 840, 113549, 1, 1, 1});
    private static final byte[] CN_OID = new byte[]{0x06, 0x03, 0x55, 0x04, 0x03};
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int MAX_KEY_FILE_SIZE = 1024 * 1024;
    private static final int MAX_CONFIG_SIZE = 16 * 1024;

    private Avb1Signer() {
    }

    public static synchronized byte[] sign(String payloadPath, String keyDirectoryPath, long offset, long length, String target) throws Exception {
        if (offset < 0 || length < 0 || offset > Long.MAX_VALUE - length) throw new IllegalArgumentException("AVB1署名対象の範囲が不正です");
        File payload = new File(payloadPath);
        if (!payload.isFile() || offset + length > payload.length()) throw new IllegalArgumentException("AVB1署名対象ファイルの範囲が不正です");
        File keyDirectory = new File(keyDirectoryPath);
        if (!keyDirectory.isDirectory() || !keyDirectory.canRead() || !keyDirectory.canWrite()) throw new IllegalStateException("AVB1鍵を配置する作業フォルダにアクセスできません: " + keyDirectoryPath);
        validateTarget(target);
        KeyMaterial material = loadOrCreate(keyDirectory);
        byte[] attributes = sequence(
                tlv(0x13, target.getBytes(StandardCharsets.US_ASCII)),
                integer(BigInteger.valueOf(length))
        );
        Signature signer = Signature.getInstance(material.signatureAlgorithm);
        Signature verifier = Signature.getInstance(material.signatureAlgorithm);
        signer.initSign(material.privateKey, RANDOM);
        verifier.initVerify(material.certificate.getPublicKey());
        updateRange(signer, verifier, payload, offset, length);
        signer.update(attributes);
        verifier.update(attributes);
        byte[] signature = signer.sign();
        if (!verifier.verify(signature)) throw new IllegalStateException("AVB1署名の自己検証に失敗しました");
        return sequence(
                integer(BigInteger.ONE),
                material.certificate.getEncoded(),
                material.algorithmIdentifier,
                attributes,
                tlv(0x04, signature)
        );
    }

    private static void updateRange(Signature signer, Signature verifier, File file, long offset, long length) throws Exception {
        try (FileInputStream input = new FileInputStream(file)) {
            long skipped = 0;
            while (skipped < offset) {
                long n = input.skip(offset - skipped);
                if (n <= 0) {
                    if (input.read() < 0) throw new IllegalArgumentException("AVB1署名対象を読み込めません");
                    n = 1;
                }
                skipped += n;
            }
            byte[] buffer = new byte[262144];
            long remaining = length;
            while (remaining > 0) {
                int count = input.read(buffer, 0, (int) Math.min(buffer.length, remaining));
                if (count < 0) throw new IllegalArgumentException("AVB1署名対象が途中で切れています");
                if (count == 0) continue;
                signer.update(buffer, 0, count);
                verifier.update(buffer, 0, count);
                remaining -= count;
            }
        }
    }

    private static KeyMaterial loadOrCreate(File directory) throws Exception {
        File canonicalDirectory = directory.getCanonicalFile();
        KeyFiles files = selectKeyFiles(canonicalDirectory);
        boolean privateExists = files.privateKey.isFile();
        boolean certificateExists = files.certificate.isFile();
        if (privateExists != certificateExists) {
            throw new IllegalStateException("AVB1鍵ペアが不完全です。秘密鍵 " + files.privateKey.getName() + " と証明書 " + files.certificate.getName() + " の両方を配置してください。既存ファイルは上書きしません");
        }
        if (privateExists) {
            KeyMaterial material = readKeyMaterial(files.privateKey, files.certificate);
            log("AVB1: 作業フォルダ内の鍵を使用します: " + files.privateKey.getName() + " / " + files.certificate.getName());
            return material;
        }
        if (files.privateKey.exists() || files.certificate.exists()) {
            throw new IllegalStateException("AVB1鍵ファイルが通常のファイルではありません");
        }
        KeyMaterial generated = generateKeyMaterial();
        saveKeyPair(canonicalDirectory, files, generated);
        KeyMaterial saved = readKeyMaterial(files.privateKey, files.certificate);
        log("AVB1: 鍵が無かったためRSA-2048鍵ペアを生成して作業フォルダへ保存しました: " + files.privateKey.getName() + " / " + files.certificate.getName());
        return saved;
    }

    private static KeyFiles selectKeyFiles(File directory) throws Exception {
        File config = new File(directory, "avb1-key.properties");
        if (config.exists()) {
            if (!config.isFile() || config.length() <= 0 || config.length() > MAX_CONFIG_SIZE) throw new IllegalStateException("avb1-key.properties が不正です");
            Properties properties = new Properties();
            try (InputStreamReader reader = new InputStreamReader(new FileInputStream(config), StandardCharsets.UTF_8)) {
                properties.load(reader);
            }
            String privateName = validateFileName(properties.getProperty("private_key", "testkey.pk8").trim());
            String certificateName = validateFileName(properties.getProperty("certificate", "testkey.x509.pem").trim());
            if (privateName.equals(certificateName)) throw new IllegalStateException("秘密鍵と証明書に同じファイル名は指定できません");
            return new KeyFiles(safeChild(directory, privateName), safeChild(directory, certificateName));
        }

        File standardPrivate = new File(directory, "testkey.pk8");
        File standardCertificate = new File(directory, "testkey.x509.pem");
        boolean hasStandardPrivate = standardPrivate.exists();
        boolean hasStandardCertificate = standardCertificate.exists();
        if (hasStandardPrivate != hasStandardCertificate) return new KeyFiles(standardPrivate, standardCertificate);

        File[] entries = directory.listFiles();
        if (entries == null) throw new IllegalStateException("作業フォルダのファイル一覧を取得できません");
        List<KeyFiles> pairs = new ArrayList<>();
        List<String> incomplete = new ArrayList<>();
        for (File entry : entries) {
            String name = entry.getName();
            if (!entry.isFile() || !name.endsWith(".pk8")) continue;
            String stem = name.substring(0, name.length() - 4);
            File cert = new File(directory, stem + ".x509.pem");
            if (cert.isFile()) pairs.add(new KeyFiles(entry, cert));
            else incomplete.add(name + " / " + cert.getName());
        }
        for (File entry : entries) {
            String name = entry.getName();
            if (!entry.isFile() || !name.endsWith(".x509.pem")) continue;
            String stem = name.substring(0, name.length() - ".x509.pem".length());
            File key = new File(directory, stem + ".pk8");
            if (!key.isFile()) incomplete.add(key.getName() + " / " + name);
        }

        if (hasStandardPrivate && hasStandardCertificate) {
            for (KeyFiles pair : pairs) {
                if (!pair.privateKey.getName().equals("testkey.pk8")) {
                    throw new IllegalStateException("AVB1鍵ペアが複数あります。testkey.* を置き換えるか、avb1-key.properties で使用する鍵を指定してください");
                }
            }
            if (!incomplete.isEmpty()) throw new IllegalStateException("作業フォルダに不完全なAVB1鍵ファイルがあります。不要な鍵ファイルを整理するか avb1-key.properties で使用する鍵を指定してください");
            return new KeyFiles(standardPrivate, standardCertificate);
        }
        if (pairs.size() == 1 && incomplete.isEmpty()) return pairs.get(0);
        if (pairs.size() > 1) throw new IllegalStateException("AVB1鍵ペアが複数あります。avb1-key.properties で使用するファイル名を指定してください");
        if (!incomplete.isEmpty()) throw new IllegalStateException("AVB1鍵ファイルの片方だけが見つかりました。秘密鍵(.pk8)と証明書(.x509.pem)を同じ名前で揃えてください");
        return new KeyFiles(standardPrivate, standardCertificate);
    }

    private static File safeChild(File directory, String name) throws Exception {
        File file = new File(directory, name).getCanonicalFile();
        if (!directory.getCanonicalFile().equals(file.getParentFile())) throw new IllegalArgumentException("AVB1鍵ファイルは作業フォルダ直下に指定してください");
        return file;
    }

    private static String validateFileName(String name) {
        if (name == null || name.isEmpty() || name.length() > 128 || name.equals(".") || name.equals("..") ||
                name.indexOf('/') >= 0 || name.indexOf('\\') >= 0 || name.indexOf('\n') >= 0 || name.indexOf('\r') >= 0 || name.indexOf('\0') >= 0) {
            throw new IllegalArgumentException("avb1-key.properties のファイル名が不正です");
        }
        return name;
    }

    private static void saveKeyPair(File directory, KeyFiles files, KeyMaterial material) throws Exception {
        if (files.privateKey.exists() || files.certificate.exists()) throw new IllegalStateException("AVB1鍵ファイルが既に存在するため、自動生成を中止しました");
        String suffix = ".tmp-" + Long.toHexString(System.nanoTime());
        File privateTemp = new File(directory, files.privateKey.getName() + suffix);
        File certificateTemp = new File(directory, files.certificate.getName() + suffix);
        boolean privateMoved = false;
        boolean certificateMoved = false;
        try {
            writeSynced(privateTemp, material.privateKey.getEncoded());
            setPrivatePermissions(privateTemp);
            String pem = "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(material.certificate.getEncoded()) + "\n-----END CERTIFICATE-----\n";
            writeSynced(certificateTemp, pem.getBytes(StandardCharsets.US_ASCII));
            setPublicPermissions(certificateTemp);
            if (!privateTemp.renameTo(files.privateKey)) throw new IllegalStateException("AVB1秘密鍵を作業フォルダへ保存できません: " + files.privateKey.getName());
            privateMoved = true;
            if (!certificateTemp.renameTo(files.certificate)) throw new IllegalStateException("AVB1証明書を作業フォルダへ保存できません: " + files.certificate.getName());
            certificateMoved = true;
            setPrivatePermissions(files.privateKey);
            setPublicPermissions(files.certificate);
        } catch (Exception e) {
            if (privateMoved) files.privateKey.delete();
            if (certificateMoved) files.certificate.delete();
            throw e;
        } finally {
            privateTemp.delete();
            certificateTemp.delete();
        }
    }

    private static KeyMaterial readKeyMaterial(File privateFile, File certificateFile) throws Exception {
        if (isSymbolicLink(privateFile) || isSymbolicLink(certificateFile)) throw new IllegalArgumentException("AVB1鍵ファイルにシンボリックリンクは使用できません");
        byte[] privateBytes = readAll(privateFile, MAX_KEY_FILE_SIZE);
        byte[] certificateBytes = readAll(certificateFile, MAX_KEY_FILE_SIZE);
        byte[] privateDer = decodePrivateKey(privateBytes);
        byte[] certificateDer = decodePemOrDer(certificateBytes, "CERTIFICATE");
        PrivateKey privateKey = loadPrivateKey(privateDer);
        X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new java.io.ByteArrayInputStream(certificateDer));
        String oid = certificate.getSigAlgOID();
        String signatureAlgorithm;
        int requiredEcBits = 0;
        if ("1.2.840.113549.1.1.11".equals(oid)) {
            signatureAlgorithm = "SHA256withRSA";
            if (!(privateKey instanceof RSAKey) || !(certificate.getPublicKey() instanceof RSAKey)) throw new IllegalArgumentException("証明書の署名方式とRSA鍵の種類が一致しません");
            if (((RSAKey) certificate.getPublicKey()).getModulus().bitLength() < 2048) throw new IllegalArgumentException("AVB1のRSA公開鍵は2048 bit以上が必要です");
        } else if ("1.2.840.10045.4.3.2".equals(oid)) {
            signatureAlgorithm = "SHA256withECDSA";
            requiredEcBits = 256;
        } else if ("1.2.840.10045.4.3.3".equals(oid)) {
            signatureAlgorithm = "SHA384withECDSA";
            requiredEcBits = 384;
        } else if ("1.2.840.10045.4.3.4".equals(oid)) {
            signatureAlgorithm = "SHA512withECDSA";
            requiredEcBits = 521;
        } else {
            throw new IllegalArgumentException("未対応のAVB1証明書署名アルゴリズムです: " + oid + " (RSA/SHA-256 または ECDSA/P-256・P-384・P-521 を使用してください)");
        }
        if (requiredEcBits != 0) {
            if (!(privateKey instanceof ECKey) || !(certificate.getPublicKey() instanceof ECKey)) throw new IllegalArgumentException("証明書の署名方式とEC鍵の種類が一致しません");
            int privateBits = ((ECKey) privateKey).getParams().getCurve().getField().getFieldSize();
            int publicBits = ((ECKey) certificate.getPublicKey()).getParams().getCurve().getField().getFieldSize();
            if (privateBits != requiredEcBits || publicBits != requiredEcBits) throw new IllegalArgumentException("AVB1のECDSA鍵サイズが証明書の署名方式と一致しません");
        }
        byte[] algorithmIdentifier = extractSignatureAlgorithmIdentifier(certificate.getEncoded());
        if (!keyMatches(privateKey, certificate, signatureAlgorithm)) throw new IllegalArgumentException("AVB1秘密鍵とX.509証明書の公開鍵が一致しません");
        return new KeyMaterial(privateKey, certificate, algorithmIdentifier, signatureAlgorithm);
    }

    private static PrivateKey loadPrivateKey(byte[] der) throws Exception {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
        Exception last = null;
        for (String algorithm : new String[]{"RSA", "EC"}) {
            try {
                return KeyFactory.getInstance(algorithm).generatePrivate(spec);
            } catch (Exception e) {
                last = e;
            }
        }
        throw new IllegalArgumentException("秘密鍵を読み込めません。Android標準のPKCS#8形式(.pk8)を使用してください", last);
    }

    private static byte[] decodePrivateKey(byte[] bytes) throws Exception {
        String text = new String(bytes, StandardCharsets.US_ASCII).trim();
        if (!text.startsWith("-----BEGIN ")) return bytes;
        if (text.startsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----")) throw new IllegalArgumentException("パスワード付き秘密鍵には対応していません。暗号化されていないPKCS#8鍵を使用してください");
        if (text.startsWith("-----BEGIN PRIVATE KEY-----")) return decodePemOrDer(bytes, "PRIVATE KEY");
        if (text.startsWith("-----BEGIN RSA PRIVATE KEY-----")) {
            byte[] pkcs1 = decodePemOrDer(bytes, "RSA PRIVATE KEY");
            return sequence(integer(BigInteger.ZERO), sequence(RSA_ENCRYPTION_OID, tlv(0x05, new byte[0])), tlv(0x04, pkcs1));
        }
        throw new IllegalArgumentException("未対応の秘密鍵PEM形式です。PKCS#8形式(.pk8)を使用してください");
    }

    private static byte[] decodePemOrDer(byte[] bytes, String label) throws Exception {
        String text = new String(bytes, StandardCharsets.US_ASCII).trim();
        String begin = "-----BEGIN " + label + "-----";
        String end = "-----END " + label + "-----";
        if (!text.startsWith("-----BEGIN ")) return bytes;
        if (!text.contains(begin) || !text.contains(end)) throw new IllegalArgumentException("PEMファイルの形式が不正です: " + label);
        String body = text.substring(text.indexOf(begin) + begin.length(), text.indexOf(end));
        body = body.replaceAll("\\s", "");
        return Base64.getDecoder().decode(body);
    }

    private static byte[] extractSignatureAlgorithmIdentifier(byte[] certificateDer) throws Exception {
        DerElement outer = readElement(certificateDer, 0, certificateDer.length);
        if (outer.tag != 0x30 || outer.end != certificateDer.length) throw new IllegalArgumentException("X.509証明書のDER構造が不正です");
        DerElement tbs = readElement(certificateDer, outer.valueOffset, outer.end);
        if (tbs.tag != 0x30) throw new IllegalArgumentException("X.509証明書のTBSCertificateが不正です");
        DerElement algorithm = readElement(certificateDer, tbs.end, outer.end);
        if (algorithm.tag != 0x30) throw new IllegalArgumentException("X.509証明書の署名アルゴリズムが不正です");
        return Arrays.copyOfRange(certificateDer, algorithm.start, algorithm.end);
    }

    private static DerElement readElement(byte[] data, int offset, int limit) {
        if (offset < 0 || limit > data.length || offset > limit - 2) throw new IllegalArgumentException("DERデータが途中で切れています");
        int tag = data[offset] & 0xff;
        int first = data[offset + 1] & 0xff;
        int headerLength = 2;
        long valueLength;
        if (first < 0x80) {
            valueLength = first;
        } else {
            int count = first & 0x7f;
            if (count < 1 || count > 4 || offset + 2 + count > limit || data[offset + 2] == 0) throw new IllegalArgumentException("DERの長さフィールドが不正です");
            valueLength = 0;
            for (int i = 0; i < count; i++) valueLength = (valueLength << 8) | (data[offset + 2 + i] & 0xff);
            if (valueLength < 128) throw new IllegalArgumentException("DERの長さ表現が正規化されていません");
            headerLength += count;
        }
        if (valueLength > Integer.MAX_VALUE || valueLength > limit - offset - headerLength) throw new IllegalArgumentException("DERのデータ長が不正です");
        int valueOffset = offset + headerLength;
        return new DerElement(tag, offset, valueOffset, valueOffset + (int) valueLength);
    }

    private static boolean keyMatches(PrivateKey privateKey, X509Certificate certificate, String algorithm) throws Exception {
        byte[] challenge = "Coara AVB1 key validation".getBytes(StandardCharsets.US_ASCII);
        Signature signer = Signature.getInstance(algorithm);
        signer.initSign(privateKey, RANDOM);
        signer.update(challenge);
        byte[] signed = signer.sign();
        Signature verifier = Signature.getInstance(algorithm);
        verifier.initVerify(certificate.getPublicKey());
        verifier.update(challenge);
        return verifier.verify(signed);
    }

    private static KeyMaterial generateKeyMaterial() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, RANDOM);
        KeyPair pair = generator.generateKeyPair();
        byte[] certificateDer = createCertificate(pair);
        X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new java.io.ByteArrayInputStream(certificateDer));
        certificate.verify(pair.getPublic());
        return new KeyMaterial(pair.getPrivate(), certificate, extractSignatureAlgorithmIdentifier(certificateDer), "SHA256withRSA");
    }

    private static byte[] createCertificate(KeyPair pair) throws Exception {
        byte[] serialBytes = new byte[20];
        RANDOM.nextBytes(serialBytes);
        BigInteger serial = new BigInteger(1, serialBytes);
        if (serial.signum() == 0) serial = BigInteger.ONE;
        byte[] name = sequence(tlv(0x31, sequence(
                CN_OID,
                tlv(0x0c, "Coara AVB1 Test Key".getBytes(StandardCharsets.UTF_8))
        )));
        byte[] validity = sequence(
                tlv(0x17, "000101000000Z".getBytes(StandardCharsets.US_ASCII)),
                tlv(0x17, "491231235959Z".getBytes(StandardCharsets.US_ASCII))
        );
        byte[] version = tlv(0xa0, integer(BigInteger.valueOf(2)));
        byte[] tbs = sequence(
                version,
                integer(serial),
                RSA_SHA256_ALGORITHM,
                name,
                validity,
                name,
                pair.getPublic().getEncoded()
        );
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(pair.getPrivate(), RANDOM);
        signer.update(tbs);
        byte[] signature = signer.sign();
        return sequence(tbs, RSA_SHA256_ALGORITHM, tlv(0x03, concatenate(new byte[]{0}, signature)));
    }

    private static byte[] readAll(File file, int maxSize) throws Exception {
        if (!file.isFile() || !file.canRead() || file.length() <= 0 || file.length() > maxSize) throw new IllegalArgumentException("AVB1鍵ファイルを読み込めないか、サイズが上限を超えています: " + file.getName());
        try (FileInputStream input = new FileInputStream(file)) {
            ByteArrayOutputStream output = new ByteArrayOutputStream((int) file.length());
            byte[] buffer = new byte[8192];
            int count;
            while ((count = input.read(buffer)) != -1) {
                if (count > 0) {
                    if (output.size() > maxSize - count) throw new IllegalArgumentException("AVB1鍵ファイルが大きすぎます: " + file.getName());
                    output.write(buffer, 0, count);
                }
            }
            return output.toByteArray();
        }
    }

    private static void writeSynced(File file, byte[] data) throws Exception {
        try (FileOutputStream output = new FileOutputStream(file)) {
            output.write(data);
            output.getFD().sync();
        }
    }

    private static void setPrivatePermissions(File file) {
        try {
            android.system.Os.chmod(file.getAbsolutePath(), 0600);
        } catch (Throwable ignored) {
            file.setReadable(false, false);
            file.setWritable(false, false);
            file.setReadable(true, true);
            file.setWritable(true, true);
        }
    }

    private static void setPublicPermissions(File file) {
        try {
            android.system.Os.chmod(file.getAbsolutePath(), 0644);
        } catch (Throwable ignored) {
            file.setReadable(true, false);
            file.setWritable(false, false);
            file.setWritable(true, true);
        }
    }

    private static boolean isSymbolicLink(File file) {
        try {
            return java.nio.file.Files.isSymbolicLink(file.toPath());
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static void log(String message) {
        try {
            NativeBridge.onLog(message);
        } catch (Throwable ignored) {
        }
    }

    private static void validateTarget(String target) {
        if (target == null || target.isEmpty() || target.length() > 64) throw new IllegalArgumentException("AVB1署名対象名が不正です");
        for (int i = 0; i < target.length(); i++) {
            char c = target.charAt(i);
            boolean valid = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                    " '()+,-./:=?".indexOf(c) >= 0;
            if (!valid) throw new IllegalArgumentException("AVB1署名対象名に使用できない文字があります");
        }
    }

    private static byte[] oid(int[] values) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        output.write(values[0] * 40 + values[1]);
        for (int i = 2; i < values.length; i++) {
            int value = values[i];
            byte[] encoded = new byte[5];
            int position = encoded.length;
            encoded[--position] = (byte) (value & 0x7f);
            value >>>= 7;
            while (value != 0) {
                encoded[--position] = (byte) ((value & 0x7f) | 0x80);
                value >>>= 7;
            }
            output.write(encoded, position, encoded.length - position);
        }
        return tlv(0x06, output.toByteArray());
    }

    private static byte[] integer(BigInteger value) {
        return tlv(0x02, value.toByteArray());
    }

    private static byte[] sequence(byte[]... values) {
        return tlv(0x30, concatenate(values));
    }

    private static byte[] tlv(int tag, byte[] value) {
        ByteArrayOutputStream output = new ByteArrayOutputStream(value.length + 6);
        output.write(tag);
        int length = value.length;
        if (length < 128) {
            output.write(length);
        } else {
            int count = 0;
            int n = length;
            while (n != 0) {
                count++;
                n >>>= 8;
            }
            output.write(0x80 | count);
            for (int i = count - 1; i >= 0; i--) output.write((length >>> (i * 8)) & 0xff);
        }
        output.write(value, 0, value.length);
        return output.toByteArray();
    }

    private static byte[] concatenate(byte[]... values) {
        int total = 0;
        for (byte[] value : values) {
            if (value.length > Integer.MAX_VALUE - total) throw new IllegalArgumentException("DERデータが大きすぎます");
            total += value.length;
        }
        byte[] result = new byte[total];
        int offset = 0;
        for (byte[] value : values) {
            System.arraycopy(value, 0, result, offset, value.length);
            offset += value.length;
        }
        return result;
    }

    private static final class KeyFiles {
        final File privateKey;
        final File certificate;

        KeyFiles(File privateKey, File certificate) {
            this.privateKey = privateKey;
            this.certificate = certificate;
        }
    }

    private static final class KeyMaterial {
        final PrivateKey privateKey;
        final X509Certificate certificate;
        final byte[] algorithmIdentifier;
        final String signatureAlgorithm;

        KeyMaterial(PrivateKey privateKey, X509Certificate certificate, byte[] algorithmIdentifier, String signatureAlgorithm) {
            this.privateKey = privateKey;
            this.certificate = certificate;
            this.algorithmIdentifier = algorithmIdentifier;
            this.signatureAlgorithm = signatureAlgorithm;
        }
    }

    private static final class DerElement {
        final int tag;
        final int start;
        final int valueOffset;
        final int end;

        DerElement(int tag, int start, int valueOffset, int end) {
            this.tag = tag;
            this.start = start;
            this.valueOffset = valueOffset;
            this.end = end;
        }
    }
}
