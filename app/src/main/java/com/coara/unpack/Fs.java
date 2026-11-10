package com.coara.unpack;

import android.content.ContentResolver;
import android.content.Context;
import android.net.Uri;
import android.os.Environment;
import android.os.StatFs;
import android.provider.OpenableColumns;
import android.database.Cursor;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

public final class Fs {

    private Fs() {
    }

    public static File downloadDir() {
        return Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
    }

    public static String stamp() {
        return new SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(new Date());
    }

    public static String stripExt(String name) {
        int dot = name.lastIndexOf('.');
        return dot > 0 ? name.substring(0, dot) : name;
    }

    public static String safeName(String name) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (c < 32 || c == '/' || c == '\\' || c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|') {
                sb.append('_');
            } else {
                sb.append(c);
            }
        }
        String r = sb.toString().trim();
        return r.isEmpty() ? "image" : r;
    }

    public static File unique(File parent, String name) {
        File f = new File(parent, name);
        if (!f.exists()) return f;
        String base = stripExt(name);
        String ext = name.substring(base.length());
        for (int i = 2; i < 1000; i++) {
            File c = new File(parent, base + "_" + i + ext);
            if (!c.exists()) return c;
        }
        return new File(parent, base + "_" + System.nanoTime() + ext);
    }

    public static void deleteRecursive(File f) {
        if (f == null) return;
        try {
            if (Files.isDirectory(f.toPath(), LinkOption.NOFOLLOW_LINKS)) {
                File[] kids = f.listFiles();
                if (kids != null) {
                    for (File k : kids) deleteRecursive(k);
                }
            }
        } catch (Throwable ignored) {
        }
        f.delete();
    }

    public static boolean probeWritable(File dir) {
        try {
            if (!dir.exists() && !dir.mkdirs()) return false;
            if (!dir.isDirectory()) return false;
            File t = new File(dir, ".coara_probe_" + System.nanoTime());
            try (FileOutputStream o = new FileOutputStream(t)) {
                o.write(1);
                o.getFD().sync();
            }
            return t.delete();
        } catch (Throwable e) {
            return false;
        }
    }

    public static long usable(File dir) {
        File p = dir;
        while (p != null && !p.exists()) p = p.getParentFile();
        if (p == null) return -1;
        try {
            StatFs s = new StatFs(p.getAbsolutePath());
            return s.getAvailableBytes();
        } catch (Throwable e) {
            return -1;
        }
    }

    public static String readValue(File info, String key) {
        if (info == null || !info.isFile()) return "";
        String prefix = key + "=";
        try (BufferedReader r = new BufferedReader(new InputStreamReader(new FileInputStream(info), StandardCharsets.UTF_8), 1 << 16)) {
            String line;
            int n = 0;
            while ((line = r.readLine()) != null && n++ < 2000) {
                if (line.startsWith(prefix)) return line.substring(prefix.length());
            }
        } catch (IOException ignored) {
        }
        return "";
    }

    public static String human(long n) {
        if (n < 1024) return n + " B";
        double v = n;
        String[] u = {"KiB", "MiB", "GiB", "TiB"};
        int i = -1;
        while (v >= 1024 && i < u.length - 1) {
            v /= 1024;
            i++;
        }
        return String.format(Locale.US, "%.2f %s", v, u[i]);
    }

    public static String rdExt(String fmt) {
        switch (fmt) {
            case "gzip":
                return ".cpio.gz";
            case "lz4":
            case "lz4_legacy":
            case "lz4_lg":
                return ".cpio.lz4";
            case "xz":
                return ".cpio.xz";
            case "lzma":
                return ".cpio.lzma";
            case "bzip2":
                return ".cpio.bz2";
            default:
                return ".cpio";
        }
    }

    public static String displayName(Context ctx, Uri uri) {
        String name = null;
        try (Cursor c = ctx.getContentResolver().query(uri, new String[]{OpenableColumns.DISPLAY_NAME}, null, null, null)) {
            if (c != null && c.moveToFirst()) name = c.getString(0);
        } catch (Throwable ignored) {
        }
        if (name == null || name.isEmpty()) {
            String p = uri.getLastPathSegment();
            name = p == null ? "image.img" : p.substring(p.lastIndexOf('/') + 1);
        }
        return safeName(name);
    }

    public static File copyUri(Context ctx, Uri uri, File dstDir, String name, CancelCheck cancel) throws IOException {
        if (!dstDir.exists() && !dstDir.mkdirs()) throw new IOException("cache");
        File dst = new File(dstDir, name);
        ContentResolver cr = ctx.getContentResolver();
        try (InputStream in = cr.openInputStream(uri); OutputStream out = new FileOutputStream(dst)) {
            if (in == null) throw new IOException("open");
            byte[] buf = new byte[1 << 20];
            int n;
            while ((n = in.read(buf)) > 0) {
                if (cancel != null && cancel.isCanceled()) throw new IOException("canceled");
                out.write(buf, 0, n);
            }
        } catch (IOException e) {
            dst.delete();
            throw e;
        }
        return dst;
    }

    public interface CancelCheck {
        boolean isCanceled();
    }
}
