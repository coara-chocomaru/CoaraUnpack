#include "avb.h"
#include "hash.h"

namespace cu {

static const char* algName(uint32_t a) {
    switch (a) {
    case 0: return "NONE";
    case 1: return "SHA256_RSA2048";
    case 2: return "SHA256_RSA4096";
    case 3: return "SHA256_RSA8192";
    case 4: return "SHA512_RSA2048";
    case 5: return "SHA512_RSA4096";
    case 6: return "SHA512_RSA8192";
    default: return "UNKNOWN";
    }
}

static bool derHdr(const uint8_t* p, size_t n, size_t pos, uint8_t& tag, size_t& hl, size_t& len) {
    if (!p || pos > n || n - pos < 2) return false;
    tag = p[pos];
    uint8_t l = p[pos + 1];
    if (l < 0x80) {
        hl = 2;
        len = l;
        return true;
    }
    int nb = l & 0x7f;
    if (nb < 1 || nb > 4 || n - pos - 2 < (size_t)nb || p[pos + 2] == 0) return false;
    size_t v = 0;
    for (int i = 0; i < nb; i++) {
        if (v > (SIZE_MAX >> 8)) return false;
        v = (v << 8) | p[pos + 2 + i];
    }
    if (v < 128) return false;
    hl = 2 + (size_t)nb;
    len = v;
    return true;
}

bool parseBootSignature(View tail, size_t& derLen, std::string& target, uint64_t& signedLen) {
    const uint8_t* p = tail.p;
    size_t n = tail.n;
    uint8_t tag = 0;
    size_t hl = 0, len = 0;
    if (n < 16 || !derHdr(p, n, 0, tag, hl, len) || tag != 0x30 || len > n - hl || len < 64) return false;
    size_t end = hl + len;
    size_t pos = hl;
    auto take = [&](uint8_t expected, size_t& valuePos, size_t& valueLen) {
        size_t fieldHeader = 0, fieldLength = 0;
        uint8_t fieldTag = 0;
        if (!derHdr(p, end, pos, fieldTag, fieldHeader, fieldLength) || fieldTag != expected) return false;
        if (fieldHeader > end - pos || fieldLength > end - pos - fieldHeader) return false;
        valuePos = pos + fieldHeader;
        valueLen = fieldLength;
        pos += fieldHeader + fieldLength;
        return true;
    };
    size_t valuePos = 0, valueLen = 0;
    if (!take(0x02, valuePos, valueLen) || valueLen != 1 || p[valuePos] != 1) return false;
    if (!take(0x30, valuePos, valueLen) || valueLen < 128) return false;
    if (!take(0x30, valuePos, valueLen) || valueLen < 3) return false;

    size_t attrHeader = 0, attrLength = 0;
    if (!derHdr(p, end, pos, tag, attrHeader, attrLength) || tag != 0x30) return false;
    if (attrHeader > end - pos || attrLength > end - pos - attrHeader) return false;
    size_t attrEnd = pos + attrHeader + attrLength;
    size_t attrPos = pos + attrHeader;
    size_t targetHeader = 0, targetLength = 0;
    if (!derHdr(p, attrEnd, attrPos, tag, targetHeader, targetLength) || (tag != 0x13 && tag != 0x0c && tag != 0x16)) return false;
    if (targetHeader > attrEnd - attrPos || targetLength == 0 || targetLength > 64 || targetLength > attrEnd - attrPos - targetHeader) return false;
    target.assign((const char*)p + attrPos + targetHeader, targetLength);
    attrPos += targetHeader + targetLength;
    size_t lengthHeader = 0, lengthLength = 0;
    if (!derHdr(p, attrEnd, attrPos, tag, lengthHeader, lengthLength) || tag != 0x02 || lengthLength == 0 || lengthLength > 8) return false;
    if (lengthHeader > attrEnd - attrPos || lengthLength != attrEnd - attrPos - lengthHeader) return false;
    if (p[attrPos + lengthHeader] & 0x80) return false;
    if (lengthLength > 1 && p[attrPos + lengthHeader] == 0 && !(p[attrPos + lengthHeader + 1] & 0x80)) return false;
    uint64_t parsedLength = 0;
    for (size_t i = 0; i < lengthLength; i++) parsedLength = (parsedLength << 8) | p[attrPos + lengthHeader + i];
    if (attrPos + lengthHeader + lengthLength != attrEnd) return false;
    signedLen = parsedLength;
    pos = attrEnd;

    size_t signatureHeader = 0, signatureLength = 0;
    if (!derHdr(p, end, pos, tag, signatureHeader, signatureLength) || tag != 0x04) return false;
    if (signatureHeader > end - pos || signatureLength > end - pos - signatureHeader) return false;
    pos += signatureHeader + signatureLength;
    if (pos != end) return false;
    derLen = end;
    return true;
}

void avbDescribe(View m, InfoWriter& w, const std::string& pfx) {
    if (m.n < 256 || memcmp(m.p, "AVB0", 4) != 0) return;
    const uint8_t* h = m.p;
    uint64_t authSz = rd64be(h + 12), auxSz = rd64be(h + 20);
    uint32_t algo = rd32be(h + 28);
    uint64_t hashOff = rd64be(h + 32), hashSz = rd64be(h + 40), sigOff = rd64be(h + 48), sigSz = rd64be(h + 56);
    uint64_t pkOff = rd64be(h + 64), pkSz = rd64be(h + 72), pkmOff = rd64be(h + 80), pkmSz = rd64be(h + 88);
    uint64_t descOff = rd64be(h + 96), descSz = rd64be(h + 104), rollback = rd64be(h + 112);
    uint32_t flags = rd32be(h + 120), rbLoc = rd32be(h + 124);
    w.kv(pfx + ".required_libavb_version", fmtstr("%u.%u", rd32be(h + 4), rd32be(h + 8)));
    w.kvu(pfx + ".authentication_data_block_size", authSz);
    w.kvu(pfx + ".auxiliary_data_block_size", auxSz);
    w.kv(pfx + ".algorithm", fmtstr("%s (%u)", algName(algo), algo));
    w.kvu(pfx + ".hash_offset", hashOff);
    w.kvu(pfx + ".hash_size", hashSz);
    w.kvu(pfx + ".signature_offset", sigOff);
    w.kvu(pfx + ".signature_size", sigSz);
    w.kvu(pfx + ".public_key_offset", pkOff);
    w.kvu(pfx + ".public_key_size", pkSz);
    w.kvu(pfx + ".public_key_metadata_offset", pkmOff);
    w.kvu(pfx + ".public_key_metadata_size", pkmSz);
    w.kvu(pfx + ".descriptors_offset", descOff);
    w.kvu(pfx + ".descriptors_size", descSz);
    w.kvu(pfx + ".rollback_index", rollback);
    w.kvx(pfx + ".flags", flags);
    w.kv(pfx + ".flags_meaning", flags == 0 ? "verification enabled" : ((flags & 2) ? "verification DISABLED" : ((flags & 1) ? "hashtree disabled" : "other")));
    w.kvu(pfx + ".rollback_index_location", rbLoc);
    w.kv(pfx + ".release_string", cstrOf((const char*)h + 128, 48));
    bool signedImg = algo != 0;
    w.kvb(pfx + ".signed", signedImg);
    if (authSz > m.n - 256 || auxSz > m.n - 256 - authSz) {
        w.kv(pfx + ".metadata_status", "invalid block sizes");
        return;
    }
    uint64_t auxStart = 256 + authSz;
    auto fits = [](uint64_t offset, uint64_t size, uint64_t limit) {
        return offset <= limit && size <= limit - offset;
    };
    if (hashSz && fits(hashOff, hashSz, authSz)) w.kv(pfx + ".hash", hex(h + 256 + hashOff, (size_t)hashSz));
    if (pkSz && fits(pkOff, pkSz, auxSz)) {
        const uint8_t* pk = h + auxStart + pkOff;
        uint8_t d1[20];
        sha1Raw(pk, (size_t)pkSz, d1);
        w.kv(pfx + ".public_key_sha1", hex(d1, 20));
        w.kv(pfx + ".public_key_sha256", sha256Hex(pk, (size_t)pkSz));
    }
    if (descSz && fits(descOff, descSz, auxSz)) {
        const uint8_t* d = h + auxStart + descOff;
        size_t pos = 0, idx = 0;
        while (pos + 16 <= descSz && idx < 64) {
            uint64_t tag = rd64be(d + pos), nbytes = rd64be(d + pos + 8);
            if (nbytes > descSz - pos - 16) break;
            const uint8_t* b = d + pos + 16;
            std::string k = fmtstr("%s.descriptor.%zu", pfx.c_str(), idx);
            if (tag == 2 && nbytes >= 116) {
                uint64_t imgSz = rd64be(b);
                std::string alg = cstrOf((const char*)b + 8, 32);
                uint32_t nl = rd32be(b + 40), sl = rd32be(b + 44), dl = rd32be(b + 48), fl = rd32be(b + 52);
                size_t o = 116;
                w.kv(k + ".type", "hash");
                w.kvu(k + ".image_size", imgSz);
                w.kv(k + ".hash_algorithm", alg);
                w.kvx(k + ".flags", fl);
                if (nl <= nbytes - o && sl <= nbytes - o - nl && dl <= nbytes - o - nl - sl) {
                    w.kv(k + ".partition_name", std::string((const char*)b + o, nl));
                    w.kv(k + ".salt", hex(b + o + nl, sl));
                    w.kv(k + ".digest", hex(b + o + nl + sl, dl));
                }
            } else if (tag == 1 && nbytes >= 164) {
                uint32_t ver = rd32be(b);
                uint64_t imgSz = rd64be(b + 4), treeOff = rd64be(b + 12), treeSz = rd64be(b + 20);
                uint32_t dbs = rd32be(b + 28), hbs = rd32be(b + 32), fecRoots = rd32be(b + 36);
                uint64_t fecOff = rd64be(b + 40), fecSz = rd64be(b + 48);
                std::string alg = cstrOf((const char*)b + 56, 32);
                uint32_t nl = rd32be(b + 88), sl = rd32be(b + 92), dl = rd32be(b + 96), fl = rd32be(b + 100);
                size_t o = 164;
                w.kv(k + ".type", "hashtree");
                w.kvu(k + ".dm_verity_version", ver);
                w.kvu(k + ".image_size", imgSz);
                w.kvu(k + ".tree_offset", treeOff);
                w.kvu(k + ".tree_size", treeSz);
                w.kvu(k + ".data_block_size", dbs);
                w.kvu(k + ".hash_block_size", hbs);
                w.kvu(k + ".fec_num_roots", fecRoots);
                w.kvu(k + ".fec_offset", fecOff);
                w.kvu(k + ".fec_size", fecSz);
                w.kv(k + ".hash_algorithm", alg);
                w.kvx(k + ".flags", fl);
                if (nl <= nbytes - o && sl <= nbytes - o - nl && dl <= nbytes - o - nl - sl) {
                    w.kv(k + ".partition_name", std::string((const char*)b + o, nl));
                    w.kv(k + ".salt", hex(b + o + nl, sl));
                    w.kv(k + ".root_digest", hex(b + o + nl + sl, dl));
                }
            } else if (tag == 3 && nbytes >= 8) {
                uint32_t fl = rd32be(b), cl = rd32be(b + 4);
                w.kv(k + ".type", "kernel_cmdline");
                w.kvx(k + ".flags", fl);
                if (cl <= nbytes - 8) w.kv(k + ".cmdline", std::string((const char*)b + 8, cl));
            } else if (tag == 4 && nbytes >= 76) {
                uint32_t loc = rd32be(b), nl = rd32be(b + 4), pl = rd32be(b + 8);
                size_t o = 76;
                w.kv(k + ".type", "chain_partition");
                w.kvu(k + ".rollback_index_location", loc);
                if (nl <= nbytes - o && pl <= nbytes - o - nl) {
                    w.kv(k + ".partition_name", std::string((const char*)b + o, nl));
                    w.kv(k + ".public_key_sha256", sha256Hex(b + o + nl, pl));
                }
            } else if (tag == 0 && nbytes >= 16) {
                uint64_t kl = rd64be(b), vl = rd64be(b + 8);
                w.kv(k + ".type", "property");
                if (kl <= nbytes - 16 && vl <= nbytes - 16 - kl) {
                    w.kv(k + ".key", std::string((const char*)b + 16, (size_t)kl));
                    w.kv(k + ".value", std::string((const char*)b + 16 + kl + 1, (size_t)vl));
                }
            } else {
                w.kv(k + ".type", fmtstr("unknown(%llu)", (unsigned long long)tag));
            }
            pos += 16 + ((nbytes + 7) & ~(uint64_t)7);
            idx++;
        }
        w.kvu(pfx + ".descriptor_count", idx);
    }
}

}
