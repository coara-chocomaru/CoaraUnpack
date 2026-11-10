#include <jni.h>
#include <new>
#include <mutex>
#include "unpacker.h"

using namespace cu;

namespace {

JavaVM* gVm = nullptr;
jclass gBridge = nullptr;
jclass gAvb1Signer = nullptr;
jmethodID gSignAvb1 = nullptr;
jmethodID gOnLog = nullptr;
jmethodID gOnProgress = nullptr;
std::mutex gErrMtx;
std::string gLastError;
thread_local JNIEnv* tEnv = nullptr;
thread_local int tLastPct = -1;

void setError(const std::string& s) {
    std::lock_guard<std::mutex> l(gErrMtx);
    gLastError = s;
}

std::string toStd(JNIEnv* env, jstring s) {
    if (!s) return std::string();
    const char* c = env->GetStringUTFChars(s, nullptr);
    if (!c) return std::string();
    std::string r(c);
    env->ReleaseStringUTFChars(s, c);
    return r;
}

jstring toJava(JNIEnv* env, const std::string& s) {
    std::string t;
    t.reserve(s.size());
    size_t i = 0;
    while (i < s.size()) {
        unsigned char c = (unsigned char)s[i];
        size_t len = c < 0x80 ? 1 : (c >> 5) == 6 ? 2 : (c >> 4) == 14 ? 3 : (c >> 3) == 30 ? 4 : 0;
        bool ok = len != 0 && i + len <= s.size();
        for (size_t k = 1; ok && k < len; k++) if (((unsigned char)s[i + k] & 0xC0) != 0x80) ok = false;
        if (ok && len == 4) ok = false;
        if (ok) {
            t.append(s, i, len);
            i += len;
        } else {
            t += '?';
            i++;
        }
    }
    return env->NewStringUTF(t.c_str());
}

void installCallbacks() {
    ctx().log = [](const std::string& m) {
        JNIEnv* env = tEnv;
        if (!env || !gBridge) return;
        jstring js = toJava(env, m);
        if (!js) {
            env->ExceptionClear();
            return;
        }
        env->CallStaticVoidMethod(gBridge, gOnLog, js);
        if (env->ExceptionCheck()) env->ExceptionClear();
        env->DeleteLocalRef(js);
    };
    ctx().progress = [](int pct) {
        JNIEnv* env = tEnv;
        if (!env || !gBridge) return;
        if (pct <= tLastPct) return;
        tLastPct = pct;
        env->CallStaticVoidMethod(gBridge, gOnProgress, (jint)pct);
        if (env->ExceptionCheck()) env->ExceptionClear();
    };
}

template <class F>
jint guarded(JNIEnv* env, F fn) {
    tEnv = env;
    tLastPct = -1;
    setError(std::string());
    installCallbacks();
    jint rc = 0;
    try {
        fn();
    } catch (const Canceled&) {
        setError("canceled");
        rc = 2;
    } catch (const Error& e) {
        setError(e.what());
        rc = 1;
    } catch (const std::bad_alloc&) {
        setError("メモリが足りないよ〜");
        rc = 3;
    } catch (const std::exception& e) {
        setError(e.what());
        rc = 3;
    } catch (...) {
        setError("unknown");
        rc = 3;
    }
    tEnv = nullptr;
    return rc;
}

jint nResetCancel(JNIEnv*, jclass) {
    ctx().cancel.store(false);
    return 0;
}

void nCancel(JNIEnv*, jclass) { ctx().cancel.store(true); }

jstring nLastError(JNIEnv* env, jclass) {
    std::string s;
    {
        std::lock_guard<std::mutex> l(gErrMtx);
        s = gLastError;
    }
    return toJava(env, s);
}

jint nUnpackBoot(JNIEnv* env, jclass, jstring img, jstring out, jboolean skipDecomp, jboolean extractRd) {
    std::string i = toStd(env, img), o = toStd(env, out);
    BootUnpackOpts opts;
    opts.skipDecomp = skipDecomp;
    opts.extractRamdisk = extractRd;
    return guarded(env, [&] { bootUnpack(i, o, opts); });
}

jint nRepackBoot(JNIEnv* env, jclass, jstring dir, jstring out, jboolean skipComp, jboolean pad,
                 jstring rdFmt, jstring kFmt, jboolean forceRebuild) {
    std::string d = toStd(env, dir), o = toStd(env, out);
    BootRepackOpts opts;
    opts.skipComp = skipComp;
    opts.padToOriginal = pad;
    opts.forceRebuild = forceRebuild;
    opts.ramdiskFmt = toStd(env, rdFmt);
    opts.kernelFmt = toStd(env, kFmt);
    if (opts.ramdiskFmt.empty()) opts.ramdiskFmt = "auto";
    if (opts.kernelFmt.empty()) opts.kernelFmt = "auto";
    return guarded(env, [&] { bootRepack(d, o, opts); });
}

jint nUnpackRamdisk(JNIEnv* env, jclass, jstring in, jstring out) {
    std::string i = toStd(env, in), o = toStd(env, out);
    return guarded(env, [&] { ramdiskUnpack(i, o); });
}

jint nRepackRamdisk(JNIEnv* env, jclass, jstring dir, jstring out, jstring fmt, jboolean force0777) {
    std::string d = toStd(env, dir), o = toStd(env, out);
    RdRepackOpts opts;
    opts.fmt = toStd(env, fmt);
    if (opts.fmt.empty()) opts.fmt = "auto";
    opts.force0777 = force0777;
    return guarded(env, [&] { ramdiskRepack(d, o, opts); });
}

jint nRemoveAll(JNIEnv* env, jclass, jstring path) {
    std::string p = toStd(env, path);
    return guarded(env, [&] { removeAll(p); });
}

const JNINativeMethod kMethods[] = {
    {"nResetCancel", "()I", (void*)nResetCancel},
    {"nCancel", "()V", (void*)nCancel},
    {"nLastError", "()Ljava/lang/String;", (void*)nLastError},
    {"nUnpackBoot", "(Ljava/lang/String;Ljava/lang/String;ZZ)I", (void*)nUnpackBoot},
    {"nRepackBoot", "(Ljava/lang/String;Ljava/lang/String;ZZLjava/lang/String;Ljava/lang/String;Z)I", (void*)nRepackBoot},
    {"nUnpackRamdisk", "(Ljava/lang/String;Ljava/lang/String;)I", (void*)nUnpackRamdisk},
    {"nRepackRamdisk", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)I", (void*)nRepackRamdisk},
    {"nRemoveAll", "(Ljava/lang/String;)I", (void*)nRemoveAll},
};

}


namespace cu {

Bytes signAvb1PayloadFile(const std::string& path, const std::string& keyDirectory, uint64_t offset, uint64_t length, const std::string& target) {
    JNIEnv* env = tEnv;
    if (!env || !gAvb1Signer || !gSignAvb1) throw Error("AVB1署名処理を初期化できません");
    jstring jPath = toJava(env, path);
    jstring jKeyDirectory = toJava(env, keyDirectory);
    jstring jTarget = toJava(env, target);
    if (!jPath || !jKeyDirectory || !jTarget) {
        if (jPath) env->DeleteLocalRef(jPath);
        if (jKeyDirectory) env->DeleteLocalRef(jKeyDirectory);
        if (jTarget) env->DeleteLocalRef(jTarget);
        throw Error("AVB1署名パラメータを作成できません");
    }
    auto result = (jbyteArray)env->CallStaticObjectMethod(gAvb1Signer, gSignAvb1, jPath, jKeyDirectory, (jlong)offset, (jlong)length, jTarget);
    env->DeleteLocalRef(jPath);
    env->DeleteLocalRef(jKeyDirectory);
    env->DeleteLocalRef(jTarget);
    if (env->ExceptionCheck()) {
        jthrowable exception = env->ExceptionOccurred();
        env->ExceptionClear();
        std::string message = "AVB1署名または鍵の読み込み・生成に失敗しました";
        if (exception) {
            jclass exceptionClass = env->GetObjectClass(exception);
            jmethodID toString = exceptionClass ? env->GetMethodID(exceptionClass, "toString", "()Ljava/lang/String;") : nullptr;
            if (toString) {
                jstring text = (jstring)env->CallObjectMethod(exception, toString);
                if (!env->ExceptionCheck() && text) {
                    message = toStd(env, text);
                    env->DeleteLocalRef(text);
                } else if (env->ExceptionCheck()) {
                    env->ExceptionClear();
                }
            }
            if (exceptionClass) env->DeleteLocalRef(exceptionClass);
            env->DeleteLocalRef(exception);
        }
        throw Error(message);
    }
    if (!result) throw Error("AVB1署名データを生成できません");
    jsize size = env->GetArrayLength(result);
    if (size <= 0 || size > (1 << 22)) {
        env->DeleteLocalRef(result);
        throw Error("AVB1署名データのサイズが不正です");
    }
    Bytes bytes((size_t)size);
    env->GetByteArrayRegion(result, 0, size, (jbyte*)bytes.data());
    env->DeleteLocalRef(result);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        throw Error("AVB1署名データを取得できません");
    }
    return bytes;
}

}

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    gVm = vm;
    JNIEnv* env = nullptr;
    if (vm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    jclass local = env->FindClass("com/coara/unpack/NativeBridge");
    if (!local) return JNI_ERR;
    gBridge = (jclass)env->NewGlobalRef(local);
    env->DeleteLocalRef(local);
    gOnLog = env->GetStaticMethodID(gBridge, "onLog", "(Ljava/lang/String;)V");
    gOnProgress = env->GetStaticMethodID(gBridge, "onProgress", "(I)V");
    if (!gOnLog || !gOnProgress) return JNI_ERR;
    jclass signerLocal = env->FindClass("com/coara/unpack/Avb1Signer");
    if (!signerLocal) return JNI_ERR;
    gAvb1Signer = (jclass)env->NewGlobalRef(signerLocal);
    env->DeleteLocalRef(signerLocal);
    if (!gAvb1Signer) return JNI_ERR;
    gSignAvb1 = env->GetStaticMethodID(gAvb1Signer, "sign", "(Ljava/lang/String;Ljava/lang/String;JJLjava/lang/String;)[B");
    if (!gSignAvb1) return JNI_ERR;
    if (env->RegisterNatives(gBridge, kMethods, sizeof(kMethods) / sizeof(kMethods[0])) != JNI_OK) return JNI_ERR;
    return JNI_VERSION_1_6;
}
