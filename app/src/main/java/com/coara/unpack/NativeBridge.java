package com.coara.unpack;

public final class NativeBridge {

    public static final int OK = 0;
    public static final int ERROR = 1;
    public static final int CANCELED = 2;
    public static final int FATAL = 3;

    public interface Listener {
        void onLog(String message);

        void onProgress(int percent);
    }

    private static volatile Listener listener;

    static {
        System.loadLibrary("coaraunpack");
    }

    private NativeBridge() {
    }

    public static void setListener(Listener l) {
        listener = l;
    }

    static void onLog(String message) {
        Listener l = listener;
        if (l != null) l.onLog(message);
    }

    static void onProgress(int percent) {
        Listener l = listener;
        if (l != null) l.onProgress(percent);
    }

    public static native int nResetCancel();

    public static native void nCancel();

    public static native String nLastError();

    public static native int nUnpackBoot(String img, String outDir, boolean skipDecompress, boolean extractRamdisk);

    public static native int nRepackBoot(String dir, String outFile, boolean skipCompress,
                                         boolean padToOriginal, String ramdiskFormat, String kernelFormat,
                                         boolean forceRebuild);

    public static native int nUnpackRamdisk(String in, String outDir);

    public static native int nRepackRamdisk(String dir, String outFile, String format, boolean force0777);

    public static native int nRemoveAll(String path);
}
