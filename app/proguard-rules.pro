-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile

-keep class com.coara.unpack.NativeBridge {
    static void onLog(java.lang.String);
    static void onProgress(int);
    native <methods>;
}

-keep class com.coara.unpack.Avb1Signer { *; }
-keep class com.coara.unpack.EdgeAwareScrollView { *; }
