package com.coara.unpack;

import android.content.Context;
import android.content.Intent;

public final class Job {

    public static final int UNPACK_BOOT = 1;
    public static final int REPACK_BOOT = 2;
    public static final int UNPACK_RAMDISK = 3;
    public static final int REPACK_RAMDISK = 4;

    public int kind;
    public String inPath = "";
    public String inUri = "";
    public String inName = "";
    public String outPath = "";
    public boolean outIsDir;
    public boolean a;
    public boolean b;
    public boolean c;
    public boolean d;
    public String s1 = "auto";
    public String s2 = "auto";

    public Intent toIntent(Context ctx) {
        Intent i = new Intent(ctx, WorkerService.class);
        i.putExtra("kind", kind);
        i.putExtra("inPath", inPath);
        i.putExtra("inUri", inUri);
        i.putExtra("inName", inName);
        i.putExtra("outPath", outPath);
        i.putExtra("outIsDir", outIsDir);
        i.putExtra("a", a);
        i.putExtra("b", b);
        i.putExtra("c", c);
        i.putExtra("d", d);
        i.putExtra("s1", s1);
        i.putExtra("s2", s2);
        return i;
    }

    public static Job from(Intent i) {
        Job j = new Job();
        j.kind = i.getIntExtra("kind", 0);
        j.inPath = nz(i.getStringExtra("inPath"));
        j.inUri = nz(i.getStringExtra("inUri"));
        j.inName = nz(i.getStringExtra("inName"));
        j.outPath = nz(i.getStringExtra("outPath"));
        j.outIsDir = i.getBooleanExtra("outIsDir", false);
        j.a = i.getBooleanExtra("a", false);
        j.b = i.getBooleanExtra("b", false);
        j.c = i.getBooleanExtra("c", false);
        j.d = i.getBooleanExtra("d", false);
        j.s1 = nz(i.getStringExtra("s1"));
        j.s2 = nz(i.getStringExtra("s2"));
        if (j.s1.isEmpty()) j.s1 = "auto";
        if (j.s2.isEmpty()) j.s2 = "auto";
        return j;
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }
}
