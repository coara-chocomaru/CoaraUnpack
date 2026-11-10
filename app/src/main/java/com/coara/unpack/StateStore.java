package com.coara.unpack;

import android.content.Context;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

public final class StateStore {

    public static final String RUNNING = "running";
    public static final String DONE = "done";
    public static final String ERROR = "error";
    public static final String CANCELED = "canceled";
    public static final String INTERRUPTED = "interrupted";
    public static final String IDLE = "idle";

    public String status = IDLE;
    public int kind;
    public String out = "";
    public boolean outIsDir;
    public boolean outCreated;
    public String message = "";
    public long time;

    private static File file(Context c) {
        return new File(c.getFilesDir(), "job.state");
    }

    public static synchronized StateStore read(Context c) {
        StateStore s = new StateStore();
        File f = file(c);
        if (!f.isFile()) return s;
        Properties p = new Properties();
        try (Reader r = new InputStreamReader(new FileInputStream(f), StandardCharsets.UTF_8)) {
            p.load(r);
        } catch (IOException e) {
            return s;
        }
        s.status = p.getProperty("status", IDLE);
        s.kind = parse(p.getProperty("kind", "0"));
        s.out = p.getProperty("out", "");
        s.outIsDir = "1".equals(p.getProperty("outIsDir", "0"));
        s.outCreated = "1".equals(p.getProperty("outCreated", "0"));
        s.message = p.getProperty("message", "");
        try {
            s.time = Long.parseLong(p.getProperty("time", "0"));
        } catch (NumberFormatException e) {
            s.time = 0;
        }
        return s;
    }

    public static synchronized void write(Context c, StateStore s) {
        Properties p = new Properties();
        p.setProperty("status", s.status);
        p.setProperty("kind", String.valueOf(s.kind));
        p.setProperty("out", s.out);
        p.setProperty("outIsDir", s.outIsDir ? "1" : "0");
        p.setProperty("outCreated", s.outCreated ? "1" : "0");
        p.setProperty("message", s.message);
        p.setProperty("time", String.valueOf(System.currentTimeMillis()));
        File f = file(c);
        File tmp = new File(f.getPath() + ".tmp");
        try (Writer w = new OutputStreamWriter(new FileOutputStream(tmp), StandardCharsets.UTF_8)) {
            p.store(w, null);
        } catch (IOException e) {
            return;
        }
        if (!tmp.renameTo(f)) tmp.delete();
    }

    public static synchronized void cleanupPartial(Context c, StateStore s) {
        if (s.outCreated && !s.out.isEmpty()) {
            File f = new File(s.out);
            if (f.exists()) Fs.deleteRecursive(f);
        }
    }

    public static synchronized boolean recoverInterrupted(Context c) {
        StateStore s = read(c);
        if (!RUNNING.equals(s.status)) return false;
        cleanupPartial(c, s);
        s.status = INTERRUPTED;
        s.outCreated = false;
        s.message = "途中で止まっちゃったみたい。途中の出力は片付けたよ";
        write(c, s);
        return true;
    }

    private static int parse(String v) {
        try {
            return Integer.parseInt(v);
        } catch (NumberFormatException e) {
            return 0;
        }
    }
}
