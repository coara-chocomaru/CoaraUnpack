package com.coara.unpack;

import android.app.Application;

import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;

public final class App extends Application {

    @Override
    public void onCreate() {
        super.onCreate();
        final Thread.UncaughtExceptionHandler prev = Thread.getDefaultUncaughtExceptionHandler();
        Thread.setDefaultUncaughtExceptionHandler(new Thread.UncaughtExceptionHandler() {
            @Override
            public void uncaughtException(Thread t, Throwable e) {
                try {
                    StringWriter sw = new StringWriter();
                    e.printStackTrace(new PrintWriter(sw));
                    try (FileOutputStream o = new FileOutputStream(new File(getFilesDir(), "crash.log"))) {
                        o.write(sw.toString().getBytes(StandardCharsets.UTF_8));
                    }
                    StateStore s = StateStore.read(App.this);
                    if (StateStore.RUNNING.equals(s.status)) {
                        StateStore.cleanupPartial(App.this, s);
                        s.status = StateStore.ERROR;
                        s.outCreated = false;
                        s.message = "アプリ内でエラーが起きたよ。途中の出力は片付けたよ";
                        StateStore.write(App.this, s);
                    }
                } catch (Throwable ignored) {
                }
                if (prev != null) prev.uncaughtException(t, e);
            }
        });
    }
}
