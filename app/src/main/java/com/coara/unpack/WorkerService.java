package com.coara.unpack;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.graphics.drawable.Icon;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Message;
import android.os.Messenger;
import android.os.PowerManager;
import android.os.Process;
import android.os.RemoteException;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public final class WorkerService extends Service {

    public static final int MSG_REGISTER = 1;
    public static final int MSG_UNREGISTER = 2;
    public static final int MSG_CANCEL = 3;
    public static final int MSG_LOG = 10;
    public static final int MSG_PROGRESS = 11;
    public static final int MSG_STATE = 12;
    public static final String ACTION_CANCEL = "com.coara.unpack.CANCEL";

    private static final String CHANNEL_RUN = "run";
    private static final String CHANNEL_DONE = "done";
    private static final int NOTIF_RUN = 1;
    private static final int NOTIF_DONE = 2;
    private static final int LOG_CAP = 48 * 1024;

    private final Handler main = new Handler(Looper.getMainLooper());
    private final List<Messenger> clients = new ArrayList<>();
    private final StringBuilder logBuf = new StringBuilder();
    private final Messenger messenger = new Messenger(new Handler(Looper.getMainLooper()) {
        @Override
        public void handleMessage(Message m) {
            switch (m.what) {
                case MSG_REGISTER:
                    if (m.replyTo != null && !clients.contains(m.replyTo)) {
                        clients.add(m.replyTo);
                        replay(m.replyTo);
                    }
                    break;
                case MSG_UNREGISTER:
                    clients.remove(m.replyTo);
                    break;
                case MSG_CANCEL:
                    requestCancel();
                    break;
                default:
                    super.handleMessage(m);
            }
        }
    });

    private volatile boolean running;
    private volatile boolean cancelRequested;
    private int progress;
    private StateStore state = new StateStore();
    private PowerManager.WakeLock wakeLock;
    private Notification.Builder runBuilder;
    private long lastNotifyMs;
    private final Object pendingLock = new Object();
    private final StringBuilder pendingLog = new StringBuilder();
    private int pendingProgress = -1;
    private boolean flushScheduled;
    private final Runnable flusher = new Runnable() {
        @Override
        public void run() {
            flushPending();
        }
    };

    @Override
    public IBinder onBind(Intent intent) {
        return messenger.getBinder();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null) {
            if (!running) stopSelf();
            return START_NOT_STICKY;
        }
        if (ACTION_CANCEL.equals(intent.getAction())) {
            requestCancel();
            return START_NOT_STICKY;
        }
        ensureChannels();
        if (running) {
            return START_NOT_STICKY;
        }
        Job job = Job.from(intent);
        if (job.kind < Job.UNPACK_BOOT || job.kind > Job.REPACK_RAMDISK) {
            stopSelf();
            return START_NOT_STICKY;
        }
        running = true;
        cancelRequested = false;
        progress = 0;
        logBuf.setLength(0);
        runBuilder = buildRunNotification(titleFor(job.kind), "準備中だよ〜");
        try {
            startFg(runBuilder.build());
        } catch (Throwable e) {
            running = false;
            StateStore bad = new StateStore();
            bad.status = StateStore.ERROR;
            bad.kind = job.kind;
            bad.out = job.outPath;
            bad.message = "うまくいかなかったよ…\n作業を始められなかったよ";
            StateStore.write(this, bad);
            stopSelf();
            return START_NOT_STICKY;
        }
        acquireWakeLock();
        final Job j = job;
        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    Process.setThreadPriority(Process.THREAD_PRIORITY_BACKGROUND);
                } catch (Throwable ignored) {
                }
                execute(j);
            }
        }, "coara-worker");
        t.setDaemon(true);
        t.start();
        return START_NOT_STICKY;
    }

    @Override
    public void onDestroy() {
        releaseWakeLock();
        super.onDestroy();
    }

    private void startFg(Notification n) {
        if (Build.VERSION.SDK_INT >= 29) {
            startForeground(NOTIF_RUN, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC);
        } else {
            startForeground(NOTIF_RUN, n);
        }
    }

    private void requestCancel() {
        if (!running) return;
        cancelRequested = true;
        NativeBridge.nCancel();
        queueLog("キャンセルするね…ちょっと待ってね");
    }

    private void ensureChannels() {
        NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        if (nm == null) return;
        if (nm.getNotificationChannel(CHANNEL_RUN) == null) {
            NotificationChannel c = new NotificationChannel(CHANNEL_RUN, "処理中", NotificationManager.IMPORTANCE_LOW);
            c.setShowBadge(false);
            nm.createNotificationChannel(c);
        }
        if (nm.getNotificationChannel(CHANNEL_DONE) == null) {
            NotificationChannel c = new NotificationChannel(CHANNEL_DONE, "結果のお知らせ", NotificationManager.IMPORTANCE_DEFAULT);
            nm.createNotificationChannel(c);
        }
    }

    private PendingIntent openIntent() {
        Intent i = new Intent(this, MainActivity.class);
        i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        return PendingIntent.getActivity(this, 0, i, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
    }

    private Notification.Builder buildRunNotification(String title, String text) {
        Intent ci = new Intent(this, WorkerService.class);
        ci.setAction(ACTION_CANCEL);
        PendingIntent cancel = PendingIntent.getService(this, 1, ci, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        return new Notification.Builder(this, CHANNEL_RUN)
                .setSmallIcon(R.drawable.ic_notification)
                .setContentTitle(title)
                .setContentText(text)
                .setOngoing(true)
                .setOnlyAlertOnce(true)
                .setContentIntent(openIntent())
                .setProgress(100, 0, true)
                .addAction(new Notification.Action.Builder(Icon.createWithResource(this, R.drawable.ic_notification), "やめる", cancel).build());
    }

    private void updateNotification(String text, int pct) {
        long now = System.currentTimeMillis();
        if (pct < 100 && now - lastNotifyMs < 700) return;
        lastNotifyMs = now;
        NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        if (nm == null || runBuilder == null) return;
        runBuilder.setContentText(text).setProgress(100, pct, pct <= 0);
        try {
            nm.notify(NOTIF_RUN, runBuilder.build());
        } catch (Throwable ignored) {
        }
    }

    private void notifyDone(String title, String text) {
        NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        if (nm == null) return;
        Notification n = new Notification.Builder(this, CHANNEL_DONE)
                .setSmallIcon(R.drawable.ic_notification)
                .setContentTitle(title)
                .setContentText(text)
                .setStyle(new Notification.BigTextStyle().bigText(text))
                .setAutoCancel(true)
                .setContentIntent(openIntent())
                .build();
        try {
            nm.notify(NOTIF_DONE, n);
        } catch (Throwable ignored) {
        }
    }

    private void acquireWakeLock() {
        try {
            PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
            if (pm == null) return;
            wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "coara:unpack");
            wakeLock.setReferenceCounted(false);
            wakeLock.acquire(60L * 60L * 1000L);
        } catch (Throwable ignored) {
        }
    }

    private void releaseWakeLock() {
        try {
            if (wakeLock != null && wakeLock.isHeld()) wakeLock.release();
        } catch (Throwable ignored) {
        }
        wakeLock = null;
    }

    private static String titleFor(int kind) {
        switch (kind) {
            case Job.UNPACK_BOOT:
                return "イメージをアンパック中だよ〜";
            case Job.REPACK_BOOT:
                return "イメージをリパック中だよ〜";
            case Job.UNPACK_RAMDISK:
                return "ramdiskを展開中だよ〜";
            default:
                return "ramdiskをリパック中だよ〜";
        }
    }

    private static String doneFor(int kind) {
        switch (kind) {
            case Job.UNPACK_BOOT:
                return "アンパックできたよ〜";
            case Job.REPACK_BOOT:
                return "リパックできたよ〜";
            case Job.UNPACK_RAMDISK:
                return "ramdiskの展開できたよ〜";
            default:
                return "ramdiskのリパックできたよ〜";
        }
    }

    private void queueLog(String line) {
        synchronized (pendingLock) {
            pendingLog.append(line).append('\n');
            if (pendingLog.length() > LOG_CAP) pendingLog.delete(0, pendingLog.length() - LOG_CAP / 2);
            scheduleFlushLocked();
        }
    }

    private void queueProgress(int pct) {
        synchronized (pendingLock) {
            if (pct > pendingProgress) pendingProgress = pct;
            scheduleFlushLocked();
        }
    }

    private void scheduleFlushLocked() {
        if (!flushScheduled) {
            flushScheduled = true;
            main.postDelayed(flusher, 200);
        }
    }

    private void flushPending() {
        String text;
        int pct;
        synchronized (pendingLock) {
            flushScheduled = false;
            text = pendingLog.length() == 0 ? null : pendingLog.toString();
            pendingLog.setLength(0);
            pct = pendingProgress;
            pendingProgress = -1;
        }
        if (text != null) {
            logBuf.append(text);
            if (logBuf.length() > LOG_CAP) logBuf.delete(0, logBuf.length() - LOG_CAP / 2);
            broadcast(MSG_LOG, text);
        }
        if (pct >= 0 && pct != progress) {
            progress = pct;
            broadcast(MSG_PROGRESS, pct);
            updateNotification(pct + "%", pct);
        }
    }

    private void broadcast(int what, Object obj) {
        for (int i = clients.size() - 1; i >= 0; i--) {
            Messenger c = clients.get(i);
            try {
                Message m = Message.obtain(null, what);
                if (obj instanceof String) {
                    Bundle b = new Bundle();
                    b.putString("s", (String) obj);
                    m.setData(b);
                } else if (obj instanceof Integer) {
                    m.arg1 = (Integer) obj;
                } else if (obj instanceof Bundle) {
                    m.setData((Bundle) obj);
                }
                c.send(m);
            } catch (RemoteException e) {
                clients.remove(i);
            } catch (RuntimeException e) {
                clients.remove(i);
            }
        }
    }

    private Bundle stateBundle() {
        Bundle b = new Bundle();
        b.putString("status", state.status);
        b.putInt("kind", state.kind);
        b.putString("out", state.out);
        b.putString("message", state.message);
        b.putInt("progress", progress);
        return b;
    }

    private void replay(Messenger c) {
        try {
            Message l = Message.obtain(null, MSG_LOG);
            Bundle lb = new Bundle();
            lb.putString("s", logBuf.toString());
            lb.putBoolean("replace", true);
            l.setData(lb);
            c.send(l);
            Message p = Message.obtain(null, MSG_PROGRESS);
            p.arg1 = progress;
            c.send(p);
            Message s = Message.obtain(null, MSG_STATE);
            s.setData(stateBundle());
            c.send(s);
        } catch (RemoteException ignored) {
        }
    }

    private void publishState(final StateStore s) {
        StateStore.write(this, s);
        main.post(new Runnable() {
            @Override
            public void run() {
                state = s;
                broadcast(MSG_STATE, stateBundle());
            }
        });
    }

    private void finish(StateStore s, String notifTitle, String notifText) {
        main.removeCallbacks(flusher);
        main.post(flusher);
        publishState(s);
        main.post(new Runnable() {
            @Override
            public void run() {
                running = false;
            }
        });
        notifyDone(notifTitle, notifText);
        main.post(new Runnable() {
            @Override
            public void run() {
                stopForeground(STOP_FOREGROUND_REMOVE);
                stopSelf();
            }
        });
    }

    private void execute(Job job) {
        NativeBridge.setListener(new NativeBridge.Listener() {
            @Override
            public void onLog(String message) {
                queueLog(message);
            }

            @Override
            public void onProgress(int percent) {
                queueProgress(percent);
            }
        });
        StateStore s = new StateStore();
        s.kind = job.kind;
        s.out = job.outPath;
        s.outIsDir = job.outIsDir;
        s.outCreated = false;
        s.status = StateStore.RUNNING;
        s.message = "";
        publishState(s);
        File cached = null;
        try {
            NativeBridge.nResetCancel();
            String in = job.inPath;
            if (!job.inUri.isEmpty()) {
                queueLog("選んだファイルを作業用にコピーするよ〜");
                File dir = new File(getCacheDir(), "in");
                Fs.deleteRecursive(dir);
                String name = job.inName.isEmpty() ? "input.img" : job.inName;
                cached = Fs.copyUri(this, Uri.parse(job.inUri), dir, name, new Fs.CancelCheck() {
                    @Override
                    public boolean isCanceled() {
                        return cancelRequested;
                    }
                });
                in = cached.getAbsolutePath();
            }
            File inFile = new File(in);
            if (!inFile.exists()) throw new FailException("入力が見つからないよ〜");
            if (job.kind == Job.UNPACK_BOOT || job.kind == Job.UNPACK_RAMDISK) {
                if (!inFile.isFile() || !inFile.canRead()) throw new FailException("入力ファイルを読めないよ(権限を確認してね)");
                if (inFile.length() < 64) throw new FailException("ファイルが小さすぎるよ");
            } else if (!inFile.isDirectory()) {
                throw new FailException("フォルダを選んでね");
            }
            File out = new File(job.outPath);
            File parent = out.getParentFile();
            if (parent == null || !Fs.probeWritable(parent)) {
                throw new FailException("出力先に書き込めないよ〜(ストレージの許可を確認してね)");
            }
            long need = need(job, inFile);
            long free = Fs.usable(parent);
            if (free >= 0 && need > free) {
                throw new FailException("空き容量が足りないよ(必要: 約" + Fs.human(need) + " / 空き: " + Fs.human(free) + ")");
            }
            if (out.exists()) {
                File u = Fs.unique(parent, out.getName());
                job.outPath = u.getAbsolutePath();
                out = u;
                s.out = job.outPath;
            }
            s.outCreated = true;
            publishState(s);
            int rc = run(job, in);
            if (rc == NativeBridge.OK) {
                s.status = StateStore.DONE;
                s.outCreated = false;
                s.message = doneFor(job.kind) + "\n" + job.outPath;
                queueLog(doneFor(job.kind));
                queueProgress(100);
                finish(s, doneFor(job.kind), job.outPath);
            } else {
                StateStore.cleanupPartial(this, s);
                s.outCreated = false;
                if (rc == NativeBridge.CANCELED || cancelRequested) {
                    s.status = StateStore.CANCELED;
                    s.message = "キャンセルしたよ。途中の出力は片付けたよ";
                    finish(s, "キャンセルしたよ", "途中の出力は片付けたよ");
                } else {
                    String err = NativeBridge.nLastError();
                    s.status = StateStore.ERROR;
                    s.message = "うまくいかなかったよ…\n" + (err == null || err.isEmpty() ? "原因不明のエラー" : err);
                    finish(s, "うまくいかなかったよ…", err == null ? "" : err);
                }
            }
        } catch (FailException e) {
            StateStore.cleanupPartial(this, s);
            s.outCreated = false;
            s.status = StateStore.ERROR;
            s.message = "うまくいかなかったよ…\n" + e.getMessage();
            queueLog(String.valueOf(e.getMessage()));
            finish(s, "うまくいかなかったよ…", e.getMessage());
        } catch (Throwable e) {
            StateStore.cleanupPartial(this, s);
            s.outCreated = false;
            boolean canceled = cancelRequested;
            s.status = canceled ? StateStore.CANCELED : StateStore.ERROR;
            String msg = canceled ? "キャンセルしたよ。途中の出力は片付けたよ" : "うまくいかなかったよ…\n" + String.valueOf(e.getMessage());
            s.message = msg;
            finish(s, canceled ? "キャンセルしたよ" : "うまくいかなかったよ…", String.valueOf(e.getMessage()));
        } finally {
            if (cached != null) Fs.deleteRecursive(cached.getParentFile());
            NativeBridge.setListener(null);
            releaseWakeLock();
        }
    }

    private long need(Job job, File in) {
        long len = in.isFile() ? in.length() : dirSize(in);
        switch (job.kind) {
            case Job.UNPACK_BOOT:
                return len * 3 + (32L << 20);
            case Job.UNPACK_RAMDISK:
                return len * 4 + (32L << 20);
            default:
                return len + (32L << 20);
        }
    }

    private static long dirSize(File d) {
        long t = 0;
        File[] k = d.listFiles();
        if (k == null) return 0;
        for (File f : k) {
            if (f.isFile()) t += f.length();
            else if (f.isDirectory() && !f.getName().equals("rootfs") && !f.getName().startsWith("rootfs_")) t += dirSize(f);
        }
        return t;
    }

    private int run(Job job, String in) {
        switch (job.kind) {
            case Job.UNPACK_BOOT:
                return NativeBridge.nUnpackBoot(in, job.outPath, job.a, job.b);
            case Job.REPACK_BOOT:
                return NativeBridge.nRepackBoot(in, job.outPath, job.a, job.c, job.s1, job.s2, job.d);
            case Job.UNPACK_RAMDISK:
                return NativeBridge.nUnpackRamdisk(in, job.outPath);
            default:
                return NativeBridge.nRepackRamdisk(in, job.outPath, job.s1, job.a);
        }
    }

    private static final class FailException extends Exception {
        FailException(String m) {
            super(m);
        }
    }
}
