package com.coara.unpack;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Message;
import android.os.Messenger;
import android.os.RemoteException;
import android.os.SystemClock;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.ProgressBar;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;

public final class MainActivity extends Activity {

    private static final int REQ_PICK = 5001;
    private static final int REQ_SAF = 5002;
    private static final int LOG_CAP = 48 * 1024;
    private static final String[] FORMATS = {"auto", "raw", "gzip", "lz4", "lz4_legacy", "xz", "lzma", "bzip2"};

    private TextView statusTitle;
    private TextView statusText;
    private TextView outPathView;
    private TextView logView;
    private EdgeAwareScrollView logScroll;
    private ProgressBar progressBar;
    private TextView progressText;
    private Button cancelButton;
    private View[] cards;

    private Messenger service;
    private boolean bound;
    private boolean busy;
    private int pendingKind;
    private Runnable afterPermission;
    private final StringBuilder logBuf = new StringBuilder();
    private static boolean processFresh = true;
    private boolean coldStart;
    private long runStartedAt;
    private long lastProgressAt;
    private int shownPct = -1;
    private final Handler ticker = new Handler(Looper.getMainLooper());
    private final Runnable tick = new Runnable() {
        @Override
        public void run() {
            if (!busy) return;
            long now = SystemClock.elapsedRealtime();
            long sec = Math.max(0, (now - runStartedAt) / 1000);
            if (now - lastProgressAt > 3000 && !progressBar.isIndeterminate()) progressBar.setIndeterminate(true);
            progressText.setText((shownPct < 0 ? 0 : shownPct) + "%  " + (sec / 60) + ":" + (sec % 60 < 10 ? "0" : "") + (sec % 60));
            ticker.postDelayed(this, 1000);
        }
    };

    private final Messenger client = new Messenger(new Handler(Looper.getMainLooper()) {
        @Override
        public void handleMessage(Message m) {
            Bundle d = m.getData();
            switch (m.what) {
                case WorkerService.MSG_LOG:
                    if (d != null) {
                        appendLog(d.getString("s", ""), d.getBoolean("replace", false));
                    }
                    break;
                case WorkerService.MSG_PROGRESS:
                    lastProgressAt = SystemClock.elapsedRealtime();
                    showProgress(m.arg1);
                    break;
                case WorkerService.MSG_STATE:
                    if (d != null) {
                        renderState(d.getString("status", StateStore.IDLE), d.getInt("kind"), d.getString("out", ""),
                                d.getString("message", ""), d.getInt("progress"));
                    }
                    break;
                default:
                    super.handleMessage(m);
            }
        }
    });

    private final ServiceConnection conn = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder binder) {
            service = new Messenger(binder);
            bound = true;
            try {
                Message m = Message.obtain(null, WorkerService.MSG_REGISTER);
                m.replyTo = client;
                service.send(m);
            } catch (RemoteException e) {
                handleServiceLost();
            }
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            service = null;
            handleServiceLost();
        }
    };

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        setContentView(R.layout.activity_main);
        statusTitle = findViewById(R.id.status_title);
        statusText = findViewById(R.id.status_text);
        outPathView = findViewById(R.id.status_out);
        logView = findViewById(R.id.log_view);
        logScroll = findViewById(R.id.log_scroll);
        progressBar = findViewById(R.id.progress_bar);
        progressText = findViewById(R.id.progress_text);
        cancelButton = findViewById(R.id.btn_cancel);
        cards = new View[]{findViewById(R.id.card_unpack), findViewById(R.id.card_repack), findViewById(R.id.card_rd_unpack), findViewById(R.id.card_rd_repack)};
        findViewById(R.id.card_unpack).setOnClickListener(v -> begin(Job.UNPACK_BOOT));
        findViewById(R.id.card_repack).setOnClickListener(v -> begin(Job.REPACK_BOOT));
        findViewById(R.id.card_rd_unpack).setOnClickListener(v -> begin(Job.UNPACK_RAMDISK));
        findViewById(R.id.card_rd_repack).setOnClickListener(v -> begin(Job.REPACK_RAMDISK));
        cancelButton.setOnClickListener(v -> sendCancel());
        findViewById(R.id.log_copy).setOnClickListener(v -> {
            if (logBuf.length() == 0) {
                Toast.makeText(this, R.string.log_empty, Toast.LENGTH_SHORT).show();
                return;
            }
            ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            if (cm != null) {
                cm.setPrimaryClip(ClipData.newPlainText("log", logBuf.toString()));
                Toast.makeText(this, R.string.log_copied, Toast.LENGTH_SHORT).show();
            }
        });
        findViewById(R.id.log_clear).setOnClickListener(v -> {
            logBuf.setLength(0);
            logView.setText("");
        });
        outPathView.setOnClickListener(v -> {
            CharSequence t = outPathView.getText();
            if (t != null && t.length() > 0) {
                ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                if (cm != null) {
                    cm.setPrimaryClip(ClipData.newPlainText("path", t));
                    Toast.makeText(this, R.string.path_copied, Toast.LENGTH_SHORT).show();
                }
            }
        });
        PermissionHelper.requestNotifications(this);
        File crash = new File(getFilesDir(), "crash.log");
        if (crash.exists()) {
            logBuf.append(getString(R.string.prev_crash)).append('\n');
            crash.delete();
        }
        logView.setText(logBuf);
        coldStart = processFresh && b == null;
        processFresh = false;
        StateStore s = StateStore.read(this);
        if (coldStart && !StateStore.RUNNING.equals(s.status) && !StateStore.IDLE.equals(s.status)) {
            StateStore idle = new StateStore();
            StateStore.write(this, idle);
            s = idle;
        }
        renderState(s.status, s.kind, s.out, s.message, 0);
    }

    @Override
    protected void onStart() {
        super.onStart();
        Intent i = new Intent(this, WorkerService.class);
        boolean ok = false;
        try {
            ok = bindService(i, conn, 0);
        } catch (Throwable ignored) {
        }
        if (!ok) {
            try {
                unbindService(conn);
            } catch (Throwable ignored) {
            }
            bound = false;
            if (StateStore.recoverInterrupted(this)) {
                afterRecover();
            } else {
                StateStore s = StateStore.read(this);
                if (!StateStore.RUNNING.equals(s.status)) renderState(s.status, s.kind, s.out, s.message, 0);
            }
        }
    }

    @Override
    protected void onDestroy() {
        ticker.removeCallbacks(tick);
        super.onDestroy();
    }

    @Override
    protected void onStop() {
        if (bound && service != null) {
            try {
                Message m = Message.obtain(null, WorkerService.MSG_UNREGISTER);
                m.replyTo = client;
                service.send(m);
            } catch (RemoteException ignored) {
            }
        }
        try {
            unbindService(conn);
        } catch (Throwable ignored) {
        }
        bound = false;
        service = null;
        super.onStop();
    }

    private void handleServiceLost() {
        bound = false;
        if (StateStore.recoverInterrupted(this)) afterRecover();
    }

    private void afterRecover() {
        logBuf.append(getString(R.string.worker_lost)).append('\n');
        logView.setText(logBuf);
        StateStore s = StateStore.read(this);
        if (coldStart) {
            coldStart = false;
            StateStore idle = new StateStore();
            StateStore.write(this, idle);
            s = idle;
        }
        renderState(s.status, s.kind, s.out, s.message, 0);
    }

    private void appendLog(String s, boolean replace) {
        boolean atBottom = logScroll.getScrollY() + logScroll.getHeight() >= logView.getHeight() - 48;
        if (replace) {
            logBuf.setLength(0);
            logBuf.append(s);
            if (logBuf.length() > LOG_CAP) logBuf.delete(0, logBuf.length() - LOG_CAP / 2);
            logView.setText(logBuf);
        } else {
            logBuf.append(s);
            if (logBuf.length() > LOG_CAP) {
                logBuf.delete(0, logBuf.length() - LOG_CAP / 2);
                logView.setText(logBuf);
            } else {
                logView.append(s);
            }
        }
        if (atBottom) logScroll.post(() -> logScroll.fullScroll(View.FOCUS_DOWN));
    }

    private void sendCancel() {
        if (service == null) return;
        try {
            service.send(Message.obtain(null, WorkerService.MSG_CANCEL));
            cancelButton.setEnabled(false);
        } catch (RemoteException e) {
            handleServiceLost();
        }
    }

    private void showProgress(int pct) {
        int p = Math.max(0, Math.min(100, pct));
        shownPct = p;
        progressBar.setIndeterminate(false);
        progressBar.setProgress(p);
        progressText.setText(p + "%");
    }

    private void renderState(String status, int kind, String out, String message, int progress) {
        boolean running = StateStore.RUNNING.equals(status);
        boolean was = busy;
        busy = running;
        ticker.removeCallbacks(tick);
        for (View c : cards) {
            c.setEnabled(!running);
            c.setAlpha(running ? 0.45f : 1f);
        }
        cancelButton.setVisibility(running ? View.VISIBLE : View.GONE);
        cancelButton.setEnabled(running);
        findViewById(R.id.progress_box).setVisibility(running ? View.VISIBLE : View.GONE);
        if (running) {
            statusTitle.setText(R.string.status_running);
            statusText.setText(titleOf(kind));
            outPathView.setText(out);
            showProgress(progress);
            if (!was) runStartedAt = SystemClock.elapsedRealtime();
            lastProgressAt = SystemClock.elapsedRealtime();
            ticker.postDelayed(tick, 1000);
            return;
        }
        switch (status) {
            case StateStore.DONE:
                statusTitle.setText(R.string.status_done);
                break;
            case StateStore.CANCELED:
                statusTitle.setText(R.string.status_canceled);
                break;
            case StateStore.ERROR:
            case StateStore.INTERRUPTED:
                statusTitle.setText(R.string.status_error);
                break;
            default:
                statusTitle.setText(R.string.status_idle);
                statusText.setText(R.string.status_idle_text);
                outPathView.setText("");
                return;
        }
        int nl = message.indexOf('\n');
        statusText.setText(nl >= 0 ? message.substring(0, nl) : message);
        String detail = nl >= 0 ? message.substring(nl + 1) : "";
        outPathView.setText(StateStore.DONE.equals(status) && detail.isEmpty() ? out : detail);
    }

    private String titleOf(int kind) {
        switch (kind) {
            case Job.UNPACK_BOOT:
                return getString(R.string.run_unpack);
            case Job.REPACK_BOOT:
                return getString(R.string.run_repack);
            case Job.UNPACK_RAMDISK:
                return getString(R.string.run_rd_unpack);
            default:
                return getString(R.string.run_rd_repack);
        }
    }

    private void begin(int kind) {
        if (busy) {
            Toast.makeText(this, R.string.busy, Toast.LENGTH_SHORT).show();
            return;
        }
        pendingKind = kind;
        if (PermissionHelper.hasStorage(this)) {
            pick(kind);
        } else {
            afterPermission = () -> pick(kind);
            new AlertDialog.Builder(this)
                    .setTitle(R.string.perm_title)
                    .setMessage(R.string.perm_message)
                    .setPositiveButton(R.string.perm_ok, (d, w) -> PermissionHelper.requestStorage(this))
                    .setNegativeButton(R.string.perm_cancel, (d, w) -> permissionDenied())
                    .setOnCancelListener(d -> permissionDenied())
                    .show();
        }
    }

    private void permissionDenied() {
        afterPermission = null;
        Toast.makeText(this, R.string.perm_denied, Toast.LENGTH_LONG).show();
    }

    private void permissionResult() {
        Runnable r = afterPermission;
        afterPermission = null;
        if (r == null) return;
        if (PermissionHelper.hasStorage(this)) {
            r.run();
        } else {
            Toast.makeText(this, R.string.perm_denied, Toast.LENGTH_LONG).show();
        }
    }

    @Override
    public void onRequestPermissionsResult(int code, String[] perms, int[] results) {
        super.onRequestPermissionsResult(code, perms, results);
        if (code == PermissionHelper.REQ_STORAGE) permissionResult();
    }

    private void pick(int kind) {
        Intent i = new Intent(this, FileBrowserActivity.class);
        switch (kind) {
            case Job.UNPACK_BOOT:
                i.putExtra(FileBrowserActivity.EXTRA_MODE, FileBrowserActivity.MODE_FILE);
                i.putExtra(FileBrowserActivity.EXTRA_TITLE, getString(R.string.pick_img));
                i.putExtra(FileBrowserActivity.EXTRA_EXTS, new String[]{".img", ".bin"});
                break;
            case Job.UNPACK_RAMDISK:
                i.putExtra(FileBrowserActivity.EXTRA_MODE, FileBrowserActivity.MODE_FILE);
                i.putExtra(FileBrowserActivity.EXTRA_TITLE, getString(R.string.pick_ramdisk));
                i.putExtra(FileBrowserActivity.EXTRA_EXTS, new String[]{".cpio", ".gz", ".lz4", ".lzma", ".xz", ".bz2", ".bz", ".img", ".rd"});
                break;
            case Job.REPACK_BOOT:
                i.putExtra(FileBrowserActivity.EXTRA_MODE, FileBrowserActivity.MODE_DIR);
                i.putExtra(FileBrowserActivity.EXTRA_TITLE, getString(R.string.pick_unpack_dir));
                i.putExtra(FileBrowserActivity.EXTRA_KIND, "boot");
                break;
            default:
                i.putExtra(FileBrowserActivity.EXTRA_MODE, FileBrowserActivity.MODE_DIR);
                i.putExtra(FileBrowserActivity.EXTRA_TITLE, getString(R.string.pick_rd_dir));
                i.putExtra(FileBrowserActivity.EXTRA_KIND, "ramdisk");
        }
        startActivityForResult(i, REQ_PICK);
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        super.onActivityResult(req, res, data);
        if (req == PermissionHelper.REQ_ALL_FILES) {
            permissionResult();
            return;
        }
        if (req == REQ_PICK) {
            if (res == RESULT_OK && data != null) {
                String path = data.getStringExtra(FileBrowserActivity.EXTRA_PATH);
                if (path != null) onPicked(pendingKind, new File(path), null);
            } else if (res == RESULT_FIRST_USER) {
                Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
                i.addCategory(Intent.CATEGORY_OPENABLE);
                i.setType("*/*");
                try {
                    startActivityForResult(i, REQ_SAF);
                } catch (Throwable e) {
                    Toast.makeText(this, R.string.err_no_saf, Toast.LENGTH_LONG).show();
                }
            }
            return;
        }
        if (req == REQ_SAF && res == RESULT_OK && data != null && data.getData() != null) {
            onPicked(pendingKind, null, data.getData());
        }
    }

    private void onPicked(int kind, File file, Uri uri) {
        if (busy) return;
        showOptions(kind, file, uri);
    }

    private void showOptions(final int kind, final File file, final Uri uri) {
        if (kind == Job.UNPACK_RAMDISK) {
            launch(buildJob(kind, file, uri, null));
            return;
        }
        View v = LayoutInflater.from(this).inflate(R.layout.dialog_options, null);
        final CheckBox cb1 = v.findViewById(R.id.opt_cb1);
        final CheckBox cb2 = v.findViewById(R.id.opt_cb2);
        final CheckBox cb3 = v.findViewById(R.id.opt_cb3);
        final CheckBox cb4 = v.findViewById(R.id.opt_cb4);
        final Spinner sp1 = v.findViewById(R.id.opt_spin1);
        final Spinner sp2 = v.findViewById(R.id.opt_spin2);
        TextView l1 = v.findViewById(R.id.opt_label1);
        TextView l2 = v.findViewById(R.id.opt_label2);
        TextView note = v.findViewById(R.id.opt_note);
        ArrayAdapter<String> ad = new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, FORMATS);
        ArrayAdapter<String> ad2 = new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, FORMATS);
        int title;
        if (kind == Job.UNPACK_BOOT) {
            title = R.string.opt_title_unpack;
            cb1.setText(R.string.opt_extract_rd);
            cb2.setText(R.string.opt_skip_decomp);
            cb3.setVisibility(View.GONE);
            cb4.setVisibility(View.GONE);
            l1.setVisibility(View.GONE);
            l2.setVisibility(View.GONE);
            sp1.setVisibility(View.GONE);
            sp2.setVisibility(View.GONE);
            note.setText(R.string.opt_note_unpack);
        } else if (kind == Job.REPACK_BOOT) {
            title = R.string.opt_title_repack;
            l1.setText(R.string.opt_rd_fmt);
            l2.setText(R.string.opt_k_fmt);
            sp1.setAdapter(ad);
            sp2.setAdapter(ad2);
            cb1.setText(R.string.opt_pad);
            cb1.setChecked(true);
            cb2.setText(R.string.opt_force);
            cb3.setText(R.string.opt_nocomp);
            cb4.setVisibility(View.GONE);
            note.setVisibility(View.VISIBLE);
            note.setText(R.string.opt_note_avb1_key);
        } else {
            title = R.string.opt_title_rd_repack;
            l1.setText(R.string.opt_rd_fmt);
            sp1.setAdapter(ad);
            l2.setVisibility(View.GONE);
            sp2.setVisibility(View.GONE);
            cb1.setText(R.string.opt_0777);
            cb2.setVisibility(View.GONE);
            cb3.setVisibility(View.GONE);
            cb4.setVisibility(View.GONE);
            note.setVisibility(View.GONE);
        }
        new AlertDialog.Builder(this)
                .setTitle(title)
                .setView(v)
                .setPositiveButton(R.string.go, (d, w) -> {
                    Job j = new Job();
                    if (kind == Job.UNPACK_BOOT) {
                        j.b = cb1.isChecked();
                        j.a = cb2.isChecked();
                    } else if (kind == Job.REPACK_BOOT) {
                        j.c = cb1.isChecked();
                        j.d = cb2.isChecked();
                        j.a = cb3.isChecked();
                        j.s1 = FORMATS[sp1.getSelectedItemPosition()];
                        j.s2 = FORMATS[sp2.getSelectedItemPosition()];
                    } else {
                        j.a = cb1.isChecked();
                        j.s1 = FORMATS[sp1.getSelectedItemPosition()];
                    }
                    launch(buildJob(kind, file, uri, j));
                })
                .setNegativeButton(R.string.back, null)
                .show();
    }

    private Job buildJob(int kind, File file, Uri uri, Job opts) {
        Job j = opts == null ? new Job() : opts;
        j.kind = kind;
        String stamp = Fs.stamp();
        File dl = Fs.downloadDir();
        if (kind == Job.UNPACK_BOOT || kind == Job.UNPACK_RAMDISK) {
            String name;
            if (file != null) {
                j.inPath = file.getAbsolutePath();
                name = file.getName();
            } else {
                j.inUri = uri.toString();
                name = Fs.displayName(this, uri);
                j.inName = name;
            }
            j.outIsDir = true;
            if (kind == Job.UNPACK_BOOT) {
                j.outPath = Fs.unique(dl, stamp + "_" + Fs.safeName(Fs.stripExt(name))).getAbsolutePath();
            } else {
                File parent = file != null && file.getParentFile() != null ? file.getParentFile() : dl;
                j.outPath = Fs.unique(parent, stamp + "-ramdisk").getAbsolutePath();
            }
        } else {
            j.inPath = file.getAbsolutePath();
            j.outIsDir = false;
            if (kind == Job.REPACK_BOOT) {
                j.outPath = Fs.unique(file, stamp + "-repack.img").getAbsolutePath();
            } else {
                String fmt = j.s1;
                if ("auto".equals(fmt)) {
                    fmt = Fs.readValue(new File(file, "info.txt"), "source_format");
                    if (fmt.isEmpty()) fmt = "raw";
                }
                j.outPath = Fs.unique(file, stamp + "-repack" + Fs.rdExt(fmt)).getAbsolutePath();
            }
        }
        return j;
    }

    private void launch(Job job) {
        StateStore s = new StateStore();
        s.status = StateStore.RUNNING;
        s.kind = job.kind;
        s.out = job.outPath;
        s.outIsDir = job.outIsDir;
        s.outCreated = false;
        StateStore.write(this, s);
        logBuf.setLength(0);
        logView.setText("");
        renderState(StateStore.RUNNING, job.kind, job.outPath, "", 0);
        try {
            startForegroundService(job.toIntent(this));
        } catch (Throwable e) {
            s.status = StateStore.ERROR;
            s.message = getString(R.string.err_start_service);
            StateStore.write(this, s);
            renderState(s.status, s.kind, s.out, s.message, 0);
            return;
        }
        if (!bound) {
            try {
                bindService(new Intent(this, WorkerService.class), conn, 0);
            } catch (Throwable ignored) {
            }
        }
    }
}
