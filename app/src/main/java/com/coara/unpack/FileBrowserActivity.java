package com.coara.unpack;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.Environment;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.Date;
import java.util.List;
import java.util.Locale;

public final class FileBrowserActivity extends Activity {

    public static final String EXTRA_MODE = "mode";
    public static final String EXTRA_TITLE = "title";
    public static final String EXTRA_EXTS = "exts";
    public static final String EXTRA_KIND = "kind";
    public static final String EXTRA_PATH = "path";
    public static final String MODE_FILE = "file";
    public static final String MODE_DIR = "dir";

    private static final String PREFS = "browser";
    private static final String KEY_LAST = "last";

    private boolean dirMode;
    private String requiredKind = "";
    private String[] exts = new String[0];
    private File current;
    private final List<File> items = new ArrayList<>();
    private final Map<File, String> kinds = new HashMap<>();
    private final ExecutorService io = Executors.newSingleThreadExecutor();
    private volatile int generation;
    private Adapter adapter;
    private TextView pathView;
    private TextView hintView;
    private Button selectButton;
    private CheckBox showAll;
    private LinearLayout shortcuts;
    private final DateFormat df = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT, Locale.getDefault());

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        setContentView(R.layout.activity_browser);
        Intent in = getIntent();
        dirMode = MODE_DIR.equals(in.getStringExtra(EXTRA_MODE));
        requiredKind = in.getStringExtra(EXTRA_KIND) == null ? "" : in.getStringExtra(EXTRA_KIND);
        String[] e = in.getStringArrayExtra(EXTRA_EXTS);
        if (e != null) exts = e;
        String title = in.getStringExtra(EXTRA_TITLE);
        ((TextView) findViewById(R.id.browser_title)).setText(title == null ? getString(R.string.pick_file) : title);
        pathView = findViewById(R.id.browser_path);
        hintView = findViewById(R.id.browser_hint);
        selectButton = findViewById(R.id.browser_select);
        showAll = findViewById(R.id.browser_show_all);
        shortcuts = findViewById(R.id.browser_shortcuts);
        ListView list = findViewById(R.id.browser_list);
        adapter = new Adapter();
        list.setAdapter(adapter);
        list.setEmptyView(findViewById(R.id.browser_empty));
        list.setOnItemClickListener((p, v, pos, id) -> onItem(items.get(pos)));
        findViewById(R.id.browser_up).setOnClickListener(v -> up());
        findViewById(R.id.browser_cancel).setOnClickListener(v -> finish());
        View saf = findViewById(R.id.browser_saf);
        saf.setVisibility(dirMode ? View.GONE : View.VISIBLE);
        saf.setOnClickListener(v -> {
            setResult(RESULT_FIRST_USER);
            finish();
        });
        showAll.setVisibility(dirMode || exts.length == 0 ? View.GONE : View.VISIBLE);
        showAll.setOnCheckedChangeListener((CompoundButton cb, boolean c) -> reload());
        selectButton.setVisibility(dirMode ? View.VISIBLE : View.GONE);
        selectButton.setOnClickListener(v -> choose(current));
        buildShortcuts();
        File start = null;
        SharedPreferences sp = getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        String last = sp.getString(KEY_LAST, null);
        if (last != null) {
            File f = new File(last);
            if (f.isDirectory()) start = f;
        }
        if (start == null) start = Fs.downloadDir();
        if (!start.isDirectory()) start = Environment.getExternalStorageDirectory();
        go(start);
    }

    @Override
    protected void onDestroy() {
        generation++;
        io.shutdownNow();
        super.onDestroy();
    }

    @Override
    public void onBackPressed() {
        if (!up()) super.onBackPressed();
    }

    private void buildShortcuts() {
        shortcuts.removeAllViews();
        addShortcut(getString(R.string.sc_download), Fs.downloadDir());
        addShortcut(getString(R.string.sc_internal), Environment.getExternalStorageDirectory());
        File[] dirs = getExternalFilesDirs(null);
        if (dirs != null) {
            for (File d : dirs) {
                if (d == null) continue;
                String p = d.getAbsolutePath();
                int i = p.indexOf("/Android/data");
                if (i > 0) {
                    File root = new File(p.substring(0, i));
                    if (!root.equals(Environment.getExternalStorageDirectory()) && root.isDirectory()) {
                        addShortcut(getString(R.string.sc_sdcard) + " " + root.getName(), root);
                    }
                }
            }
        }
    }

    private void addShortcut(String label, final File dir) {
        Button bt = (Button) LayoutInflater.from(this).inflate(R.layout.item_chip, shortcuts, false);
        bt.setText(label);
        bt.setOnClickListener(v -> go(dir));
        shortcuts.addView(bt);
    }

    private boolean up() {
        if (current == null) return false;
        File p = current.getParentFile();
        if (p == null || !p.canRead()) return false;
        go(p);
        return true;
    }

    private void onItem(File f) {
        if (f.isDirectory()) {
            go(f);
        } else if (!dirMode) {
            choose(f);
        }
    }

    private void choose(File f) {
        if (f == null) return;
        if (dirMode && !requiredKind.isEmpty()) {
            String kind = Fs.readValue(new File(f, "info.txt"), "kind");
            if (!requiredKind.equals(kind)) {
                Toast.makeText(this, R.string.err_not_unpack_dir, Toast.LENGTH_LONG).show();
                return;
            }
        }
        getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString(KEY_LAST, dirMode ? f.getAbsolutePath() : f.getParent()).apply();
        Intent r = new Intent();
        r.putExtra(EXTRA_PATH, f.getAbsolutePath());
        setResult(RESULT_OK, r);
        finish();
    }

    private void go(File dir) {
        current = dir;
        reload();
    }

    private void reload() {
        final File dir = current;
        final boolean all = showAll.isChecked() || exts.length == 0;
        final int gen = ++generation;
        pathView.setText(dir.getAbsolutePath());
        hintView.setText(R.string.browser_loading);
        hintView.setTextColor(getColor(R.color.text_secondary));
        hintView.setVisibility(View.VISIBLE);
        if (dirMode) selectButton.setEnabled(false);
        io.execute(() -> {
            final List<File> out = new ArrayList<>();
            final Map<File, String> tags = new HashMap<>();
            File[] kids = dir.listFiles();
            if (kids != null) {
                for (File k : kids) {
                    boolean d = k.isDirectory();
                    if (!d && k.getName().startsWith(".")) continue;
                    if (d || dirMode || all || matches(k.getName())) out.add(k);
                }
                Collections.sort(out, new Comparator<File>() {
                    @Override
                    public int compare(File a, File b) {
                        boolean da = a.isDirectory(), db = b.isDirectory();
                        if (da != db) return da ? -1 : 1;
                        return a.getName().compareToIgnoreCase(b.getName());
                    }
                });
                for (File k : out) {
                    if (k.isDirectory()) tags.put(k, Fs.readValue(new File(k, "info.txt"), "kind"));
                }
            }
            final String curKind = dirMode ? Fs.readValue(new File(dir, "info.txt"), "kind") : "";
            final boolean readable = kids != null;
            runOnUiThread(() -> {
                if (gen != generation || isDestroyed()) return;
                items.clear();
                items.addAll(out);
                kinds.clear();
                kinds.putAll(tags);
                if (readable) {
                    hintView.setVisibility(View.GONE);
                } else {
                    hintView.setText(R.string.err_cannot_read_dir);
                    hintView.setTextColor(getColor(R.color.danger));
                }
                if (dirMode) {
                    boolean ok = requiredKind.isEmpty() || requiredKind.equals(curKind);
                    selectButton.setEnabled(ok);
                    selectButton.setText(ok ? R.string.pick_this_folder : R.string.pick_this_folder_ng);
                }
                adapter.notifyDataSetChanged();
                ((ListView) findViewById(R.id.browser_list)).setSelection(0);
            });
        });
    }

    private boolean matches(String name) {
        String n = name.toLowerCase(Locale.ROOT);
        for (String e : exts) {
            if (n.endsWith(e)) return true;
        }
        return false;
    }

    private final class Adapter extends BaseAdapter {
        @Override
        public int getCount() {
            return items.size();
        }

        @Override
        public Object getItem(int i) {
            return items.get(i);
        }

        @Override
        public long getItemId(int i) {
            return i;
        }

        @Override
        public View getView(int i, View convert, ViewGroup parent) {
            View v = convert;
            if (v == null) v = LayoutInflater.from(FileBrowserActivity.this).inflate(R.layout.item_file, parent, false);
            File f = items.get(i);
            ImageView icon = v.findViewById(R.id.item_icon);
            TextView name = v.findViewById(R.id.item_name);
            TextView meta = v.findViewById(R.id.item_meta);
            name.setText(f.getName());
            if (f.isDirectory()) {
                icon.setImageResource(R.drawable.ic_folder);
                String kind = kinds.get(f);
                if (kind == null) kind = "";
                meta.setText(kind.isEmpty() ? df.format(new Date(f.lastModified())) : getString(R.string.unpack_folder_tag, kind));
            } else {
                icon.setImageResource(R.drawable.ic_file);
                meta.setText(Fs.human(f.length()) + "  ·  " + df.format(new Date(f.lastModified())));
            }
            return v;
        }
    }
}
