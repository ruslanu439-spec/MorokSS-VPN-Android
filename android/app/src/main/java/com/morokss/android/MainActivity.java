package com.morokss.android;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.BroadcastReceiver;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

public final class MainActivity extends Activity {
    private static final int REQUEST_IMPORT = 1001;
    private static final int REQUEST_NOTIFICATIONS = 1002;
    private static final int MAX_PROFILE_BYTES = 128 * 1024;

    private TextView status;
    private Button startButton;
    private Button stopButton;
    private Button copyButton;
    private boolean receiverRegistered;

    private final BroadcastReceiver stateReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            boolean isRunning = intent.getBooleanExtra(MorokssService.EXTRA_RUNNING, false);
            String message = intent.getStringExtra(MorokssService.EXTRA_MESSAGE);
            showState(isRunning, message);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(buildContent());
        refreshState();
    }

    @Override
    protected void onStart() {
        super.onStart();
        IntentFilter filter = new IntentFilter(MorokssService.ACTION_STATE);
        registerReceiver(
                stateReceiver,
                filter,
                MorokssService.STATUS_PERMISSION,
                null,
                Context.RECEIVER_NOT_EXPORTED
        );
        receiverRegistered = true;
        refreshState();
    }

    @Override
    protected void onStop() {
        if (receiverRegistered) {
            unregisterReceiver(stateReceiver);
            receiverRegistered = false;
        }
        super.onStop();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != REQUEST_IMPORT || resultCode != RESULT_OK || data == null) {
            return;
        }
        Uri uri = data.getData();
        if (uri == null) {
            showState(false, "Файл профиля не выбран");
            return;
        }
        try {
            String raw = readProfile(uri);
            importProfileJson(raw, null);
        } catch (Exception error) {
            showState(false, "Не удалось импортировать профиль: " + error.getMessage());
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == REQUEST_NOTIFICATIONS) {
            startTunnel();
        }
    }

    private View buildContent() {
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(Color.rgb(16, 16, 20));

        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(dp(24), dp(32), dp(24), dp(32));
        scroll.addView(content, new ScrollView.LayoutParams(
                ScrollView.LayoutParams.MATCH_PARENT,
                ScrollView.LayoutParams.WRAP_CONTENT
        ));

        TextView title = text("MorokSS", 30, Color.WHITE);
        title.setTypeface(title.getTypeface(), android.graphics.Typeface.BOLD);
        content.addView(title);

        TextView subtitle = text(
                "Локальный транспорт для Shadowsocks. Адрес для Amnezia: 127.0.0.1:8389.",
                16,
                Color.rgb(190, 188, 205)
        );
        subtitle.setPadding(0, dp(10), 0, dp(20));
        content.addView(subtitle);

        status = text("Проверка…", 16, Color.WHITE);
        status.setPadding(dp(16), dp(14), dp(16), dp(14));
        status.setBackgroundColor(Color.rgb(38, 37, 48));
        content.addView(status, matchWidth());

        content.addView(button("1А. Выбрать JSON-файл", view -> importProfile()));
        content.addView(button("1Б. Вставить JSON вручную", view -> showJsonInput()));
        startButton = button("2. Запустить MorokSS", view -> requestStart());
        content.addView(startButton);
        copyButton = button("3. Скопировать ss:// для Amnezia", view -> copyShadowsocksUri());
        content.addView(copyButton);
        stopButton = button("Остановить", view -> stopTunnel());
        content.addView(stopButton);

        TextView instructions = text(
                "Важно\n\n" +
                        "В Amnezia открой разделение трафика и исключи приложение MorokSS из VPN. " +
                        "Иначе соединение может зациклиться.\n\n" +
                        "Потом импортируй скопированную строку ss:// и подключись. " +
                        "Уведомление MorokSS должно оставаться включённым.",
                15,
                Color.rgb(215, 211, 230)
        );
        instructions.setPadding(0, dp(24), 0, dp(8));
        content.addView(instructions);

        Button notificationSettings = button("Настройки уведомлений", view -> openNotificationSettings());
        content.addView(notificationSettings);
        return scroll;
    }

    private void importProfile() {
        if (MorokssService.isRunning()) {
            showState(true, "Сначала останови MorokSS, потом меняй профиль");
            return;
        }
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT)
                .addCategory(Intent.CATEGORY_OPENABLE)
                .setType("application/json");
        intent.putExtra(Intent.EXTRA_MIME_TYPES, new String[]{"application/json", "text/plain", "*/*"});
        startActivityForResult(intent, REQUEST_IMPORT);
    }

    private void showJsonInput() {
        if (MorokssService.isRunning()) {
            showState(true, "Сначала останови MorokSS, потом меняй профиль");
            return;
        }

        EditText input = new EditText(this);
        input.setHint("{\n  \"hostname\": \"…\",\n  \"morokss_secret\": \"…\"\n}");
        input.setGravity(Gravity.TOP | Gravity.START);
        input.setMinLines(12);
        input.setMaxLines(20);
        input.setHorizontallyScrolling(false);
        input.setInputType(
                InputType.TYPE_CLASS_TEXT
                        | InputType.TYPE_TEXT_FLAG_MULTI_LINE
                        | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        );
        input.setPadding(dp(12), dp(12), dp(12), dp(12));

        LinearLayout container = new LinearLayout(this);
        container.setPadding(dp(18), 0, dp(18), 0);
        container.addView(input, matchWidth());

        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle("JSON-профиль MorokSS")
                .setMessage("Вставь весь JSON целиком. Он будет проверен и сохранён в зашифрованном виде.")
                .setView(container)
                .setPositiveButton("Сохранить", null)
                .setNeutralButton("Вставить из буфера", null)
                .setNegativeButton("Отмена", null)
                .create();

        dialog.setOnShowListener(ignored -> {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(view -> {
                if (importProfileJson(input.getText().toString(), input)) {
                    dialog.dismiss();
                }
            });
            dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener(view -> pasteClipboard(input));
        });
        dialog.show();
        Window window = dialog.getWindow();
        if (window != null) {
            window.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE);
        }
    }

    private boolean importProfileJson(String raw, EditText errorTarget) {
        try {
            String json = raw == null ? "" : raw.trim();
            if (json.isEmpty()) {
                throw new IllegalArgumentException("JSON пустой");
            }
            if (json.getBytes(StandardCharsets.UTF_8).length > MAX_PROFILE_BYTES) {
                throw new IllegalArgumentException("JSON слишком большой");
            }
            Profile profile = Profile.parse(json);
            ProfileStore.save(this, profile);
            showState(false, "Профиль сохранён. Теперь запусти MorokSS.");
            return true;
        } catch (Exception error) {
            String message = "Не удалось сохранить профиль: " + error.getMessage();
            if (errorTarget != null) {
                errorTarget.setError(message);
                errorTarget.requestFocus();
            }
            showState(false, message);
            return false;
        }
    }

    private void pasteClipboard(EditText input) {
        ClipboardManager clipboard = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
        if (!clipboard.hasPrimaryClip() || clipboard.getPrimaryClip() == null
                || clipboard.getPrimaryClip().getItemCount() == 0) {
            input.setError("Буфер обмена пуст");
            return;
        }
        CharSequence value = clipboard.getPrimaryClip().getItemAt(0).coerceToText(this);
        input.setText(value);
        input.setSelection(input.length());
        input.setError(null);
    }

    private void requestStart() {
        if (!ProfileStore.hasProfile(this)) {
            showState(false, "Сначала выбери файл профиля или вставь JSON");
            return;
        }
        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, REQUEST_NOTIFICATIONS);
            return;
        }
        startTunnel();
    }

    private void startTunnel() {
        Intent intent = new Intent(this, MorokssService.class).setAction(MorokssService.ACTION_START);
        startForegroundService(intent);
        showState(true, "MorokSS запускается…");
    }

    private void stopTunnel() {
        stopService(new Intent(this, MorokssService.class));
        showState(false, "MorokSS остановлен");
    }

    private void copyShadowsocksUri() {
        try {
            Profile profile = ProfileStore.load(this);
            String uri = profile.shadowsocksUri();
            ClipboardManager clipboard = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
            clipboard.setPrimaryClip(ClipData.newPlainText("MorokSS Shadowsocks", uri));
            Toast.makeText(this, "Ссылка скопирована", Toast.LENGTH_SHORT).show();
            showState(MorokssService.isRunning(), "Ссылка ss:// скопирована. Импортируй её в Amnezia.");
        } catch (Exception error) {
            showState(false, "Сначала импортируй профиль: " + error.getMessage());
        }
    }

    private String readProfile(Uri uri) throws Exception {
        try (InputStream input = getContentResolver().openInputStream(uri);
             ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            if (input == null) {
                throw new IllegalStateException("cannot open selected file");
            }
            byte[] buffer = new byte[4096];
            int total = 0;
            int read;
            while ((read = input.read(buffer)) != -1) {
                total += read;
                if (total > MAX_PROFILE_BYTES) {
                    throw new IllegalArgumentException("profile is too large");
                }
                output.write(buffer, 0, read);
            }
            return output.toString(StandardCharsets.UTF_8.name());
        }
    }

    private void refreshState() {
        boolean hasProfile = ProfileStore.hasProfile(this);
        boolean isRunning = MorokssService.isRunning();
        String message;
        if (isRunning) {
            message = "MorokSS работает на 127.0.0.1:8389";
        } else if (hasProfile) {
            message = "Профиль загружен. MorokSS остановлен.";
        } else {
            message = "Выбери файл профиля или вставь JSON вручную.";
        }
        showState(isRunning, message);
    }

    private void showState(boolean isRunning, String message) {
        status.setText(message == null ? "" : message);
        status.setTextColor(isRunning ? Color.rgb(132, 255, 175) : Color.WHITE);
        startButton.setEnabled(!isRunning && ProfileStore.hasProfile(this));
        stopButton.setEnabled(isRunning);
        copyButton.setEnabled(ProfileStore.hasProfile(this));
    }

    private void openNotificationSettings() {
        Intent intent = new Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
                .putExtra(Settings.EXTRA_APP_PACKAGE, getPackageName());
        startActivity(intent);
    }

    private Button button(String label, View.OnClickListener listener) {
        Button button = new Button(this);
        button.setText(label);
        button.setTextSize(15);
        button.setAllCaps(false);
        button.setOnClickListener(listener);
        button.setLayoutParams(matchWidthWithTopMargin());
        return button;
    }

    private TextView text(String value, int size, int color) {
        TextView text = new TextView(this);
        text.setText(value);
        text.setTextSize(size);
        text.setTextColor(color);
        return text;
    }

    private LinearLayout.LayoutParams matchWidth() {
        return new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
        );
    }

    private LinearLayout.LayoutParams matchWidthWithTopMargin() {
        LinearLayout.LayoutParams params = matchWidth();
        params.topMargin = dp(12);
        return params;
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
