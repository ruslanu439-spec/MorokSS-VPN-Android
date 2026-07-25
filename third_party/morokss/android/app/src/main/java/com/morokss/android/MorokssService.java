package com.morokss.android;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.IBinder;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class MorokssService extends Service {
    static final String ACTION_START = "com.morokss.android.START";
    static final String ACTION_STOP = "com.morokss.android.STOP";
    static final String ACTION_STATE = "com.morokss.android.STATE";
    static final String EXTRA_RUNNING = "running";
    static final String EXTRA_MESSAGE = "message";
    static final String STATUS_PERMISSION = "com.morokss.android.permission.STATUS";

    private static final String TAG = "MorokSS";
    private static final String CHANNEL_ID = "morokss_tunnel";
    private static final int NOTIFICATION_ID = 1043;

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private volatile Process nativeProcess;
    private volatile boolean stopping;
    private static volatile boolean running;

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? ACTION_START : intent.getAction();
        if (ACTION_STOP.equals(action)) {
            stopSelf();
            return START_NOT_STICKY;
        }

        startInForeground("Запуск локального туннеля…");
        if (nativeProcess == null || !nativeProcess.isAlive()) {
            stopping = false;
            executor.execute(this::runNativeClient);
        }
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        stopping = true;
        running = false;
        Process process = nativeProcess;
        nativeProcess = null;
        if (process != null && process.isAlive()) {
            process.destroy();
            if (process.isAlive()) {
                process.destroyForcibly();
            }
        }
        executor.shutdownNow();
        broadcastState(false, "MorokSS остановлен");
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    static boolean isRunning() {
        return running;
    }

    private void runNativeClient() {
        try {
            Profile profile = ProfileStore.load(this);
            File executable = new File(getApplicationInfo().nativeLibraryDir, "libmorokss.so");
            if (!executable.isFile()) {
                throw new IllegalStateException("native MorokSS client is missing for this phone CPU");
            }

            File stateDirectory = new File(getFilesDir(), "client-state");
            if (!stateDirectory.isDirectory() && !stateDirectory.mkdirs()) {
                throw new IllegalStateException("cannot create the client state directory");
            }

            List<String> command = new ArrayList<>();
            command.add(executable.getAbsolutePath());
            addOption(command, "-listen", "127.0.0.1:8389");
            addOption(command, "-udp-listen", "127.0.0.1:8389");
            addOption(command, "-profile", "auto");
            addOption(command, "-transport", "auto");
            addOption(command, "-profile-cache", new File(stateDirectory, "tls-profiles.json").getAbsolutePath());
            addOption(command, "-transport-cache", new File(stateDirectory, "transports.json").getAbsolutePath());
            addOption(command, "-endpoint-cache", new File(stateDirectory, "endpoints.json").getAbsolutePath());
            for (String endpoint : profile.endpoints) {
                addOption(command, "-endpoint", endpoint);
            }

            ProcessBuilder builder = new ProcessBuilder(command);
            builder.redirectErrorStream(true);
            builder.environment().put("MOROKSS_SECRET", profile.secret);
            Process process = builder.start();
            nativeProcess = process;
            if (stopping) {
                process.destroyForcibly();
                return;
            }

            running = true;
            updateNotification("Работает на 127.0.0.1:8389");
            broadcastState(true, "MorokSS работает на 127.0.0.1:8389");

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    Log.i(TAG, line);
                }
            }
            int exitCode = process.waitFor();
            if (!stopping) {
                broadcastState(false, "Клиент остановился, код " + exitCode);
            }
        } catch (Exception error) {
            Log.e(TAG, "MorokSS client failed", error);
            if (!stopping) {
                broadcastState(false, "Ошибка запуска: " + safeMessage(error));
            }
        } finally {
            running = false;
            nativeProcess = null;
            if (!stopping) {
                stopSelf();
            }
        }
    }

    private void startInForeground(String text) {
        Notification notification = notification(text);
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(
                    NOTIFICATION_ID,
                    notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            );
        } else {
            startForeground(NOTIFICATION_ID, notification);
        }
    }

    private void updateNotification(String text) {
        NotificationManager manager = getSystemService(NotificationManager.class);
        manager.notify(NOTIFICATION_ID, notification(text));
    }

    private Notification notification(String text) {
        Intent openIntent = new Intent(this, MainActivity.class);
        PendingIntent openPendingIntent = PendingIntent.getActivity(
                this,
                0,
                openIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
        );

        Intent stopIntent = new Intent(this, MorokssService.class).setAction(ACTION_STOP);
        PendingIntent stopPendingIntent = PendingIntent.getService(
                this,
                1,
                stopIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
        );

        return new Notification.Builder(this, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_morokss)
                .setContentTitle("MorokSS")
                .setContentText(text)
                .setContentIntent(openPendingIntent)
                .setOngoing(true)
                .addAction(new Notification.Action.Builder(null, "Остановить", stopPendingIntent).build())
                .build();
    }

    private void createNotificationChannel() {
        NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID,
                "Туннель MorokSS",
                NotificationManager.IMPORTANCE_LOW
        );
        channel.setDescription("Показывает, когда локальный транспорт MorokSS работает");
        getSystemService(NotificationManager.class).createNotificationChannel(channel);
    }

    private void broadcastState(boolean isRunning, String message) {
        Intent intent = new Intent(ACTION_STATE)
                .setPackage(getPackageName())
                .putExtra(EXTRA_RUNNING, isRunning)
                .putExtra(EXTRA_MESSAGE, message);
        sendBroadcast(intent, STATUS_PERMISSION);
    }

    private static void addOption(List<String> command, String name, String value) {
        command.add(name);
        command.add(value);
    }

    private static String safeMessage(Exception error) {
        String message = error.getMessage();
        if (message == null || message.trim().isEmpty()) {
            return error.getClass().getSimpleName();
        }
        return message.replace('\n', ' ').replace('\r', ' ');
    }
}
