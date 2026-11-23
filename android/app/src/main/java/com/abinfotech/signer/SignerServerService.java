package com.abinfotech.signer;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.IBinder;
import android.util.Log;

public class SignerServerService extends Service {
    private static final String TAG = "SignerServerService";
    private static final String CHANNEL_ID = "abinfo_signer_channel";
    private static final int NOTIF_ID = 5001;
    public static LocalSignerServer serverInstance;

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();

        // Android 14 (API 34) Foreground Service compliance (specialUse)
        try {
            Notification notif = createNotification();
            if (Build.VERSION.SDK_INT >= 34) {
                startForeground(NOTIF_ID, notif, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
            } else {
                startForeground(NOTIF_ID, notif);
            }
        } catch (Throwable t) {
            Log.w(TAG, "startForeground specialUse failed, attempting standard: " + t.getMessage());
            try {
                Notification notif = createNotification();
                startForeground(NOTIF_ID, notif);
            } catch (Throwable t2) {
                Log.e(TAG, "startForeground failed: " + t2.getMessage());
            }
        }

        // Asynchronously start the socket server on a daemon worker thread
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    if (serverInstance == null || !serverInstance.isRunning()) {
                        serverInstance = new LocalSignerServer(getApplicationContext(), 5000);
                        serverInstance.start();
                        Log.i(TAG, "LocalSignerServer started successfully on Port 5000");
                    }
                } catch (Throwable e) {
                    Log.e(TAG, "LocalSignerServer start error: " + e.getMessage());
                }
            }
        }, "SignerServerDaemon").start();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && "ACTION_STOP".equals(intent.getAction())) {
            new Thread(new Runnable() {
                @Override
                public void run() {
                    if (serverInstance != null) {
                        serverInstance.stop();
                        serverInstance = null;
                    }
                }
            }).start();
            try {
                stopForeground(true);
            } catch (Throwable ignored) {}
            stopSelf();
            return START_NOT_STICKY;
        }
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                if (serverInstance != null) {
                    serverInstance.stop();
                    serverInstance = null;
                }
            }
        }).start();
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            try {
                NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID,
                    "A B INFOTECH Signer Server",
                    NotificationManager.IMPORTANCE_LOW
                );
                channel.setDescription("Background PDF digital signing local server on Port 5000");
                NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
                if (nm != null) {
                    nm.createNotificationChannel(channel);
                }
            } catch (Throwable ignored) {}
        }
    }

    private Notification createNotification() {
        Intent notifIntent = new Intent(this, MainActivity.class);
        PendingIntent pi = PendingIntent.getActivity(
            this, 
            0, 
            notifIntent, 
            (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) ? (PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT) : PendingIntent.FLAG_UPDATE_CURRENT
        );

        Notification.Builder builder = (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
            ? new Notification.Builder(this, CHANNEL_ID)
            : new Notification.Builder(this);

        builder
            .setContentTitle("A B INFOTECH Local Signer")
            .setContentText("🟢 Online on Port 5000 (https://127.0.0.1:5000)")
            .setContentIntent(pi)
            .setOngoing(true);

        try {
            builder.setSmallIcon(R.drawable.app_logo);
        } catch (Throwable t) {
            builder.setSmallIcon(android.R.drawable.stat_notify_sync);
        }

        return builder.build();
    }
}
