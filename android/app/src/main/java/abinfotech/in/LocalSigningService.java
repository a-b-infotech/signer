package abinfotech.in.server;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;
import android.util.Log;

import androidx.core.app.NotificationCompat;

import abinfotech.in.MainActivity;
import abinfotech.in.R;

public class LocalSigningService extends Service {

    private static final String TAG = "LocalSigningService";
    private static final String CHANNEL_ID = "abinfo_signer_channel";
    private static final int NOTIFICATION_ID = 5001;

    private LocalSigningServer server;
    private static boolean isRunning = false;

    public static boolean isServerRunning() {
        return isRunning;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && "STOP".equals(intent.getAction())) {
            stopServer();
            stopSelf();
            return START_NOT_STICKY;
        }

        startServer();
        startForeground(NOTIFICATION_ID, buildNotification());
        return START_STICKY;
    }

    private void startServer() {
        if (server == null) {
            try {
                server = new LocalSigningServer(this);
                server.start();
                isRunning = true;
                Log.i(TAG, "Local Signing HTTP Server started on port 5000");
            } catch (Exception e) {
                Log.e(TAG, "Failed to start Local Signing Server: " + e.getMessage(), e);
                isRunning = false;
            }
        }
    }

    private void stopServer() {
        if (server != null) {
            server.stop();
            server = null;
            isRunning = false;
            Log.i(TAG, "Local Signing HTTP Server stopped");
        }
    }

    @Override
    public void onDestroy() {
        stopServer();
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID,
                    "A B INFOTECH Signer Server Service",
                    NotificationManager.IMPORTANCE_LOW
            );
            channel.setDescription("Keeps local HTTP signing server active on port 5000");
            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) {
                manager.createNotificationChannel(channel);
            }
        }
    }

    private Notification buildNotification() {
        Intent notificationIntent = new Intent(this, MainActivity.class);
        PendingIntent pendingIntent = PendingIntent.getActivity(
                this, 0, notificationIntent,
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT
        );

        Intent stopIntent = new Intent(this, LocalSigningService.class);
        stopIntent.setAction("STOP");
        PendingIntent stopPendingIntent = PendingIntent.getService(
                this, 1, stopIntent,
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT
        );

        return new NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("A B INFOTECH SIGNER OFFLINE")
                .setContentText("Local HTTP Signing Server Active on port 5000")
                .setSmallIcon(R.drawable.app_logo)
                .setContentIntent(pendingIntent)
                .addAction(R.drawable.app_logo, "STOP SERVER", stopPendingIntent)
                .setOngoing(true)
                .build();
    }
}