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

        // Asynchronously start Web Server Cloud Tunnel poller (Zero Port Forwarding / Remote Token Relay)
        startCloudTunnelWorker();
    }

    private void startCloudTunnelWorker() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                while (true) {
                    try {
                        android.content.SharedPreferences sp = getSharedPreferences("AbinfoSignerPrefs", Context.MODE_PRIVATE);
                        String tunnelUrl = sp.getString("tunnel_server_url", "");
                        if (tunnelUrl == null || tunnelUrl.trim().isEmpty()) {
                            // Default to local gateway if tested on emulator / LAN
                            tunnelUrl = "http://10.0.2.2/abinfo_signer/Token.php";
                        }
                        if (tunnelUrl.endsWith("/")) tunnelUrl = tunnelUrl.substring(0, tunnelUrl.length() - 1);
                        if (!tunnelUrl.endsWith("Token.php") && !tunnelUrl.contains("action=")) {
                            tunnelUrl += "/Token.php";
                        }

                        java.net.URL pollUrl = new java.net.URL(tunnelUrl + "?action=tunnel_poll&tunnel_id=default");
                        java.net.HttpURLConnection conn = (java.net.HttpURLConnection) pollUrl.openConnection();
                        conn.setRequestMethod("GET");
                        conn.setConnectTimeout(4000);
                        conn.setReadTimeout(4000);
                        conn.setRequestProperty("User-Agent", "ABInfoAndroidSigner/2.2");

                        int code = conn.getResponseCode();
                        if (code == 200) {
                            java.io.InputStream is = conn.getInputStream();
                            java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
                            byte[] buf = new byte[2048];
                            int r;
                            while ((r = is.read(buf)) != -1) baos.write(buf, 0, r);
                            is.close();

                            String jsonStr = new String(baos.toByteArray(), "UTF-8");
                            org.json.JSONObject data = new org.json.JSONObject(jsonStr);
                            if ("job_available".equals(data.optString("status")) && data.has("job")) {
                                org.json.JSONObject job = data.getJSONObject("job");
                                String jobId = job.optString("job_id", "");
                                String endpoint = job.optString("endpoint", "/api/health");

                                if (endpoint.contains("/api/certificates")) {
                                    String pin = job.optJSONObject("params") != null ? job.optJSONObject("params").optString("password", "") : "";
                                    org.json.JSONArray certs = CertificateManager.listCertificatesJson(getApplicationContext(), pin);

                                    java.net.URL respUrl = new java.net.URL(tunnelUrl + "?action=tunnel_respond&tunnel_id=default&job_id=" + jobId);
                                    java.net.HttpURLConnection rConn = (java.net.HttpURLConnection) respUrl.openConnection();
                                    rConn.setRequestMethod("POST");
                                    rConn.setDoOutput(true);
                                    rConn.setRequestProperty("Content-Type", "application/json");
                                    rConn.getOutputStream().write(certs.toString().getBytes("UTF-8"));
                                    rConn.getResponseCode();
                                    rConn.disconnect();
                                }
                            }
                        }
                        conn.disconnect();
                    } catch (Throwable ignored) {}
                    try { Thread.sleep(3000); } catch (Throwable ignored) {}
                }
            }
        }, "CloudTunnelWorker").start();
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
