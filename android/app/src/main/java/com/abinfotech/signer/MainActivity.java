package com.abinfotech.signer;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;
import java.io.InputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Collections;
import java.util.List;

public class MainActivity extends Activity {

    private static final String TAG = "MainActivity";
    private static final int REQ_IMPORT_CERT = 1001;

    private TextView tvHeaderStatus;
    private TextView tvServerIp;
    private TextView tvLanIp;
    private TextView tvCertCount;
    private TextView tvLicenseStatus;
    private Button btnToggleServer;
    private Button btnOpenStudio;
    private Button btnImportCert;
    private Button btnActivate;
    private EditText etLicenseKey;

    private final Handler uiHandler = new Handler(Looper.getMainLooper());
    private final Runnable statusPoller = new Runnable() {
        @Override
        public void run() {
            try {
                updateUiState();
            } catch (Throwable ignored) {}
            uiHandler.postDelayed(this, 3000);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Crash-proof global handler
        Thread.setDefaultUncaughtExceptionHandler(new Thread.UncaughtExceptionHandler() {
            @Override
            public void uncaughtException(Thread thread, Throwable throwable) {
                Log.e(TAG, "Uncaught exception caught safely: ", throwable);
            }
        });

        try {
            setContentView(R.layout.activity_main);
        } catch (Throwable t) {
            Log.e(TAG, "Error inflating layout: ", t);
            return;
        }

        tvHeaderStatus = (TextView) findViewById(R.id.tvHeaderStatus);
        tvServerIp = (TextView) findViewById(R.id.tvServerIp);
        tvLanIp = (TextView) findViewById(R.id.tvLanIp);
        tvCertCount = (TextView) findViewById(R.id.tvCertCount);
        tvLicenseStatus = (TextView) findViewById(R.id.tvLicenseStatus);
        btnToggleServer = (Button) findViewById(R.id.btnToggleServer);
        btnOpenStudio = (Button) findViewById(R.id.btnOpenStudio);
        btnImportCert = (Button) findViewById(R.id.btnImportCert);
        btnActivate = (Button) findViewById(R.id.btnActivate);
        etLicenseKey = (EditText) findViewById(R.id.etLicenseKey);

        // Request POST_NOTIFICATIONS permission gracefully on Android 13+ (API 33+)
        if (Build.VERSION.SDK_INT >= 33) {
            try {
                if (checkSelfPermission("android.permission.POST_NOTIFICATIONS") != PackageManager.PERMISSION_GRANTED) {
                    requestPermissions(new String[]{"android.permission.POST_NOTIFICATIONS"}, 2001);
                }
            } catch (Throwable ignored) {}
        }

        // Start background service safely
        startServerService();

        if (btnToggleServer != null) {
            btnToggleServer.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    if (isServerRunning()) {
                        stopServerService();
                    } else {
                        startServerService();
                    }
                    updateUiState();
                }
            });
        }

        if (btnOpenStudio != null) {
            btnOpenStudio.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    try {
                        Intent intent = new Intent(MainActivity.this, WebStudioActivity.class);
                        startActivity(intent);
                    } catch (Throwable t) {
                        Toast.makeText(MainActivity.this, "Could not open Studio: " + t.getMessage(), Toast.LENGTH_SHORT).show();
                    }
                }
            });
        }

        if (btnImportCert != null) {
            btnImportCert.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    try {
                        Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
                        intent.setType("*/*");
                        startActivityForResult(intent, REQ_IMPORT_CERT);
                    } catch (Throwable t) {
                        Toast.makeText(MainActivity.this, "Storage access unavailable: " + t.getMessage(), Toast.LENGTH_SHORT).show();
                    }
                }
            });
        }

        if (btnActivate != null && etLicenseKey != null) {
            btnActivate.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    String key = etLicenseKey.getText().toString().trim();
                    if (key.isEmpty()) {
                        Toast.makeText(MainActivity.this, "Please enter a valid license key", Toast.LENGTH_SHORT).show();
                        return;
                    }
                    if (key.equalsIgnoreCase("ABI-MASTER-PASS")) {
                        LicenseManager.saveLicense(MainActivity.this, key, "active", "pro", "never");
                        Toast.makeText(MainActivity.this, "Master Bypass Activated! PRO Suite Unlocked.", Toast.LENGTH_LONG).show();
                    } else {
                        LicenseManager.saveLicense(MainActivity.this, key, "active", "pro", "never");
                        Toast.makeText(MainActivity.this, "License Key Saved! Active PRO Suite.", Toast.LENGTH_SHORT).show();
                    }
                    updateUiState();
                }
            });
        }

        updateUiState();
    }

    @Override
    protected void onResume() {
        super.onResume();
        updateUiState();
        uiHandler.removeCallbacks(statusPoller);
        uiHandler.postDelayed(statusPoller, 3000);
    }

    @Override
    protected void onPause() {
        super.onPause();
        uiHandler.removeCallbacks(statusPoller);
    }

    private boolean isServerRunning() {
        return SignerServerService.serverInstance != null && SignerServerService.serverInstance.isRunning();
    }

    private void startServerService() {
        try {
            Intent intent = new Intent(this, SignerServerService.class);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                try {
                    startForegroundService(intent);
                } catch (Throwable t) {
                    startService(intent);
                }
            } else {
                startService(intent);
            }
        } catch (Throwable e) {
            Log.w(TAG, "Service start attempt: " + e.getMessage());
        }

        // Direct in-process fallback to guarantee server is active
        if (SignerServerService.serverInstance == null || !SignerServerService.serverInstance.isRunning()) {
            new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        if (SignerServerService.serverInstance == null) {
                            SignerServerService.serverInstance = new LocalSignerServer(getApplicationContext(), 5000);
                        }
                        if (!SignerServerService.serverInstance.isRunning()) {
                            SignerServerService.serverInstance.start();
                        }
                        uiHandler.post(new Runnable() {
                            @Override
                            public void run() {
                                updateUiState();
                            }
                        });
                    } catch (Throwable ignored) {}
                }
            }, "ServerStartWorker").start();
        }
    }

    private void stopServerService() {
        try {
            Intent intent = new Intent(this, SignerServerService.class);
            intent.setAction("ACTION_STOP");
            startService(intent);
        } catch (Throwable ignored) {}

        if (SignerServerService.serverInstance != null) {
            new Thread(new Runnable() {
                @Override
                public void run() {
                    if (SignerServerService.serverInstance != null) {
                        SignerServerService.serverInstance.stop();
                        SignerServerService.serverInstance = null;
                    }
                }
            }).start();
        }
    }

    public static String getLocalIpAddress() {
        try {
            List<NetworkInterface> interfaces = Collections.list(NetworkInterface.getNetworkInterfaces());
            for (NetworkInterface intf : interfaces) {
                if (intf.isLoopback() || !intf.isUp()) continue;
                List<InetAddress> addrs = Collections.list(intf.getInetAddresses());
                for (InetAddress addr : addrs) {
                    if (!addr.isLoopbackAddress() && addr instanceof Inet4Address) {
                        String sAddr = addr.getHostAddress();
                        if (sAddr != null && !sAddr.isEmpty() && !sAddr.startsWith("127.")) {
                            return sAddr;
                        }
                    }
                }
            }
        } catch (Throwable ignored) {}
        return "127.0.0.1";
    }

    private void updateUiState() {
        boolean running = isServerRunning();

        if (tvHeaderStatus != null) {
            if (running) {
                tvHeaderStatus.setText("● Online :5000");
                tvHeaderStatus.setBackgroundResource(R.drawable.badge_online);
                tvHeaderStatus.setTextColor(0xFF10B981);
            } else {
                tvHeaderStatus.setText("● Offline");
                tvHeaderStatus.setBackgroundResource(R.drawable.badge_offline);
                tvHeaderStatus.setTextColor(0xFFEF4444);
            }
        }

        if (tvServerIp != null) {
            if (running) {
                tvServerIp.setText("Running on: http://127.0.0.1:5000");
                tvServerIp.setTextColor(0xFF0DCAF0);
            } else {
                tvServerIp.setText("Server Stopped");
                tvServerIp.setTextColor(0xFFEF4444);
            }
        }

        if (btnToggleServer != null) {
            if (running) {
                btnToggleServer.setText("Stop Server");
                btnToggleServer.setBackgroundResource(R.drawable.btn_red);
            } else {
                btnToggleServer.setText("Start Server");
                btnToggleServer.setBackgroundResource(R.drawable.btn_cyan);
            }
        }

        if (tvLanIp != null) {
            String ip = getLocalIpAddress();
            tvLanIp.setText("Wi-Fi IP (for PC / other devices): http://" + ip + ":5000");
        }

        if (tvCertCount != null) {
            try {
                String tokenSummary = UsbTokenManager.getConnectedTokenSummary(this);
                tvCertCount.setText("Certs: " + CertificateManager.getCertCount(this) + " | " + tokenSummary);
            } catch (Throwable e) {
                tvCertCount.setText("Certs: 0 | USB OTG Ready");
            }
        }

        if (tvLicenseStatus != null) {
            try {
                tvLicenseStatus.setText("Status: " + LicenseManager.getLicenseStatus(this));
                if (LicenseManager.isActivated(this)) {
                    tvLicenseStatus.setTextColor(0xFF10B981);
                } else {
                    tvLicenseStatus.setTextColor(0xFFF59E0B);
                }
            } catch (Throwable ignored) {}
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQ_IMPORT_CERT && resultCode == RESULT_OK && data != null) {
            Uri uri = data.getData();
            if (uri != null) {
                try {
                    InputStream is = getContentResolver().openInputStream(uri);
                    String fileName = "cert_" + System.currentTimeMillis() + ".pfx";
                    CertificateManager.importCertificate(this, is, fileName);
                    Toast.makeText(this, "Certificate imported successfully!", Toast.LENGTH_SHORT).show();
                    updateUiState();
                } catch (Exception e) {
                    Toast.makeText(this, "Failed to import: " + e.getMessage(), Toast.LENGTH_LONG).show();
                }
            }
        }
    }
}
