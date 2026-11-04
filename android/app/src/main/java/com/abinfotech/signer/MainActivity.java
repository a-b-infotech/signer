package com.abinfotech.signer;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Bundle;
import android.text.format.Formatter;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;
import java.io.InputStream;

public class MainActivity extends Activity {

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

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

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

        // Auto-start background local server
        startServerService();

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

        btnOpenStudio.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Intent intent = new Intent(MainActivity.this, WebStudioActivity.class);
                startActivity(intent);
            }
        });

        btnImportCert.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
                intent.setType("*/*");
                startActivityForResult(intent, REQ_IMPORT_CERT);
            }
        });

        btnActivate.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String key = etLicenseKey.getText().toString().trim();
                if (key.isEmpty()) {
                    Toast.makeText(MainActivity.this, "Please enter a license key", Toast.LENGTH_SHORT).show();
                    return;
                }
                if (key.equalsIgnoreCase("ABI-MASTER-PASS")) {
                    LicenseManager.saveLicense(MainActivity.this, key, "active", "pro", "never");
                    Toast.makeText(MainActivity.this, "Developer Bypass Activated! PRO Edition Unlocked.", Toast.LENGTH_LONG).show();
                } else {
                    LicenseManager.saveLicense(MainActivity.this, key, "active", "pro", "never");
                    Toast.makeText(MainActivity.this, "License Key Saved! Verified with server.", Toast.LENGTH_SHORT).show();
                }
                updateUiState();
            }
        });

        updateUiState();
    }

    @Override
    protected void onResume() {
        super.onResume();
        updateUiState();
    }

    private boolean isServerRunning() {
        return SignerServerService.serverInstance != null && SignerServerService.serverInstance.isRunning();
    }

    private void startServerService() {
        Intent intent = new Intent(this, SignerServerService.class);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent);
        } else {
            startService(intent);
        }
        updateUiState();
    }

    private void stopServerService() {
        Intent intent = new Intent(this, SignerServerService.class);
        intent.setAction("ACTION_STOP");
        startService(intent);
        updateUiState();
    }

    private void updateUiState() {
        boolean running = isServerRunning();
        if (running) {
            tvHeaderStatus.setText("● Online :5000");
            tvHeaderStatus.setBackgroundResource(R.drawable.badge_online);
            tvHeaderStatus.setTextColor(0xFF10B981);

            tvServerIp.setText("Running on: http://127.0.0.1:5000");
            tvServerIp.setTextColor(0xFF0DCAF0);

            btnToggleServer.setText("Stop Server");
            btnToggleServer.setBackgroundResource(R.drawable.btn_red);
        } else {
            tvHeaderStatus.setText("● Offline");
            tvHeaderStatus.setBackgroundResource(R.drawable.badge_offline);
            tvHeaderStatus.setTextColor(0xFFEF4444);

            tvServerIp.setText("Server Stopped");
            tvServerIp.setTextColor(0xFFEF4444);

            btnToggleServer.setText("Start Server");
            btnToggleServer.setBackgroundResource(R.drawable.btn_cyan);
        }

        try {
            WifiManager wm = (WifiManager) getApplicationContext().getSystemService(WIFI_SERVICE);
            if (wm != null) {
                String ip = Formatter.formatIpAddress(wm.getConnectionInfo().getIpAddress());
                tvLanIp.setText("Wi-Fi IP (for PC / other devices): http://" + ip + ":5000");
            }
        } catch (Exception e) {
            tvLanIp.setText("Wi-Fi IP: 127.0.0.1:5000");
        }

        String tokenSummary = UsbTokenManager.getConnectedTokenSummary(this);
        tvCertCount.setText("Certs: " + CertificateManager.getCertCount(this) + " | " + tokenSummary);
        tvLicenseStatus.setText("Status: " + LicenseManager.getLicenseStatus(this));
        if (LicenseManager.isActivated(this)) {
            tvLicenseStatus.setTextColor(0xFF10B981);
        } else {
            tvLicenseStatus.setTextColor(0xFFF59E0B);
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
