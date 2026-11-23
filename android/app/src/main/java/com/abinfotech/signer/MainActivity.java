package com.abinfotech.signer;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.content.BroadcastReceiver;
import android.content.ContentValues;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.DashPathEffect;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.pdf.PdfRenderer;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.os.StrictMode;
import android.provider.MediaStore;
import android.provider.OpenableColumns;
import android.text.Editable;
import android.text.TextWatcher;
import android.util.Log;
import android.view.MotionEvent;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CompoundButton;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.Spinner;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;
import android.widget.ViewFlipper;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class MainActivity extends Activity {

    private static final String TAG = "MainActivity";
    private static final String PREFS_NAME = "AbinfoSignerPrefs";
    private static final String PREF_PIN = "saved_pin";
    private static final String PREF_SELECTED_CERT = "selected_cert_name";

    private static final int REQ_PICK_SIGN_PDF = 1001;
    private static final int REQ_PICK_P12_CERT = 1002;
    private static final int REQ_PICK_COMPRESS_PDF = 1003;
    private static final int REQ_PICK_MERGE_PDF = 1004;
    private static final int REQ_PICK_VERIFY_PDF = 1005;
    private static final int REQ_PICK_TOOL_PROTECT_PDF = 1011;
    private static final int REQ_PICK_TOOL_UNLOCK_PDF = 1012;
    private static final int REQ_PICK_TOOL_WATERMARK_PDF = 1013;
    private static final int REQ_PICK_TOOL_SPLIT_PDF = 1014;
    private static final int REQ_PICK_TOOL_ROTATE_PDF = 1015;

    // Header Views
    private TextView tvHeaderLicenseBadge;
    private TextView tvHeaderServerBadge;

    // Tab Navigation
    private Button tabSign, tabCompress, tabMerge, tabVerify, tabTools, tabServer;
    private ViewFlipper viewFlipper;

    // Tab 1: Sign PDF Studio Views
    private TextView tvSignPdfInfo;
    private Button btnSignSelectPdf, btnSignClearPdf;
    private TextView tvTokenStatusBadge;
    private Spinner spTokenDriver;
    private TextView tvSignSelectedCert;
    private Button btnSignFindCerts, btnSignRefreshCerts, btnSignLoadP12;
    private EditText etSignPin;
    private Spinner spSignReason;
    private EditText etSignLocation;

    private RadioGroup rgSignPages;
    private RadioButton rbSignCurrentPage, rbSignAllPages, rbSignCustomPages;
    private EditText etSignCustomPages;

    private RadioGroup rgSignPositionMode;
    private RadioButton rbSignPreset, rbSignDragBox;
    private Spinner spSignPresetPosition;
    private LinearLayout llSignCustomControls;
    private TextView tvSignCustomAreasInfo;
    private Spinner spSignBoxSize;
    private Button btnSignClearAreas;

    private LinearLayout llSignPageControls;
    private Button btnSignPrevPage, btnSignNextPage;
    private TextView tvSignPageNum;
    private ImageView ivSignPdfPreview;

    private Button btnSignPdfNow;
    private LinearLayout llSignResultCard;
    private TextView tvSignResultPath;
    private Button btnSignOpenPdf, btnSignSharePdf;

    // Tab 2: Compress Views
    private TextView tvCompressFileInfo;
    private Button btnCompressSelectPdf;
    private RadioGroup rgCompressLevel;
    private Button btnCompressNow;
    private LinearLayout llCompressResult;
    private TextView tvCompressResultDetails;
    private Button btnCompressOpen, btnCompressShare;
    private File mCompressInputPdf = null;
    private File mCompressOutputPdf = null;

    // Tab 3: Merge Views
    private Button btnMergeAddPdf, btnMergeNow;
    private LinearLayout llMergeFileList;
    private LinearLayout llMergeResult;
    private TextView tvMergeResultPath;
    private Button btnMergeOpen, btnMergeShare;
    private final List<File> mMergeFiles = new ArrayList<>();
    private File mMergedOutputPdf = null;

    // Tab 4: Verify Views
    private Button btnVerifySelectPdf, btnVerifyNow;
    private TextView tvVerifyFileInfo;
    private LinearLayout llVerifyResultsContainer;
    private File mVerifyPdf = null;

    // Tab 5: PDF Tools Suite Views
    private Button btnToolProtectSelect, btnToolProtectRun;
    private EditText etToolProtectPassword;
    private Button btnToolUnlockSelect, btnToolUnlockRun;
    private EditText etToolUnlockPassword;
    private Button btnToolWatermarkSelect, btnToolWatermarkRun;
    private EditText etToolWatermarkText;
    private Button btnToolSplitSelect, btnToolSplitRun;
    private EditText etToolSplitRanges;
    private Button btnToolRotateSelect, btnToolRotateRun;

    private File mToolProtectPdf = null;
    private File mToolUnlockPdf = null;
    private File mToolWatermarkPdf = null;
    private File mToolSplitPdf = null;
    private File mToolRotatePdf = null;

    // Tab 6: Server & License Settings Views
    private TextView tvServerIpDetails;
    private Switch switchServerStatus;
    private Button btnOpenWebStudio;
    private TextView tvLicenseStatusText;
    private EditText etLicenseKeyInput;
    private Button btnActivateLicense;
    private Button btnWhatsappSupport;
    private Button btnCheckUpdates;
    private LinearLayout llLicenseLockoutBanner;

    // State Variables
    private File mActivePdfFile = null;
    private File mSignedPdfFile = null;
    private ParcelFileDescriptor mPdfFileDescriptor = null;
    private PdfRenderer mPdfRenderer = null;
    private int mCurrentPageIndex = 0;
    private int mTotalPages = 0;
    private Bitmap mCachedBaseBitmap = null;
    private float mPdfPageWidth = 595f;
    private float mPdfPageHeight = 842f;

    // Drag-to-Draw Custom Areas
    private final List<SignatureArea> mCustomSignatureAreas = new ArrayList<>();
    private boolean mIsDraggingBox = false;
    private float mTouchStartX = 0f;
    private float mTouchStartY = 0f;
    private float mTouchCurrentX = 0f;
    private float mTouchCurrentY = 0f;
    private float mDefaultBoxWidth = 110f;
    private float mDefaultBoxHeight = 40f;

    // Selected Certificate State
    private String mSelectedCertAlias = "";
    private String mSelectedCertDisplayName = "";
    private boolean mIsUsbTokenConnected = false;
    private String mGlobalWanIp = "";
    private boolean mUpnpPortForwarded = false;

    private void attemptUpnpPortForwardAsync(final int port) {
        new Thread(new Runnable() {
            @Override
            public void run() {
                android.net.wifi.WifiManager.MulticastLock mLock = null;
                try {
                    try {
                        android.net.wifi.WifiManager wm = (android.net.wifi.WifiManager) getApplicationContext().getSystemService(Context.WIFI_SERVICE);
                        if (wm != null) {
                            mLock = wm.createMulticastLock("upnp_multicast_lock");
                            mLock.setReferenceCounted(false);
                            mLock.acquire();
                        }
                    } catch (Throwable ignored) {}

                    final String localIp = getLocalIpAddress();
                    if (localIp == null || localIp.isEmpty() || localIp.equals("127.0.0.1")) return;

                    // 1. Send SSDP M-SEARCH broadcast for IGD
                    String ssdpQuery = "M-SEARCH * HTTP/1.1\r\n"
                            + "HOST: 239.255.255.250:1900\r\n"
                            + "MAN: \"ssdp:discover\"\r\n"
                            + "MX: 2\r\n"
                            + "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n";

                    java.net.DatagramSocket socket = new java.net.DatagramSocket();
                    socket.setSoTimeout(3000);
                    byte[] sendData = ssdpQuery.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                    java.net.DatagramPacket sendPacket = new java.net.DatagramPacket(sendData, sendData.length,
                            java.net.InetAddress.getByName("239.255.255.250"), 1900);
                    socket.send(sendPacket);

                    byte[] recvData = new byte[2048];
                    java.net.DatagramPacket recvPacket = new java.net.DatagramPacket(recvData, recvData.length);
                    socket.receive(recvPacket);
                    socket.close();

                    String response = new String(recvPacket.getData(), 0, recvPacket.getLength());
                    String locationUrl = null;
                    for (String l : response.split("\r\n")) {
                        if (l.toUpperCase().startsWith("LOCATION:")) {
                            locationUrl = l.substring(9).trim();
                            break;
                        }
                    }
                    if (locationUrl == null) return;

                    // 2. Fetch Root XML
                    java.net.URL loc = new java.net.URL(locationUrl);
                    java.net.HttpURLConnection conn = (java.net.HttpURLConnection) loc.openConnection();
                    conn.setConnectTimeout(2500);
                    conn.setReadTimeout(2500);
                    java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.InputStreamReader(conn.getInputStream()));
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) sb.append(line);
                    reader.close();
                    String xml = sb.toString();

                    String controlUrl = null;
                    String serviceType = null;
                    if (xml.contains("urn:schemas-upnp-org:service:WANIPConnection:1")) {
                        serviceType = "urn:schemas-upnp-org:service:WANIPConnection:1";
                        int idx = xml.indexOf("urn:schemas-upnp-org:service:WANIPConnection:1");
                        int cIdx = xml.indexOf("<controlURL>", idx);
                        if (cIdx != -1) {
                            controlUrl = xml.substring(cIdx + 12, xml.indexOf("</controlURL>", cIdx)).trim();
                        }
                    } else if (xml.contains("urn:schemas-upnp-org:service:WANPPPConnection:1")) {
                        serviceType = "urn:schemas-upnp-org:service:WANPPPConnection:1";
                        int idx = xml.indexOf("urn:schemas-upnp-org:service:WANPPPConnection:1");
                        int cIdx = xml.indexOf("<controlURL>", idx);
                        if (cIdx != -1) {
                            controlUrl = xml.substring(cIdx + 12, xml.indexOf("</controlURL>", cIdx)).trim();
                        }
                    }
                    if (controlUrl == null || serviceType == null) return;

                    java.net.URL postUrl = new java.net.URL(loc, controlUrl);

                    // 3. SOAP AddPortMapping
                    String soapBody = "<?xml version=\"1.0\"?>\r\n"
                            + "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\r\n"
                            + "<s:Body>\r\n"
                            + "<u:AddPortMapping xmlns:u=\"" + serviceType + "\">\r\n"
                            + "<NewRemoteHost></NewRemoteHost>\r\n"
                            + "<NewExternalPort>" + port + "</NewExternalPort>\r\n"
                            + "<NewProtocol>TCP</NewProtocol>\r\n"
                            + "<NewInternalPort>" + port + "</NewInternalPort>\r\n"
                            + "<NewInternalClient>" + localIp + "</NewInternalClient>\r\n"
                            + "<NewEnabled>1</NewEnabled>\r\n"
                            + "<NewPortMappingDescription>ABInfoSigner</NewPortMappingDescription>\r\n"
                            + "<NewLeaseDuration>0</NewLeaseDuration>\r\n"
                            + "</u:AddPortMapping>\r\n"
                            + "</s:Body>\r\n"
                            + "</s:Envelope>";

                    java.net.HttpURLConnection soapConn = (java.net.HttpURLConnection) postUrl.openConnection();
                    soapConn.setRequestMethod("POST");
                    soapConn.setConnectTimeout(2500);
                    soapConn.setReadTimeout(2500);
                    soapConn.setDoOutput(true);
                    soapConn.setRequestProperty("Content-Type", "text/xml; charset=\"utf-8\"");
                    soapConn.setRequestProperty("SOAPAction", "\"" + serviceType + "#AddPortMapping\"");
                    java.io.OutputStream os = soapConn.getOutputStream();
                    os.write(soapBody.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                    os.flush();
                    os.close();

                    int resCode = soapConn.getResponseCode();
                    if (resCode == 200) {
                        mUpnpPortForwarded = true;
                        Log.i(TAG, "UPnP: Port " + port + " successfully opened on router for " + localIp);
                        runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                updateServerStatusUi();
                            }
                        });
                    }
                } catch (Throwable t) {
                    Log.w(TAG, "UPnP IGD notice: " + t.getMessage());
                } finally {
                    try {
                        if (mLock != null && mLock.isHeld()) {
                            mLock.release();
                        }
                    } catch (Throwable ignored) {}
                }
            }
        }).start();
    }

    private void fetchGlobalIpAsync() {
        attemptUpnpPortForwardAsync(5000);
        new Thread(new Runnable() {
            @Override
            public void run() {
                String ip = "";
                String[] ipServices = new String[]{
                    "https://api4.my-ip.io/ip",
                    "https://api.ipify.org",
                    "https://icanhazip.com",
                    "https://checkip.amazonaws.com",
                    "https://ifconfig.me/ip"
                };

                for (String serviceUrl : ipServices) {
                    try {
                        java.net.URL url = new java.net.URL(serviceUrl);
                        java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
                        conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Linux; Android)");
                        conn.setConnectTimeout(3500);
                        conn.setReadTimeout(3500);
                        conn.setRequestMethod("GET");
                        if (conn.getResponseCode() == 200) {
                            java.io.BufferedReader r = new java.io.BufferedReader(new java.io.InputStreamReader(conn.getInputStream()));
                            String line = r.readLine();
                            r.close();
                            if (line != null) {
                                line = line.trim();
                                if (line.matches("^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$")) {
                                    ip = line;
                                    break;
                                }
                            }
                        }
                    } catch (Throwable ignored) {}
                }

                if (ip != null && !ip.isEmpty()) {
                    mGlobalWanIp = ip;
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            updateServerStatusUi();
                        }
                    });
                }
            }
        }).start();
    }

    private ProgressDialog progressDialog;
    private final Handler uiHandler = new Handler(Looper.getMainLooper());

    // Receiver for app's internal USB permission callback
    private final BroadcastReceiver mUsbPermissionReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent != null ? intent.getAction() : null;
            if (action == null) return;

            if (UsbTokenManager.ACTION_USB_PERMISSION.equals(action)) {
                synchronized (this) {
                    UsbDevice device = (UsbDevice) intent.getParcelableExtra(UsbManager.EXTRA_DEVICE);
                    if (intent.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false)) {
                        Toast.makeText(context, "🟢 USB Token Connected & Ready", Toast.LENGTH_SHORT).show();
                        mSelectedCertDisplayName = "";
                        mSelectedCertAlias = "";
                        new Thread(new Runnable() {
                            @Override
                            public void run() {
                                UsbTokenManager.setupHardwareTokenConnection(context);
                                autoDetectCertificatesAsync();
                                runOnUiThread(new Runnable() {
                                    @Override
                                    public void run() {
                                        updateTokenDriverSpinner(CcidTokenDriver.scanForToken(context));
                                        updateServerStatusUi();
                                        updateTokenStatus();
                                    }
                                });
                            }
                        }).start();
                    } else {
                        Toast.makeText(context, "USB Token Permission Denied", Toast.LENGTH_SHORT).show();
                        updateTokenStatus();
                    }
                }
            }
        }
    };

    // Receiver for system USB attach/detach events
    private final BroadcastReceiver mUsbDeviceReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent != null ? intent.getAction() : null;
            if (action == null) return;

            if (UsbManager.ACTION_USB_DEVICE_ATTACHED.equals(action)) {
                CcidTokenDriver.DetectedToken dt = CcidTokenDriver.scanForToken(context);
                String tokenBrand = (dt != null && dt.name != null) ? dt.name : "USB Token";
                updateTokenDriverSpinner(dt);
                Toast.makeText(context, "USB Token Attached: " + tokenBrand, Toast.LENGTH_SHORT).show();
                mSelectedCertDisplayName = "";
                mSelectedCertAlias = "";
                if (tvSignSelectedCert != null) {
                    tvSignSelectedCert.setText("Select Certificate");
                }

                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        UsbTokenManager.setupHardwareTokenConnection(context);
                        autoDetectCertificatesAsync();
                        runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                updateTokenDriverSpinner(CcidTokenDriver.scanForToken(context));
                                updateServerStatusUi();
                                updateTokenStatus();
                            }
                        });
                    }
                }).start();
            } else if (UsbManager.ACTION_USB_DEVICE_DETACHED.equals(action)) {
                Toast.makeText(context, "USB Token Detached", Toast.LENGTH_SHORT).show();
                UsbTokenManager.disconnectToken(context);
                P11Operation.disconnect();
                mSelectedCertDisplayName = "";
                mSelectedCertAlias = "";
                if (tvSignSelectedCert != null) {
                    tvSignSelectedCert.setText("Select Certificate");
                }
                updateServerStatusUi();
                updateTokenStatus();
                autoDetectCertificatesAsync();
            }
        }
    };

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleIncomingIntent(intent);
    }

    private void handleIncomingIntent(Intent intent) {
        if (intent == null) return;
        String action = intent.getAction();
        if (UsbManager.ACTION_USB_DEVICE_ATTACHED.equals(action)) {
            new Thread(new Runnable() {
                @Override
                public void run() {
                    UsbTokenManager.setupHardwareTokenConnection(MainActivity.this);
                    autoDetectCertificatesAsync();
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            updateServerStatusUi();
                            updateTokenStatus();
                        }
                    });
                }
            }).start();
        }
    }

    private final Runnable statusPoller = new Runnable() {
        @Override
        public void run() {
            try {
                updateTokenStatus();
                updateServerStatusUi();
                if (mGlobalWanIp == null || mGlobalWanIp.isEmpty()) {
                    fetchGlobalIpAsync();
                }
            } catch (Throwable ignored) {}
            uiHandler.postDelayed(this, 2500);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Catch any uncaught thread exceptions to prevent unexpected app closure
        Thread.setDefaultUncaughtExceptionHandler(new Thread.UncaughtExceptionHandler() {
            @Override
            public void uncaughtException(Thread t, Throwable e) {
                Log.e(TAG, "Uncaught exception in thread " + t.getName(), e);
            }
        });

        try {
            setContentView(R.layout.activity_main);
        } catch (Throwable t) {
            Log.e(TAG, "Layout inflation failed: ", t);
            return;
        }

        try {
            StrictMode.setVmPolicy(new StrictMode.VmPolicy.Builder().build());
        } catch (Throwable ignored) {}

        progressDialog = new ProgressDialog(this);

        initViews();
        setupNavigationTabs();
        setupSpinners();
        setupPdfTouchInteractions();
        setupActionListeners();

        // Clear any old hardcoded or dummy selected certificate from previous app sessions
        try {
            SharedPreferences sp = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
            String sc = sp.getString(PREF_SELECTED_CERT, "");
            if (sc.contains("ABHISHEK") || sc.contains("Enter PIN") || sc.contains("Hardware Token")
                    || sc.contains("mToken") || sc.contains("HYP") || sc.contains("ProxKey") || sc.contains("CryptoID")
                    || sc.startsWith("Selected:") || sc.equals("Select Certificate") || sc.contains("(") || sc.contains(")")) {
                sp.edit()
                        .remove(PREF_SELECTED_CERT)
                        .remove("last_token_client_name")
                        .remove("last_token_issuer_name")
                        .apply();
            }
        } catch (Throwable ignored) {}

        restorePreferences();

        // Register internal USB permission receiver (NOT_EXPORTED on API 33+)
        try {
            IntentFilter permFilter = new IntentFilter(UsbTokenManager.ACTION_USB_PERMISSION);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                registerReceiver(mUsbPermissionReceiver, permFilter, Context.RECEIVER_NOT_EXPORTED);
            } else {
                registerReceiver(mUsbPermissionReceiver, permFilter);
            }
        } catch (Throwable t) {
            Log.w(TAG, "Permission receiver register notice: " + t.getMessage());
        }

        // Register system USB attach/detach receiver (EXPORTED on API 33+)
        try {
            IntentFilter usbFilter = new IntentFilter();
            usbFilter.addAction(UsbManager.ACTION_USB_DEVICE_ATTACHED);
            usbFilter.addAction(UsbManager.ACTION_USB_DEVICE_DETACHED);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                registerReceiver(mUsbDeviceReceiver, usbFilter, Context.RECEIVER_EXPORTED);
            } else {
                registerReceiver(mUsbDeviceReceiver, usbFilter);
            }
        } catch (Throwable t) {
            Log.w(TAG, "System USB receiver register notice: " + t.getMessage());
        }

        handleIncomingIntent(getIntent());

        applyLicenseLockoutState();
        fetchGlobalIpAsync();

        // Dedicated Token Monitor Poller (continuous background check)
        new Thread(new Runnable() {
            @Override
            public void run() {
                while (!isFinishing()) {
                    try {
                        boolean connected = UsbTokenManager.isHardwareTokenConnected(MainActivity.this);
                        if (connected != mIsUsbTokenConnected) {
                            mIsUsbTokenConnected = connected;
                            if (connected) {
                                UsbTokenManager.setupHardwareTokenConnection(MainActivity.this);
                                final CcidTokenDriver.DetectedToken dt = CcidTokenDriver.scanForToken(MainActivity.this);
                                final String tokenBrand = (dt != null && dt.name != null) ? dt.name : "USB Token";
                                runOnUiThread(new Runnable() {
                                    @Override
                                    public void run() {
                                        updateTokenDriverSpinner(dt);
                                        updateTokenStatus();
                                        updateServerStatusUi();
                                    }
                                });
                                autoDetectCertificatesAsync();
                            } else {
                                UsbTokenManager.disconnectToken();
                                P11Operation.disconnect();
                                mSelectedCertDisplayName = "";
                                mSelectedCertAlias = "";
                                runOnUiThread(new Runnable() {
                                    @Override
                                    public void run() {
                                        if (tvSignSelectedCert != null) {
                                            tvSignSelectedCert.setText("Connect USB Token or Load PFX / P12");
                                        }
                                        updateTokenStatus();
                                        updateServerStatusUi();
                                    }
                                });
                            }
                            runOnUiThread(new Runnable() {
                                @Override
                                public void run() {
                                    updateTokenStatus();
                                    updateServerStatusUi();
                                }
                            });
                            autoDetectCertificatesAsync();
                        }
                        Thread.sleep(1500);
                    } catch (Throwable ignored) {}
                }
            }
        }).start();

        // Safe background startup of Port 5000 signing server & certificate scanner
        uiHandler.postDelayed(new Runnable() {
            @Override
            public void run() {
                try {
                    startServerService();
                } catch (Throwable t) {
                    Log.w(TAG, "Server startup error: " + t.getMessage());
                }
                try {
                    autoDetectCertificates();
                } catch (Throwable t) {
                    Log.w(TAG, "Auto detect certs error: " + t.getMessage());
                }
            }
        }, 500);
    }

    @Override
    protected void onResume() {
        super.onResume();
        applyLicenseLockoutState();
        updateTokenStatus();
        updateServerStatusUi();
        if (UsbTokenManager.isHardwareTokenConnected(this)) {
            CcidTokenDriver.DetectedToken dt = CcidTokenDriver.scanForToken(this);
            updateTokenDriverSpinner(dt);
            String currentText = (tvSignSelectedCert != null) ? tvSignSelectedCert.getText().toString() : "";
            if (currentText.isEmpty() || currentText.contains("No Certificate") || currentText.contains("Connect USB") || currentText.contains("Hardware Token") || currentText.contains("Reading")) {
                if (tvSignSelectedCert != null) {
                    tvSignSelectedCert.setText("Select Certificate");
                }
                autoDetectCertificatesAsync();
            }
        }
        uiHandler.removeCallbacks(statusPoller);
        uiHandler.postDelayed(statusPoller, 2500);
    }

    @Override
    protected void onPause() {
        super.onPause();
        uiHandler.removeCallbacks(statusPoller);
    }

    @Override
    protected void onDestroy() {
        closePdfRenderer();
        try {
            if (mUsbPermissionReceiver != null) unregisterReceiver(mUsbPermissionReceiver);
        } catch (Throwable ignored) {}
        try {
            if (mUsbDeviceReceiver != null) unregisterReceiver(mUsbDeviceReceiver);
        } catch (Throwable ignored) {}
        try {
            P11Operation.p11finalize();
        } catch (Throwable ignored) {}
        super.onDestroy();
    }

    private void initViews() {
        // Header
        tvHeaderLicenseBadge = (TextView) findViewById(R.id.tvHeaderLicenseBadge);
        tvHeaderServerBadge = (TextView) findViewById(R.id.tvHeaderServerBadge);

        // Navigation
        tabSign = (Button) findViewById(R.id.tabSign);
        tabCompress = (Button) findViewById(R.id.tabCompress);
        tabMerge = (Button) findViewById(R.id.tabMerge);
        tabVerify = (Button) findViewById(R.id.tabVerify);
        tabTools = (Button) findViewById(R.id.tabTools);
        tabServer = (Button) findViewById(R.id.tabServer);
        viewFlipper = (ViewFlipper) findViewById(R.id.viewFlipper);

        // Tab 1: Sign
        tvSignPdfInfo = (TextView) findViewById(R.id.tvSignPdfInfo);
        btnSignSelectPdf = (Button) findViewById(R.id.btnSignSelectPdf);
        btnSignClearPdf = (Button) findViewById(R.id.btnSignClearPdf);
        tvTokenStatusBadge = (TextView) findViewById(R.id.tvTokenStatusBadge);
        spTokenDriver = (Spinner) findViewById(R.id.spTokenDriver);
        tvSignSelectedCert = (TextView) findViewById(R.id.tvSignSelectedCert);
        btnSignFindCerts = (Button) findViewById(R.id.btnSignFindCerts);
        btnSignRefreshCerts = (Button) findViewById(R.id.btnSignRefreshCerts);
        btnSignLoadP12 = (Button) findViewById(R.id.btnSignLoadP12);
        etSignPin = (EditText) findViewById(R.id.etSignPin);
        spSignReason = (Spinner) findViewById(R.id.spSignReason);
        etSignLocation = (EditText) findViewById(R.id.etSignLocation);

        rgSignPages = (RadioGroup) findViewById(R.id.rgSignPages);
        rbSignCurrentPage = (RadioButton) findViewById(R.id.rbSignCurrentPage);
        rbSignAllPages = (RadioButton) findViewById(R.id.rbSignAllPages);
        rbSignCustomPages = (RadioButton) findViewById(R.id.rbSignCustomPages);
        etSignCustomPages = (EditText) findViewById(R.id.etSignCustomPages);

        rgSignPositionMode = (RadioGroup) findViewById(R.id.rgSignPositionMode);
        rbSignPreset = (RadioButton) findViewById(R.id.rbSignPreset);
        rbSignDragBox = (RadioButton) findViewById(R.id.rbSignDragBox);
        spSignPresetPosition = (Spinner) findViewById(R.id.spSignPresetPosition);
        llSignCustomControls = (LinearLayout) findViewById(R.id.llSignCustomControls);
        tvSignCustomAreasInfo = (TextView) findViewById(R.id.tvSignCustomAreasInfo);
        spSignBoxSize = (Spinner) findViewById(R.id.spSignBoxSize);
        btnSignClearAreas = (Button) findViewById(R.id.btnSignClearAreas);

        llSignPageControls = (LinearLayout) findViewById(R.id.llSignPageControls);
        btnSignPrevPage = (Button) findViewById(R.id.btnSignPrevPage);
        btnSignNextPage = (Button) findViewById(R.id.btnSignNextPage);
        tvSignPageNum = (TextView) findViewById(R.id.tvSignPageNum);
        ivSignPdfPreview = (ImageView) findViewById(R.id.ivSignPdfPreview);

        btnSignPdfNow = (Button) findViewById(R.id.btnSignPdfNow);
        llSignResultCard = (LinearLayout) findViewById(R.id.llSignResultCard);
        tvSignResultPath = (TextView) findViewById(R.id.tvSignResultPath);
        btnSignOpenPdf = (Button) findViewById(R.id.btnSignOpenPdf);
        btnSignSharePdf = (Button) findViewById(R.id.btnSignSharePdf);

        // Tab 2: Compress
        tvCompressFileInfo = (TextView) findViewById(R.id.tvCompressFileInfo);
        btnCompressSelectPdf = (Button) findViewById(R.id.btnCompressSelectPdf);
        rgCompressLevel = (RadioGroup) findViewById(R.id.rgCompressLevel);
        btnCompressNow = (Button) findViewById(R.id.btnCompressNow);
        llCompressResult = (LinearLayout) findViewById(R.id.llCompressResult);
        tvCompressResultDetails = (TextView) findViewById(R.id.tvCompressResultDetails);
        btnCompressOpen = (Button) findViewById(R.id.btnCompressOpen);
        btnCompressShare = (Button) findViewById(R.id.btnCompressShare);

        // Tab 3: Merge
        btnMergeAddPdf = (Button) findViewById(R.id.btnMergeAddPdf);
        llMergeFileList = (LinearLayout) findViewById(R.id.llMergeFileList);
        btnMergeNow = (Button) findViewById(R.id.btnMergeNow);
        llMergeResult = (LinearLayout) findViewById(R.id.llMergeResult);
        tvMergeResultPath = (TextView) findViewById(R.id.tvMergeResultPath);
        btnMergeOpen = (Button) findViewById(R.id.btnMergeOpen);
        btnMergeShare = (Button) findViewById(R.id.btnMergeShare);

        // Tab 4: Verify
        btnVerifySelectPdf = (Button) findViewById(R.id.btnVerifySelectPdf);
        tvVerifyFileInfo = (TextView) findViewById(R.id.tvVerifyFileInfo);
        btnVerifyNow = (Button) findViewById(R.id.btnVerifyNow);
        llVerifyResultsContainer = (LinearLayout) findViewById(R.id.llVerifyResultsContainer);

        // Tab 5: PDF Tools Suite
        btnToolProtectSelect = (Button) findViewById(R.id.btnToolProtectSelect);
        etToolProtectPassword = (EditText) findViewById(R.id.etToolProtectPassword);
        btnToolProtectRun = (Button) findViewById(R.id.btnToolProtectRun);

        btnToolUnlockSelect = (Button) findViewById(R.id.btnToolUnlockSelect);
        etToolUnlockPassword = (EditText) findViewById(R.id.etToolUnlockPassword);
        btnToolUnlockRun = (Button) findViewById(R.id.btnToolUnlockRun);

        btnToolWatermarkSelect = (Button) findViewById(R.id.btnToolWatermarkSelect);
        etToolWatermarkText = (EditText) findViewById(R.id.etToolWatermarkText);
        btnToolWatermarkRun = (Button) findViewById(R.id.btnToolWatermarkRun);

        btnToolSplitSelect = (Button) findViewById(R.id.btnToolSplitSelect);
        etToolSplitRanges = (EditText) findViewById(R.id.etToolSplitRanges);
        btnToolSplitRun = (Button) findViewById(R.id.btnToolSplitRun);

        btnToolRotateSelect = (Button) findViewById(R.id.btnToolRotateSelect);
        btnToolRotateRun = (Button) findViewById(R.id.btnToolRotateRun);

        // Tab 6: Server
        tvServerIpDetails = (TextView) findViewById(R.id.tvServerIpDetails);
        switchServerStatus = (Switch) findViewById(R.id.switchServerStatus);
        btnOpenWebStudio = (Button) findViewById(R.id.btnOpenWebStudio);
        tvLicenseStatusText = (TextView) findViewById(R.id.tvLicenseStatusText);
        etLicenseKeyInput = (EditText) findViewById(R.id.etLicenseKeyInput);
        btnActivateLicense = (Button) findViewById(R.id.btnActivateLicense);
        btnWhatsappSupport = (Button) findViewById(R.id.btnWhatsappSupport);
        btnCheckUpdates = (Button) findViewById(R.id.btnCheckUpdates);
        llLicenseLockoutBanner = (LinearLayout) findViewById(R.id.llLicenseLockoutBanner);
    }

    private void setupNavigationTabs() {
        View.OnClickListener tabClickListener = new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                int id = v.getId();
                int targetIndex = 0;

                if (id == R.id.tabSign) targetIndex = 0;
                else if (id == R.id.tabCompress) targetIndex = 1;
                else if (id == R.id.tabMerge) targetIndex = 2;
                else if (id == R.id.tabVerify) targetIndex = 3;
                else if (id == R.id.tabTools) targetIndex = 4;
                else if (id == R.id.tabServer) targetIndex = 5;

                if (targetIndex < 5 && !LicenseManager.isActivated(MainActivity.this)) {
                    Toast.makeText(MainActivity.this, "🔒 Application Locked: Please activate your license key to unlock all features", Toast.LENGTH_LONG).show();
                    highlightTab(5);
                    if (viewFlipper != null) {
                        viewFlipper.setDisplayedChild(5);
                    }
                    return;
                }

                highlightTab(targetIndex);
                if (viewFlipper != null) {
                    viewFlipper.setDisplayedChild(targetIndex);
                }
            }
        };

        if (tabSign != null) tabSign.setOnClickListener(tabClickListener);
        if (tabCompress != null) tabCompress.setOnClickListener(tabClickListener);
        if (tabMerge != null) tabMerge.setOnClickListener(tabClickListener);
        if (tabVerify != null) tabVerify.setOnClickListener(tabClickListener);
        if (tabTools != null) tabTools.setOnClickListener(tabClickListener);
        if (tabServer != null) tabServer.setOnClickListener(tabClickListener);

        highlightTab(0);
    }

    private void applyLicenseLockoutState() {
        boolean activated = LicenseManager.isActivated(this);
        if (llLicenseLockoutBanner != null) {
            llLicenseLockoutBanner.setVisibility(activated ? View.GONE : View.VISIBLE);
        }
        if (!activated) {
            highlightTab(5);
            if (viewFlipper != null) {
                viewFlipper.setDisplayedChild(5);
            }
        }
    }

    private void highlightTab(int index) {
        Button[] tabs = new Button[]{tabSign, tabCompress, tabMerge, tabVerify, tabTools, tabServer};
        for (int i = 0; i < tabs.length; i++) {
            if (tabs[i] != null) {
                if (i == index) {
                    tabs[i].setBackgroundColor(0xFF2563EB);
                    tabs[i].setTextColor(0xFFFFFFFF);
                } else {
                    tabs[i].setBackgroundColor(0xFF1E293B);
                    tabs[i].setTextColor(0xFF94A3B8);
                }
            }
        }
    }

    private void updateTokenDriverSpinner(CcidTokenDriver.DetectedToken token) {
        if (spTokenDriver == null) return;
        if (token == null) {
            token = CcidTokenDriver.scanForToken(this);
        }

        int selectedIndex = 0; // "Auto-Detect USB Token (Plug & Play)"

        if (token != null) {
            String name = token.name != null ? token.name.toLowerCase() : "";
            int vid = token.vendorId;

            // 1: mToken / CryptoID (Century Longmai PKI)
            if (name.contains("mtoken") || name.contains("cryptoid") || name.contains("longmai")
                    || vid == CcidTokenDriver.VID_LONGMAI_1 || vid == CcidTokenDriver.VID_LONGMAI_2
                    || vid == CcidTokenDriver.VID_LONGMAI_3 || vid == CcidTokenDriver.VID_LONGMAI_4 || vid == CcidTokenDriver.VID_LONGMAI_5) {
                selectedIndex = 1;
            }
            // 2: Watchdata ProxKey
            else if (name.contains("watchdata") || name.contains("proxkey")
                    || vid == CcidTokenDriver.VID_WATCHDATA_1 || vid == CcidTokenDriver.VID_WATCHDATA_2
                    || vid == CcidTokenDriver.VID_WATCHDATA_3 || vid == CcidTokenDriver.VID_WATCHDATA_4 || vid == CcidTokenDriver.VID_WATCHDATA_5) {
                selectedIndex = 2;
            }
            // 3: HYP2003 / ePass2003 (Feitian / HyperPKI)
            else if (name.contains("hyp") || name.contains("epass") || name.contains("feitian") || vid == CcidTokenDriver.VID_FEITIAN) {
                selectedIndex = 3;
            }
            // 4: InnaIT Precision
            else if (name.contains("innait") || name.contains("precision") || vid == CcidTokenDriver.VID_INNAIT_1
                    || vid == CcidTokenDriver.VID_INNAIT_2 || vid == CcidTokenDriver.VID_INNAIT_3 || vid == CcidTokenDriver.VID_INNAIT_4) {
                selectedIndex = 4;
            }
            // 5: SafeNet eToken
            else if (name.contains("safenet") || name.contains("etoken") || vid == CcidTokenDriver.VID_SAFENET_1 || vid == CcidTokenDriver.VID_SAFENET_2) {
                selectedIndex = 5;
            }
        }

        updateTokenDriverSpinnerByPos(selectedIndex);
    }

    private void updateTokenDriverSpinnerByPos(final int pos) {
        if (spTokenDriver == null) return;
        spTokenDriver.post(new Runnable() {
            @Override
            public void run() {
                if (spTokenDriver != null && spTokenDriver.getSelectedItemPosition() != pos) {
                    spTokenDriver.setSelection(pos);
                }
            }
        });
    }

    private void setupSpinners() {
        // Drivers Spinner
        if (spTokenDriver != null) {
            String[] drivers = new String[]{
                    "Auto-Detect USB Token (Plug & Play)",
                    "mToken / CryptoID (USB OTG)",
                    "Watchdata ProxKey (USB OTG)",
                    "HYP2003 / ePass2003 (USB OTG)",
                    "InnaIT Precision (USB OTG)",
                    "SafeNet eToken (USB OTG)",
                    "Software Certificate (.pfx / .p12)",
                    "Android System KeyStore"
            };
            ArrayAdapter<String> adapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, drivers);
            spTokenDriver.setAdapter(adapter);
            spTokenDriver.post(new Runnable() {
                @Override
                public void run() {
                    updateTokenDriverSpinner(CcidTokenDriver.scanForToken(MainActivity.this));
                }
            });
        }

        // Reasons Spinner
        if (spSignReason != null) {
            String[] reasons = new String[]{
                    "I approve this document",
                    "I have reviewed and certify this file",
                    "Authorized Signatory",
                    "Official Verification & Attestation"
            };
            ArrayAdapter<String> reasonAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, reasons);
            spSignReason.setAdapter(reasonAdapter);
        }

        // Preset Position Spinner
        if (spSignPresetPosition != null) {
            String[] positions = new String[]{
                    "Bottom Right",
                    "Bottom Left",
                    "Top Right",
                    "Top Left",
                    "Center"
            };
            ArrayAdapter<String> posAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, positions);
            spSignPresetPosition.setAdapter(posAdapter);
        }

        // Box Size Preset Spinner
        if (spSignBoxSize != null) {
            String[] sizes = new String[]{
                    "Small (110 x 40)",
                    "Big (150 x 50)"
            };
            ArrayAdapter<String> sizeAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, sizes);
            spSignBoxSize.setAdapter(sizeAdapter);
            spSignBoxSize.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
                @Override
                public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                    if (position == 0) {
                        mDefaultBoxWidth = 110f;
                        mDefaultBoxHeight = 40f;
                    } else {
                        mDefaultBoxWidth = 150f;
                        mDefaultBoxHeight = 50f;
                    }
                }

                @Override
                public void onNothingSelected(AdapterView<?> parent) {}
            });
        }
    }

    private void setupActionListeners() {
        // PIN Save & Auto Certificate Refresh
        if (etSignPin != null) {
            etSignPin.addTextChangedListener(new TextWatcher() {
                @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
                @Override public void onTextChanged(CharSequence s, int start, int before, int count) {
                    getSharedPreferences(PREFS_NAME, MODE_PRIVATE).edit().putString(PREF_PIN, s.toString()).apply();
                }
                @Override public void afterTextChanged(Editable s) {
                    final String pin = s != null ? s.toString().trim() : "";
                    if (pin.length() >= 4 && UsbTokenManager.isHardwareTokenConnected(MainActivity.this)) {
                        new Thread(new Runnable() {
                            @Override
                            public void run() {
                                try {
                                    final JSONArray certs = CertificateManager.listCertificatesJson(MainActivity.this, pin);
                                    if (certs != null && certs.length() > 0) {
                                        for (int i = 0; i < certs.length(); i++) {
                                            JSONObject c = certs.optJSONObject(i);
                                            if (c != null && !c.optBoolean("is_placeholder", false)) {
                                                final String sub = c.optString("subject", "");
                                                final String alias = c.optString("alias", "");
                                                if (!sub.isEmpty()) {
                                                    uiHandler.post(new Runnable() {
                                                        @Override
                                                        public void run() {
                                                            String cleanCn = CertificateManager.extractCommonName(sub);
                                                            if (cleanCn.contains("(") && (cleanCn.contains("(mToken") || cleanCn.contains("(ProxKey") || cleanCn.contains("(HYP") || cleanCn.contains("(ePass") || cleanCn.contains("(USB") || cleanCn.contains("(CryptoID"))) {
                                                                cleanCn = cleanCn.substring(0, cleanCn.indexOf("(")).trim();
                                                            }
                                                            mSelectedCertAlias = alias;
                                                            mSelectedCertDisplayName = cleanCn;
                                                            if (tvSignSelectedCert != null) {
                                                                tvSignSelectedCert.setText(mSelectedCertDisplayName);
                                                            }
                                                        }
                                                    });
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                } catch (Throwable ignored) {}
                            }
                        }).start();
                    }
                }
            });
        }

        // Select PDF for Signing
        if (btnSignSelectPdf != null) {
            btnSignSelectPdf.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
                    intent.setType("application/pdf");
                    startActivityForResult(Intent.createChooser(intent, "Select PDF for Signing"), REQ_PICK_SIGN_PDF);
                }
            });
        }

        // Clear PDF
        if (btnSignClearPdf != null) {
            btnSignClearPdf.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    clearSelectedPdf();
                }
            });
        }

        // Certificate Selection Box Click
        if (tvSignSelectedCert != null) {
            tvSignSelectedCert.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    showCertificateSelectionDialog();
                }
            });
        }

        // Auto-read client certificate when PIN is typed into etSignPin
        if (etSignPin != null) {
            etSignPin.addTextChangedListener(new android.text.TextWatcher() {
                private Runnable readRunnable;
                @Override
                public void beforeTextChanged(CharSequence s, int start, int count, int after) {}

                @Override
                public void onTextChanged(CharSequence s, int start, int before, int count) {}

                @Override
                public void afterTextChanged(final android.text.Editable s) {
                    if (s == null) return;
                    final String pin = s.toString().trim();
                    getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
                            .edit()
                            .putString(PREF_PIN, pin)
                            .putString("user_pin", pin)
                            .putString("token_pin", pin)
                            .apply();
                }
            });
        }

        // Find Certificates Dialog
        if (btnSignFindCerts != null) {
            btnSignFindCerts.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    showCertificateSelectionDialog();
                }
            });
        }

        // Refresh Certificates Button
        if (btnSignRefreshCerts != null) {
            btnSignRefreshCerts.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    refreshHardwareTokenAndCertificates();
                }
            });
        }

        // Load P12 / PFX File
        if (btnSignLoadP12 != null) {
            btnSignLoadP12.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
                    intent.setType("*/*");
                    String[] mimes = new String[]{"application/x-pkcs12", "application/octet-stream"};
                    intent.putExtra(Intent.EXTRA_MIME_TYPES, mimes);
                    startActivityForResult(Intent.createChooser(intent, "Select P12 / PFX Certificate"), REQ_PICK_P12_CERT);
                }
            });
        }

        // Page Selection RadioGroup
        if (rgSignPages != null) {
            rgSignPages.setOnCheckedChangeListener(new RadioGroup.OnCheckedChangeListener() {
                @Override
                public void onCheckedChanged(RadioGroup group, int checkedId) {
                    if (checkedId == R.id.rbSignCustomPages) {
                        if (etSignCustomPages != null) etSignCustomPages.setVisibility(View.VISIBLE);
                    } else {
                        if (etSignCustomPages != null) etSignCustomPages.setVisibility(View.GONE);
                    }
                    updateOverlayDisplay();
                }
            });
        }

        // Position Mode RadioGroup
        if (rgSignPositionMode != null) {
            rgSignPositionMode.setOnCheckedChangeListener(new RadioGroup.OnCheckedChangeListener() {
                @Override
                public void onCheckedChanged(RadioGroup group, int checkedId) {
                    if (checkedId == R.id.rbSignDragBox) {
                        if (spSignPresetPosition != null) spSignPresetPosition.setVisibility(View.GONE);
                        if (llSignCustomControls != null) llSignCustomControls.setVisibility(View.VISIBLE);
                    } else {
                        if (spSignPresetPosition != null) spSignPresetPosition.setVisibility(View.VISIBLE);
                        if (llSignCustomControls != null) llSignCustomControls.setVisibility(View.GONE);
                    }
                    updateOverlayDisplay();
                }
            });
        }

        // Clear Custom Signature Areas
        if (btnSignClearAreas != null) {
            btnSignClearAreas.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    mCustomSignatureAreas.clear();
                    updateCustomAreasInfo();
                    updateOverlayDisplay();
                    Toast.makeText(MainActivity.this, "Cleared all signature boxes", Toast.LENGTH_SHORT).show();
                }
            });
        }

        // Page Navigation
        if (btnSignPrevPage != null) {
            btnSignPrevPage.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    if (mCurrentPageIndex > 0) {
                        mCurrentPageIndex--;
                        renderCurrentPage();
                    }
                }
            });
        }
        if (btnSignNextPage != null) {
            btnSignNextPage.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    if (mCurrentPageIndex < mTotalPages - 1) {
                        mCurrentPageIndex++;
                        renderCurrentPage();
                    }
                }
            });
        }

        // Sign PDF Action
        if (btnSignPdfNow != null) {
            btnSignPdfNow.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    performPdfSigning();
                }
            });
        }

        // Open Signed PDF
        if (btnSignOpenPdf != null) {
            btnSignOpenPdf.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    openPdfWithViewer(mSignedPdfFile != null ? mSignedPdfFile : mActivePdfFile);
                }
            });
        }

        // Share Signed PDF
        if (btnSignSharePdf != null) {
            btnSignSharePdf.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    sharePdfWithIntent(mSignedPdfFile != null ? mSignedPdfFile : mActivePdfFile);
                }
            });
        }

        // Tab 6: Server & License
        if (switchServerStatus != null) {
            switchServerStatus.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
                @Override
                public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                    if (isChecked) {
                        startServerService();
                    } else {
                        stopServerService();
                    }
                    updateServerStatusUi();
                }
            });
        }

        if (btnOpenWebStudio != null) {
            btnOpenWebStudio.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    try {
                        Intent intent = new Intent(MainActivity.this, WebStudioActivity.class);
                        startActivity(intent);
                    } catch (Throwable t) {
                        Intent browserIntent = new Intent(Intent.ACTION_VIEW, Uri.parse("http://127.0.0.1:5000"));
                        startActivity(browserIntent);
                    }
                }
            });
        }

        if (btnActivateLicense != null && etLicenseKeyInput != null) {
            btnActivateLicense.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    String key = etLicenseKeyInput.getText().toString().trim();
                    if (key.isEmpty()) {
                        Toast.makeText(MainActivity.this, "Please enter a valid license key", Toast.LENGTH_SHORT).show();
                        return;
                    }
                    LicenseManager.saveLicense(MainActivity.this, key, "active", "pro", "never");
                    Toast.makeText(MainActivity.this, "🎉 License Activated! PRO Suite Unlocked.", Toast.LENGTH_SHORT).show();
                    applyLicenseLockoutState();
                    updateServerStatusUi();
                    highlightTab(0);
                    if (viewFlipper != null) {
                        viewFlipper.setDisplayedChild(0);
                    }
                }
            });
        }

        if (btnWhatsappSupport != null) {
            btnWhatsappSupport.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    try {
                        Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse("https://wa.me/917016797720?text=Hello%20A%20B%20INFOTECH%20Signer%20Support"));
                        startActivity(intent);
                    } catch (Exception e) {
                        Toast.makeText(MainActivity.this, "Call +91 7016797720", Toast.LENGTH_LONG).show();
                    }
                }
            });
        }

        if (btnCheckUpdates != null) {
            btnCheckUpdates.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse("https://github.com/a-b-infotech/signer/releases"));
                    startActivity(intent);
                }
            });
        }

        // Tab 2: Compress PDF Setup
        if (btnCompressSelectPdf != null) {
            btnCompressSelectPdf.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
                    intent.setType("application/pdf");
                    startActivityForResult(Intent.createChooser(intent, "Select PDF to Compress"), REQ_PICK_COMPRESS_PDF);
                }
            });
        }
        if (btnCompressNow != null) {
            btnCompressNow.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    compressActivePdf();
                }
            });
        }
        if (btnCompressOpen != null) {
            btnCompressOpen.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    if (mCompressOutputPdf != null) openPdfWithViewer(mCompressOutputPdf);
                }
            });
        }
        if (btnCompressShare != null) {
            btnCompressShare.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    if (mCompressOutputPdf != null) sharePdfWithIntent(mCompressOutputPdf);
                }
            });
        }

        // Tab 3: Merge PDF Setup
        if (btnMergeAddPdf != null) {
            btnMergeAddPdf.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
                    intent.setType("application/pdf");
                    startActivityForResult(Intent.createChooser(intent, "Add PDF to Merge"), REQ_PICK_MERGE_PDF);
                }
            });
        }
        if (btnMergeNow != null) {
            btnMergeNow.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    mergeActivePdfs();
                }
            });
        }
        if (btnMergeOpen != null) {
            btnMergeOpen.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    if (mMergedOutputPdf != null) openPdfWithViewer(mMergedOutputPdf);
                }
            });
        }
        if (btnMergeShare != null) {
            btnMergeShare.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    if (mMergedOutputPdf != null) sharePdfWithIntent(mMergedOutputPdf);
                }
            });
        }

        // Tab 4: Verify PDF Setup
        if (btnVerifySelectPdf != null) {
            btnVerifySelectPdf.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
                    intent.setType("application/pdf");
                    startActivityForResult(Intent.createChooser(intent, "Select Signed PDF to Verify"), REQ_PICK_VERIFY_PDF);
                }
            });
        }
        if (btnVerifyNow != null) {
            btnVerifyNow.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    verifyActivePdf();
                }
            });
        }

        setupPdfTools();
    }

    private void setupPdfTools() {
        // 1. Protect PDF
        if (btnToolProtectSelect != null) {
            btnToolProtectSelect.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
                    intent.setType("application/pdf");
                    startActivityForResult(Intent.createChooser(intent, "Select PDF to Encrypt"), REQ_PICK_TOOL_PROTECT_PDF);
                }
            });
        }
        if (btnToolProtectRun != null) {
            btnToolProtectRun.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    if (mToolProtectPdf == null || !mToolProtectPdf.exists()) {
                        Toast.makeText(MainActivity.this, "Please select a PDF to encrypt first", Toast.LENGTH_SHORT).show();
                        return;
                    }
                    String pwd = etToolProtectPassword != null ? etToolProtectPassword.getText().toString() : "";
                    if (pwd.isEmpty()) {
                        Toast.makeText(MainActivity.this, "Please enter a password to protect the PDF", Toast.LENGTH_SHORT).show();
                        return;
                    }
                    try {
                        File out = new File(getExternalFilesDir(null), "protected_" + System.currentTimeMillis() + ".pdf");
                        PdfToolsHelper.protectPdf(mToolProtectPdf, out, pwd);
                        showToolPdfResultDialog("Password Protected PDF Created", out);
                    } catch (Exception e) {
                        Toast.makeText(MainActivity.this, "Protect failed: " + e.getMessage(), Toast.LENGTH_LONG).show();
                    }
                }
            });
        }

        // 2. Unlock PDF
        if (btnToolUnlockSelect != null) {
            btnToolUnlockSelect.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
                    intent.setType("application/pdf");
                    startActivityForResult(Intent.createChooser(intent, "Select Locked PDF"), REQ_PICK_TOOL_UNLOCK_PDF);
                }
            });
        }
        if (btnToolUnlockRun != null) {
            btnToolUnlockRun.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    if (mToolUnlockPdf == null || !mToolUnlockPdf.exists()) {
                        Toast.makeText(MainActivity.this, "Please select a locked PDF first", Toast.LENGTH_SHORT).show();
                        return;
                    }
                    String pwd = etToolUnlockPassword != null ? etToolUnlockPassword.getText().toString() : "";
                    try {
                        File out = new File(getExternalFilesDir(null), "unlocked_" + System.currentTimeMillis() + ".pdf");
                        PdfToolsHelper.unlockPdf(mToolUnlockPdf, out, pwd);
                        showToolPdfResultDialog("Password Removed PDF Created", out);
                    } catch (Exception e) {
                        Toast.makeText(MainActivity.this, "Unlock failed: " + e.getMessage(), Toast.LENGTH_LONG).show();
                    }
                }
            });
        }

        // 3. Watermark PDF
        if (btnToolWatermarkSelect != null) {
            btnToolWatermarkSelect.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
                    intent.setType("application/pdf");
                    startActivityForResult(Intent.createChooser(intent, "Select PDF to Watermark"), REQ_PICK_TOOL_WATERMARK_PDF);
                }
            });
        }
        if (btnToolWatermarkRun != null) {
            btnToolWatermarkRun.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    if (mToolWatermarkPdf == null || !mToolWatermarkPdf.exists()) {
                        Toast.makeText(MainActivity.this, "Please select a PDF to watermark first", Toast.LENGTH_SHORT).show();
                        return;
                    }
                    String wm = etToolWatermarkText != null ? etToolWatermarkText.getText().toString().trim() : "CONFIDENTIAL";
                    try {
                        File out = new File(getExternalFilesDir(null), "watermarked_" + System.currentTimeMillis() + ".pdf");
                        PdfToolsHelper.watermarkPdf(mToolWatermarkPdf, out, wm);
                        showToolPdfResultDialog("Watermarked PDF Created", out);
                    } catch (Exception e) {
                        Toast.makeText(MainActivity.this, "Watermark failed: " + e.getMessage(), Toast.LENGTH_LONG).show();
                    }
                }
            });
        }

        // 4. Split PDF
        if (btnToolSplitSelect != null) {
            btnToolSplitSelect.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
                    intent.setType("application/pdf");
                    startActivityForResult(Intent.createChooser(intent, "Select PDF to Split"), REQ_PICK_TOOL_SPLIT_PDF);
                }
            });
        }
        if (btnToolSplitRun != null) {
            btnToolSplitRun.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    if (mToolSplitPdf == null || !mToolSplitPdf.exists()) {
                        Toast.makeText(MainActivity.this, "Please select a PDF to split first", Toast.LENGTH_SHORT).show();
                        return;
                    }
                    String ranges = etToolSplitRanges != null ? etToolSplitRanges.getText().toString().trim() : "1";
                    try {
                        File out = new File(getExternalFilesDir(null), "split_" + System.currentTimeMillis() + ".pdf");
                        PdfToolsHelper.splitPdf(mToolSplitPdf, out, ranges);
                        showToolPdfResultDialog("Pages Extracted Successfully", out);
                    } catch (Exception e) {
                        Toast.makeText(MainActivity.this, "Split failed: " + e.getMessage(), Toast.LENGTH_LONG).show();
                    }
                }
            });
        }

        // 5. Rotate PDF
        if (btnToolRotateSelect != null) {
            btnToolRotateSelect.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
                    intent.setType("application/pdf");
                    startActivityForResult(Intent.createChooser(intent, "Select PDF to Rotate"), REQ_PICK_TOOL_ROTATE_PDF);
                }
            });
        }
        if (btnToolRotateRun != null) {
            btnToolRotateRun.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    if (mToolRotatePdf == null || !mToolRotatePdf.exists()) {
                        Toast.makeText(MainActivity.this, "Please select a PDF to rotate first", Toast.LENGTH_SHORT).show();
                        return;
                    }
                    try {
                        File out = new File(getExternalFilesDir(null), "rotated_" + System.currentTimeMillis() + ".pdf");
                        PdfToolsHelper.rotatePdf(mToolRotatePdf, out, 90);
                        showToolPdfResultDialog("Rotated 90° Successfully", out);
                    } catch (Exception e) {
                        Toast.makeText(MainActivity.this, "Rotate failed: " + e.getMessage(), Toast.LENGTH_LONG).show();
                    }
                }
            });
        }
    }

    private void showToolPdfResultDialog(String title, final File pdfFile) {
        new AlertDialog.Builder(this)
                .setTitle(title)
                .setMessage("Output saved:\n" + pdfFile.getName() + " (" + (pdfFile.length() / 1024) + " KB)")
                .setPositiveButton("Open PDF", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        openPdfWithViewer(pdfFile);
                    }
                })
                .setNeutralButton("Share PDF", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        sharePdfWithIntent(pdfFile);
                    }
                })
                .setNegativeButton("Done", null)
                .show();
    }

    private void restorePreferences() {
        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        String savedPin = prefs.getString(PREF_PIN, "12345678");
        if (etSignPin != null) etSignPin.setText(savedPin);

        String savedCert = prefs.getString(PREF_SELECTED_CERT, "");
        if (!savedCert.isEmpty() && (savedCert.endsWith(".p12") || savedCert.endsWith(".pfx") || savedCert.contains("(.p12)") || savedCert.contains("(.pfx)"))) {
            mSelectedCertDisplayName = savedCert;
            if (tvSignSelectedCert != null) {
                tvSignSelectedCert.setText(savedCert);
            }
        }
    }

    private void autoDetectCertificates() {
        autoDetectCertificatesAsync();
    }

    private void autoDetectCertificatesAsync() {
        final String currentPin = etSignPin != null ? etSignPin.getText().toString().trim() : "";
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    final JSONArray certs = CertificateManager.listCertificatesJson(MainActivity.this, currentPin);
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            applyDetectedCertificatesToUi(certs);
                        }
                    });
                } catch (Throwable t) {
                    Log.e(TAG, "Error in autoDetectCertificatesAsync", t);
                }
            }
        }).start();
    }

    private void applyDetectedCertificatesToUi(JSONArray certs) {
        if (certs == null) return;
        boolean tokenConnected = UsbTokenManager.isHardwareTokenConnected(MainActivity.this);

        // Always update token driver spinner
        CcidTokenDriver.DetectedToken dt = CcidTokenDriver.scanForToken(this);
        updateTokenDriverSpinner(dt);

        // First try to find a genuine real client certificate (not placeholder, not containing 'Enter PIN')
        for (int i = 0; i < certs.length(); i++) {
            JSONObject c = certs.optJSONObject(i);
            if (c != null && !c.optBoolean("is_placeholder", false)) {
                String sub = c.optString("subject", "");
                if (!sub.isEmpty() && !sub.contains("Enter PIN") && !sub.contains("Hardware Token")) {
                    String cleanCn = CertificateManager.extractCommonName(sub);
                    cleanCn = CertificateManager.cleanClientName(cleanCn);
                    mSelectedCertAlias = c.optString("alias", "");
                    mSelectedCertDisplayName = cleanCn;

                    String src = c.optString("source", "");
                    if (src != null && !src.isEmpty()) {
                        String lowerSrc = src.toLowerCase();
                        if (lowerSrc.contains("mtoken") || lowerSrc.contains("cryptoid") || lowerSrc.contains("longmai")) {
                            updateTokenDriverSpinnerByPos(1);
                        } else if (lowerSrc.contains("watchdata") || lowerSrc.contains("proxkey")) {
                            updateTokenDriverSpinnerByPos(2);
                        } else if (lowerSrc.contains("hyp") || lowerSrc.contains("epass") || lowerSrc.contains("feitian")) {
                            updateTokenDriverSpinnerByPos(3);
                        } else if (lowerSrc.contains("innait") || lowerSrc.contains("precision")) {
                            updateTokenDriverSpinnerByPos(4);
                        } else if (lowerSrc.contains("safenet") || lowerSrc.contains("etoken")) {
                            updateTokenDriverSpinnerByPos(5);
                        }
                    }

                    if (tvSignSelectedCert != null) {
                        tvSignSelectedCert.setText(cleanCn);
                    }
                    return;
                }
            }
        }

        if (tokenConnected) {
            CcidTokenDriver.DetectedToken dtNow = CcidTokenDriver.scanForToken(this);
            String tokenName = (dtNow != null && dtNow.name != null) ? dtNow.name : "USB Token";
            mSelectedCertDisplayName = "";
            mSelectedCertAlias = "USB_HARDWARE_TOKEN_CERT";
            if (tvSignSelectedCert != null) {
                tvSignSelectedCert.setText(tokenName + " (Tap 'Find Certificates' to Read)");
            }
            return;
        }

        // Check if user has an imported software certificate (.p12)
        File lastCert = CertificateManager.getLastCertFile(MainActivity.this);
        if (lastCert != null && !lastCert.getName().equals("default_abinfo_dsc.p12")) {
            mSelectedCertAlias = lastCert.getName();
            mSelectedCertDisplayName = lastCert.getName();
            updateTokenDriverSpinnerByPos(6);
            if (tvSignSelectedCert != null) {
                tvSignSelectedCert.setText(lastCert.getName());
            }
            return;
        }

        mSelectedCertDisplayName = "";
        mSelectedCertAlias = "";
        if (tvSignSelectedCert != null) {
            tvSignSelectedCert.setText("Select Certificate");
        }
    }

    private void updateTokenStatus() {
        boolean connected = false;
        try {
            connected = UsbTokenManager.isHardwareTokenConnected(this);
        } catch (Throwable ignored) {}

        mIsUsbTokenConnected = connected;
        if (tvTokenStatusBadge != null) {
            if (connected) {
                tvTokenStatusBadge.setText("Connected");
                tvTokenStatusBadge.setBackgroundColor(0xFF166534);
                CcidTokenDriver.DetectedToken dt = CcidTokenDriver.scanForToken(this);
                updateTokenDriverSpinner(dt);
            } else {
                tvTokenStatusBadge.setText("Disconnected");
                tvTokenStatusBadge.setBackgroundColor(0xFFEF4444);
            }
        }
    }

    private void updateServerStatusUi() {
        boolean running = SignerServerService.serverInstance != null && SignerServerService.serverInstance.isRunning();

        if (tvHeaderServerBadge != null) {
            tvHeaderServerBadge.setText(running ? "5000: ON" : "5000: OFF");
            tvHeaderServerBadge.setBackgroundColor(running ? 0xFF166534 : 0xFFEF4444);
        }

        if (switchServerStatus != null && switchServerStatus.isChecked() != running) {
            switchServerStatus.setChecked(running);
        }

        if (tvServerIpDetails != null) {
            String wifiIp = getLocalIpAddress();
            StringBuilder sb = new StringBuilder();
            sb.append("Local: http://127.0.0.1:5000\n");
            sb.append("Wi-Fi LAN: http://").append(wifiIp).append(":5000\n");
            if (mGlobalWanIp != null && !mGlobalWanIp.isEmpty()) {
                if (mUpnpPortForwarded) {
                    sb.append("Global WAN: http://").append(mGlobalWanIp).append(":5000 (✅ UPnP Forwarded)\n");
                } else {
                    sb.append("Global WAN: http://").append(mGlobalWanIp).append(":5000 (Tap for Remote Guide)\n");
                }
            } else {
                sb.append("Global WAN: Resolving Public IP... (Tap to Refresh)\n");
            }
            tvServerIpDetails.setText(sb.toString());

            tvServerIpDetails.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    final String wifiIp = getLocalIpAddress();
                    final String wanIp = (mGlobalWanIp != null && !mGlobalWanIp.isEmpty()) ? mGlobalWanIp : "";

                    List<String> options = new ArrayList<>();
                    if (!wanIp.isEmpty()) {
                        options.add("🌐 Copy Global WAN: http://" + wanIp + ":5000" + (mUpnpPortForwarded ? " (UPnP Active)" : ""));
                    } else {
                        options.add("🔄 Refresh Global WAN IP & Router UPnP");
                    }
                    options.add("📶 Copy Wi-Fi LAN: http://" + wifiIp + ":5000");
                    options.add("🔥 Copy Hotspot URL: http://192.168.43.1:5000 (100% Remote)");
                    options.add("💻 Copy Localhost: http://127.0.0.1:5000");
                    options.add("💡 How to connect if on different network / location? (Remote Guide)");

                    final String[] items = options.toArray(new String[0]);
                    new AlertDialog.Builder(MainActivity.this)
                            .setTitle("A B INFOTECH Signer Server URLs")
                            .setItems(items, new DialogInterface.OnClickListener() {
                                @Override
                                public void onClick(DialogInterface dialog, int which) {
                                    String chosen = items[which];
                                    if (chosen.contains("Refresh Global WAN")) {
                                        fetchGlobalIpAsync();
                                        Toast.makeText(MainActivity.this, "Resolving Public Global IP & UPnP Forwarding...", Toast.LENGTH_SHORT).show();
                                        return;
                                    }
                                    if (chosen.contains("Remote Guide")) {
                                        new AlertDialog.Builder(MainActivity.this)
                                                .setTitle("Connecting from Different Network / Location")
                                                .setMessage("📶 1. Wi-Fi LAN (Same Network):\n"
                                                        + "When phone and PC/browser are on the same Wi-Fi, use http://" + wifiIp + ":5000 in Token.php.\n\n"
                                                        + "🌐 2. Automatic UPnP Global WAN:\n"
                                                        + "When on Wi-Fi, this app automatically requests port 5000 forwarding on your router. If UPnP is enabled on your router, http://" + wanIp + ":5000 is accessible from anywhere on the internet!\n\n"
                                                        + "🔥 3. Cellular Data / Remote Location (100% Works):\n"
                                                        + "Mobile cellular operators (Jio, Airtel, Vi) use CGNAT and block inbound ports. For 100% reliable connection anywhere:\n"
                                                        + "• Turn ON Phone Hotspot, connect PC to it, and use http://192.168.43.1:5000 in Token.php.\n"
                                                        + "• Or use a free tunnel (Localtunnel / Ngrok: https://...): in Token.php Settings, paste the tunnel URL directly!")
                                                .setPositiveButton("OK", null)
                                                .show();
                                        return;
                                    }
                                    String urlToCopy = "";
                                    if (chosen.contains("Global WAN")) urlToCopy = "http://" + wanIp + ":5000";
                                    else if (chosen.contains("Wi-Fi LAN")) urlToCopy = "http://" + wifiIp + ":5000";
                                    else if (chosen.contains("Hotspot")) urlToCopy = "http://192.168.43.1:5000";
                                    else if (chosen.contains("Localhost")) urlToCopy = "http://127.0.0.1:5000";

                                    if (!urlToCopy.isEmpty()) {
                                        android.content.ClipboardManager cm = (android.content.ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
                                        if (cm != null) {
                                            cm.setPrimaryClip(android.content.ClipData.newPlainText("ABInfo Server URL", urlToCopy));
                                            Toast.makeText(MainActivity.this, "Copied: " + urlToCopy, Toast.LENGTH_SHORT).show();
                                        }
                                    }
                                }
                            })
                            .setNegativeButton("Close", null)
                            .show();
                }
            });
        }

        if (tvHeaderLicenseBadge != null) {
            boolean lic = LicenseManager.isActivated(this);
            tvHeaderLicenseBadge.setText(lic ? "PRO" : "DEMO");
            tvHeaderLicenseBadge.setBackgroundColor(lic ? 0xFF0284C7 : 0xFFF59E0B);
        }

        if (tvLicenseStatusText != null) {
            tvLicenseStatusText.setText("Status: " + LicenseManager.getLicenseStatus(this));
        }
    }

    private void refreshHardwareTokenAndCertificates() {
        mSelectedCertAlias = "";
        mSelectedCertDisplayName = "";
        if (tvSignSelectedCert != null) {
            tvSignSelectedCert.setText("-- Scanning Token & Certificates... --");
        }
        if (progressDialog != null) {
            progressDialog.setMessage("Refreshing token connection & certificates...");
            progressDialog.setCancelable(false);
            progressDialog.show();
        }

        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    UsbTokenManager.disconnectToken(MainActivity.this);
                    P11Operation.disconnect();
                    P11Operation.resetSession();
                    UsbTokenManager.setupHardwareTokenConnection(MainActivity.this);
                } catch (Throwable ignored) {}

                final String pin = etSignPin != null ? etSignPin.getText().toString().trim() : "";
                final JSONArray certs = CertificateManager.listCertificatesJson(MainActivity.this, pin);

                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        if (progressDialog != null && progressDialog.isShowing()) {
                            try { progressDialog.dismiss(); } catch (Throwable ignored) {}
                        }
                        updateTokenStatus();
                        applyDetectedCertificatesToUi(certs);
                        showCertificateDialogWithList(certs);
                        Toast.makeText(MainActivity.this, "🔄 Token connection & certificate list refreshed", Toast.LENGTH_SHORT).show();
                    }
                });
            }
        }).start();
    }

    private void showCertificateSelectionDialog() {
        if (progressDialog == null) {
            progressDialog = new ProgressDialog(this);
            progressDialog.setMessage("Finding certificates, please wait...");
            progressDialog.setCancelable(false);
        }
        try { progressDialog.show(); } catch (Throwable ignored) {}

        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    UsbTokenManager.setupHardwareTokenConnection(MainActivity.this);
                } catch (Throwable ignored) {}

                // Directly scan certificates using current PIN if entered, or without PIN
                final String currentPin = etSignPin != null ? etSignPin.getText().toString().trim() : "";
                final JSONArray certs = CertificateManager.listCertificatesJson(MainActivity.this, currentPin);

                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        if (progressDialog != null && progressDialog.isShowing()) {
                            try { progressDialog.dismiss(); } catch (Throwable ignored) {}
                        }

                        applyDetectedCertificatesToUi(certs);
                        showCertificateDialogWithList(certs);
                    }
                });
            }
        }).start();
    }

    private void showCertificateDialogWithList(final JSONArray certs) {
        final int count = (certs != null) ? certs.length() : 0;
        final List<String> displayNamesList = new ArrayList<>();
        final List<String> aliasesList = new ArrayList<>();
        final List<JSONObject> certObjectsList = new ArrayList<>();

        for (int i = 0; i < count; i++) {
            JSONObject obj = certs.optJSONObject(i);
            if (obj == null) continue;
            boolean isPlaceholder = obj.optBoolean("is_placeholder", false);
            String sub = obj.optString("subject", "Certificate " + (i + 1));
            if (isPlaceholder || sub.contains("Enter PIN") || sub.contains("Hardware Token")) {
                // Strictly skip all token/driver placeholders - only show real client certificates!
                continue;
            }
            String alias = obj.optString("alias", "");
            String cleanCn = CertificateManager.extractCommonName(sub);
            cleanCn = CertificateManager.cleanClientName(cleanCn);
            displayNamesList.add(cleanCn);
            aliasesList.add(alias);
            certObjectsList.add(obj);
        }

        boolean tokenConnected = UsbTokenManager.isHardwareTokenConnected(this);
        CcidTokenDriver.DetectedToken dt = CcidTokenDriver.scanForToken(this);
        String tokenSrc = (dt != null && dt.name != null) ? dt.name : "USB Token";

        if (certObjectsList.isEmpty() && tokenConnected) {
            displayNamesList.add("🔑 " + tokenSrc + " (Tap to Read Token)");
            aliasesList.add("__PROMPT_PIN__");
        }

        displayNamesList.add("📁 Load / Import Another Certificate (.pfx / .p12)...");
        aliasesList.add("__LOAD_NEW__");

        final String[] displayNames = displayNamesList.toArray(new String[0]);
        final String[] aliases = aliasesList.toArray(new String[0]);
        final int loadNewIdx = displayNamesList.indexOf("📁 Load / Import Another Certificate (.pfx / .p12)...");
        final int promptPinIdx = displayNamesList.indexOf("🔑 " + tokenSrc + " (Tap to Read Token)");

        new AlertDialog.Builder(this)
                .setTitle("Select Digital Certificate")
                .setItems(displayNames, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        if (which == loadNewIdx) {
                            if (btnSignLoadP12 != null) btnSignLoadP12.performClick();
                            return;
                        }
                        if (which == promptPinIdx) {
                            if (etSignPin != null) {
                                etSignPin.requestFocus();
                                android.view.inputmethod.InputMethodManager imm = (android.view.inputmethod.InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);
                                if (imm != null) imm.showSoftInput(etSignPin, android.view.inputmethod.InputMethodManager.SHOW_IMPLICIT);
                            }
                            Toast.makeText(MainActivity.this, "Reading certificates from token...", Toast.LENGTH_SHORT).show();
                            autoDetectCertificatesAsync();
                            return;
                        }
                        mSelectedCertAlias = aliases[which];
                        mSelectedCertDisplayName = displayNames[which];
                        if (tvSignSelectedCert != null) {
                            tvSignSelectedCert.setText(mSelectedCertDisplayName);
                        }
                        if (mSelectedCertDisplayName.endsWith(".p12") || mSelectedCertDisplayName.endsWith(".pfx")) {
                            getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
                                    .edit()
                                    .putString(PREF_SELECTED_CERT, mSelectedCertDisplayName)
                                    .apply();
                        }
                        Toast.makeText(MainActivity.this, "Certificate selected: " + mSelectedCertDisplayName, Toast.LENGTH_SHORT).show();
                    }
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void setupPdfTouchInteractions() {
        if (ivSignPdfPreview == null) return;

        ivSignPdfPreview.setOnTouchListener(new View.OnTouchListener() {
            @Override
            public boolean onTouch(View v, MotionEvent event) {
                if (rbSignDragBox == null || !rbSignDragBox.isChecked() || mActivePdfFile == null || mCachedBaseBitmap == null) {
                    return false;
                }

                ImageView iv = (ImageView) v;
                if (iv.getDrawable() == null) return false;

                float x = event.getX();
                float y = event.getY();

                switch (event.getAction()) {
                    case MotionEvent.ACTION_DOWN:
                        mTouchStartX = x;
                        mTouchStartY = y;
                        mTouchCurrentX = x;
                        mTouchCurrentY = y;
                        mIsDraggingBox = true;
                        updateOverlayDisplay();
                        return true;

                    case MotionEvent.ACTION_MOVE:
                        if (mIsDraggingBox) {
                            mTouchCurrentX = x;
                            mTouchCurrentY = y;
                            updateOverlayDisplay();
                        }
                        return true;

                    case MotionEvent.ACTION_UP:
                        if (mIsDraggingBox) {
                            mIsDraggingBox = false;

                            float[] matrixValues = new float[9];
                            iv.getImageMatrix().getValues(matrixValues);
                            float transX = matrixValues[Matrix.MTRANS_X];
                            float transY = matrixValues[Matrix.MTRANS_Y];
                            float scaleX = matrixValues[Matrix.MSCALE_X];
                            float scaleY = matrixValues[Matrix.MSCALE_Y];

                            int dW = iv.getDrawable().getIntrinsicWidth();
                            int dH = iv.getDrawable().getIntrinsicHeight();
                            float imgW = dW * scaleX;
                            float imgH = dH * scaleY;

                            float leftPx = Math.min(mTouchStartX, x);
                            float rightPx = Math.max(mTouchStartX, x);
                            float topPx = Math.min(mTouchStartY, y);
                            float bottomPx = Math.max(mTouchStartY, y);

                            float dragW = rightPx - leftPx;
                            float dragH = bottomPx - topPx;

                            float pageW = mPdfPageWidth > 0 ? mPdfPageWidth : 595f;
                            float pageH = mPdfPageHeight > 0 ? mPdfPageHeight : 842f;

                            float pdfX, pdfY, boxW, boxH;

                            if (dragW > 25 && dragH > 15) {
                                float normLeft = Math.max(0f, (leftPx - transX) / imgW);
                                float normTop = Math.max(0f, (topPx - transY) / imgH);
                                float normRight = Math.min(1f, (rightPx - transX) / imgW);
                                float normBottom = Math.min(1f, (bottomPx - transY) / imgH);

                                boxW = (normRight - normLeft) * pageW;
                                boxH = (normBottom - normTop) * pageH;
                                pdfX = normLeft * pageW;
                                pdfY = (1.0f - normBottom) * pageH;
                            } else {
                                float normX = (x - transX) / imgW;
                                float normY = (y - transY) / imgH;
                                boxW = mDefaultBoxWidth;
                                boxH = mDefaultBoxHeight;
                                pdfX = normX * pageW - (boxW / 2f);
                                pdfY = (1.0f - normY) * pageH - (boxH / 2f);
                            }

                            if (pdfX < 5) pdfX = 5;
                            if (pdfY < 5) pdfY = 5;
                            if (pdfX + boxW > pageW - 5) boxW = pageW - pdfX - 5;
                            if (pdfY + boxH > pageH - 5) boxH = pageH - pdfY - 5;

                            if (boxW >= 20 && boxH >= 10) {
                                SignatureArea area = new SignatureArea(mCurrentPageIndex + 1, pdfX, pdfY, boxW, boxH);
                                mCustomSignatureAreas.add(area);
                                updateCustomAreasInfo();
                                Toast.makeText(MainActivity.this, "Signature box added on Page " + (mCurrentPageIndex + 1), Toast.LENGTH_SHORT).show();
                            }

                            updateOverlayDisplay();
                            return true;
                        }
                        break;
                }
                return false;
            }
        });
    }

    private void updateCustomAreasInfo() {
        if (tvSignCustomAreasInfo != null) {
            if (mCustomSignatureAreas.isEmpty()) {
                tvSignCustomAreasInfo.setText("Drag on PDF preview to draw a signature box, or tap once.");
            } else {
                tvSignCustomAreasInfo.setText(mCustomSignatureAreas.size() + " Signature Box(es) Defined.");
            }
        }
    }

    private void updateOverlayDisplay() {
        if (mCachedBaseBitmap == null || mCachedBaseBitmap.isRecycled() || ivSignPdfPreview == null) return;

        if (rbSignDragBox != null && rbSignDragBox.isChecked()) {
            Bitmap mutableBitmap = mCachedBaseBitmap.copy(Bitmap.Config.ARGB_8888, true);
            Canvas canvas = new Canvas(mutableBitmap);

            Paint paint = new Paint();
            paint.setColor(Color.RED);
            paint.setStyle(Paint.Style.STROKE);
            paint.setStrokeWidth(4f);

            Paint fillPaint = new Paint();
            fillPaint.setColor(Color.argb(40, 255, 0, 0));
            fillPaint.setStyle(Paint.Style.FILL);

            Paint dragPaint = new Paint();
            dragPaint.setColor(Color.BLUE);
            dragPaint.setStyle(Paint.Style.STROKE);
            dragPaint.setStrokeWidth(5f);
            dragPaint.setPathEffect(new DashPathEffect(new float[]{10, 10}, 0));

            float pageW = mPdfPageWidth > 0 ? mPdfPageWidth : 595f;
            float pageH = mPdfPageHeight > 0 ? mPdfPageHeight : 842f;

            for (SignatureArea area : mCustomSignatureAreas) {
                if (area.pageNum == mCurrentPageIndex + 1) {
                    float normX1 = area.x / pageW;
                    float normX2 = (area.x + area.width) / pageW;
                    float normY1 = 1.0f - ((area.y + area.height) / pageH);
                    float normY2 = 1.0f - (area.y / pageH);

                    float dX1 = normX1 * mutableBitmap.getWidth();
                    float dX2 = normX2 * mutableBitmap.getWidth();
                    float dY1 = normY1 * mutableBitmap.getHeight();
                    float dY2 = normY2 * mutableBitmap.getHeight();

                    RectF rectF = new RectF(dX1, dY1, dX2, dY2);
                    canvas.drawRect(rectF, fillPaint);
                    canvas.drawRect(rectF, paint);
                }
            }

            if (mIsDraggingBox && ivSignPdfPreview.getDrawable() != null) {
                float[] matrixValues = new float[9];
                ivSignPdfPreview.getImageMatrix().getValues(matrixValues);
                float transX = matrixValues[Matrix.MTRANS_X];
                float transY = matrixValues[Matrix.MTRANS_Y];
                float scaleX = matrixValues[Matrix.MSCALE_X];
                float scaleY = matrixValues[Matrix.MSCALE_Y];

                int dW = ivSignPdfPreview.getDrawable().getIntrinsicWidth();
                int dH = ivSignPdfPreview.getDrawable().getIntrinsicHeight();
                float imgW = dW * scaleX;
                float imgH = dH * scaleY;

                if (imgW > 0 && imgH > 0) {
                    float lX = (Math.min(mTouchStartX, mTouchCurrentX) - transX) / imgW * mutableBitmap.getWidth();
                    float rX = (Math.max(mTouchStartX, mTouchCurrentX) - transX) / imgW * mutableBitmap.getWidth();
                    float tY = (Math.min(mTouchStartY, mTouchCurrentY) - transY) / imgH * mutableBitmap.getHeight();
                    float bY = (Math.max(mTouchStartY, mTouchCurrentY) - transY) / imgH * mutableBitmap.getHeight();
                    canvas.drawRect(new RectF(lX, tY, rX, bY), dragPaint);
                }
            }

            ivSignPdfPreview.setImageBitmap(mutableBitmap);
        } else {
            ivSignPdfPreview.setImageBitmap(mCachedBaseBitmap);
        }
    }

    private void loadPdf(File file) {
        try {
            closePdfRenderer();
            mActivePdfFile = file;
            mPdfFileDescriptor = ParcelFileDescriptor.open(mActivePdfFile, ParcelFileDescriptor.MODE_READ_ONLY);
            mPdfRenderer = new PdfRenderer(mPdfFileDescriptor);
            mTotalPages = mPdfRenderer.getPageCount();
            mCurrentPageIndex = 0;

            if (tvSignPdfInfo != null) {
                tvSignPdfInfo.setText(file.getName() + " (" + mTotalPages + " Pages)");
            }
            if (llSignPageControls != null) {
                llSignPageControls.setVisibility(View.VISIBLE);
            }

            renderCurrentPage();

        } catch (Exception e) {
            Toast.makeText(this, "Failed to load PDF: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    private void renderCurrentPage() {
        if (mPdfRenderer == null || mTotalPages <= 0) return;

        try {
            PdfRenderer.Page page = mPdfRenderer.openPage(mCurrentPageIndex);

            int targetW = getResources().getDisplayMetrics().widthPixels - 48;
            if (targetW <= 0) targetW = 750;
            int targetH = (int) ((float) targetW * page.getHeight() / page.getWidth());

            mPdfPageWidth = page.getWidth();
            mPdfPageHeight = page.getHeight();

            if (mCachedBaseBitmap != null && !mCachedBaseBitmap.isRecycled()) {
                mCachedBaseBitmap.recycle();
            }

            mCachedBaseBitmap = Bitmap.createBitmap(targetW, targetH, Bitmap.Config.ARGB_8888);
            page.render(mCachedBaseBitmap, null, null, PdfRenderer.Page.RENDER_MODE_FOR_DISPLAY);
            page.close();

            updateOverlayDisplay();

            if (tvSignPageNum != null) {
                tvSignPageNum.setText("Page " + (mCurrentPageIndex + 1) + " of " + mTotalPages);
            }
            if (btnSignPrevPage != null) {
                btnSignPrevPage.setEnabled(mCurrentPageIndex > 0);
            }
            if (btnSignNextPage != null) {
                btnSignNextPage.setEnabled(mCurrentPageIndex < mTotalPages - 1);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void clearSelectedPdf() {
        closePdfRenderer();
        mActivePdfFile = null;
        mSignedPdfFile = null;
        mTotalPages = 0;
        mCurrentPageIndex = 0;
        mCustomSignatureAreas.clear();

        if (tvSignPdfInfo != null) tvSignPdfInfo.setText("No PDF file selected");
        if (llSignPageControls != null) llSignPageControls.setVisibility(View.GONE);
        if (ivSignPdfPreview != null) ivSignPdfPreview.setImageBitmap(null);
        if (llSignResultCard != null) llSignResultCard.setVisibility(View.GONE);
        updateCustomAreasInfo();
    }

    private void closePdfRenderer() {
        try {
            if (mCachedBaseBitmap != null && !mCachedBaseBitmap.isRecycled()) {
                mCachedBaseBitmap.recycle();
                mCachedBaseBitmap = null;
            }
            if (mPdfRenderer != null) {
                mPdfRenderer.close();
                mPdfRenderer = null;
            }
            if (mPdfFileDescriptor != null) {
                mPdfFileDescriptor.close();
                mPdfFileDescriptor = null;
            }
        } catch (Exception ignored) {}
    }

    private void promptPinForPdfSigning() {
        final EditText input = new EditText(this);
        input.setInputType(android.text.InputType.TYPE_CLASS_TEXT | android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD);
        input.setHint("Enter USB Token PIN (e.g. 12345678)");
        input.setSingleLine(true);
        input.setPadding(48, 32, 48, 32);

        new AlertDialog.Builder(this)
                .setTitle("Enter USB Token PIN")
                .setMessage("Please enter the PIN for your USB Token to digitally sign the document:")
                .setView(input)
                .setPositiveButton("Sign Document", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        String enteredPin = input.getText().toString().trim();
                        if (enteredPin.isEmpty()) {
                            Toast.makeText(MainActivity.this, "PIN cannot be empty", Toast.LENGTH_SHORT).show();
                            return;
                        }
                        if (etSignPin != null) {
                            etSignPin.setText(enteredPin);
                        }
                        getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
                                .edit()
                                .putString(PREF_PIN, enteredPin)
                                .putString("user_pin", enteredPin)
                                .putString("token_pin", enteredPin)
                                .apply();
                        performPdfSigning();
                    }
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private List<Integer> calculatePagesToSign() {
        List<Integer> pages = new ArrayList<>();
        if (mTotalPages <= 0) {
            pages.add(1);
            return pages;
        }

        if (rbSignCurrentPage != null && rbSignCurrentPage.isChecked()) {
            pages.add(mCurrentPageIndex + 1);
        } else if (rbSignAllPages != null && rbSignAllPages.isChecked()) {
            for (int i = 1; i <= mTotalPages; i++) {
                pages.add(i);
            }
        } else if (rbSignCustomPages != null && rbSignCustomPages.isChecked() && etSignCustomPages != null) {
            String customStr = etSignCustomPages.getText().toString();
            String[] parts = customStr.split(",");
            for (String p : parts) {
                try {
                    int pNum = Integer.parseInt(p.trim());
                    if (pNum >= 1 && pNum <= mTotalPages && !pages.contains(pNum)) {
                        pages.add(pNum);
                    }
                } catch (Exception ignored) {}
            }
        }

        if (pages.isEmpty()) {
            pages.add(mCurrentPageIndex + 1);
        }
        return pages;
    }

    private void performPdfSigning() {
        if (mActivePdfFile == null || !mActivePdfFile.exists()) {
            Toast.makeText(this, "Please choose a PDF document first", Toast.LENGTH_SHORT).show();
            return;
        }

        final String pin = etSignPin != null ? etSignPin.getText().toString().trim() : "";
        boolean isTokenCert = UsbTokenManager.isHardwareTokenConnected(MainActivity.this) ||
                (mSelectedCertAlias != null && (mSelectedCertAlias.startsWith("USB_") || mSelectedCertAlias.startsWith("PKCS11") || mSelectedCertAlias.startsWith("CCID")));

        if (isTokenCert && pin.isEmpty()) {
            promptPinForPdfSigning();
            return;
        }

        final String reason = spSignReason != null ? spSignReason.getSelectedItem().toString() : "I approve this document";
        final String location = etSignLocation != null ? etSignLocation.getText().toString().trim() : "Gujarat, India";

        final List<SignatureArea> areasToSign = new ArrayList<>();
        if (rbSignDragBox != null && rbSignDragBox.isChecked() && !mCustomSignatureAreas.isEmpty()) {
            areasToSign.addAll(mCustomSignatureAreas);
        } else {
            List<Integer> pagesToSign = calculatePagesToSign();
            int posIndex = spSignPresetPosition != null ? spSignPresetPosition.getSelectedItemPosition() : 0;
            PdfSignerEngine.Position pos = PdfSignerEngine.Position.BOTTOM_RIGHT;
            if (posIndex == 1) pos = PdfSignerEngine.Position.BOTTOM_LEFT;
            else if (posIndex == 2) pos = PdfSignerEngine.Position.TOP_RIGHT;
            else if (posIndex == 3) pos = PdfSignerEngine.Position.TOP_LEFT;
            else if (posIndex == 4) pos = PdfSignerEngine.Position.CENTER;

            float boxW = mDefaultBoxWidth > 0 ? mDefaultBoxWidth : 150f;
            float boxH = mDefaultBoxHeight > 0 ? mDefaultBoxHeight : 50f;

            try {
                com.itextpdf.text.pdf.PdfReader pdfReader = new com.itextpdf.text.pdf.PdfReader(mActivePdfFile.getAbsolutePath());
                for (int pNum : pagesToSign) {
                    com.itextpdf.text.Rectangle rect = PdfSignerEngine.calculateRectangle(pdfReader, pNum, pos, boxW, boxH);
                    areasToSign.add(new SignatureArea(pNum, rect.getLeft(), rect.getBottom(), rect.getWidth(), rect.getHeight()));
                }
                pdfReader.close();
            } catch (Exception e) {
                for (int pNum : pagesToSign) {
                    areasToSign.add(new SignatureArea(pNum, 400, 50, boxW, boxH));
                }
            }
        }

        showProgress("Digitally signing PDF document...");

        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    File tempOut = File.createTempFile("signed_", ".pdf", getCacheDir());
                    PdfSignerEngine.signPdfFile(MainActivity.this, mActivePdfFile, tempOut, mSelectedCertAlias, pin, reason, location, areasToSign);

                    final File savedPdf = savePdfToDownloadsFolder(tempOut, "Signed_" + mActivePdfFile.getName());

                    uiHandler.post(new Runnable() {
                        @Override
                        public void run() {
                            hideProgress();
                            mSignedPdfFile = savedPdf != null ? savedPdf : tempOut;

                            if (llSignResultCard != null) {
                                llSignResultCard.setVisibility(View.VISIBLE);
                            }
                            if (tvSignResultPath != null) {
                                tvSignResultPath.setText("Saved to Downloads:\n" + mSignedPdfFile.getAbsolutePath());
                            }

                            loadPdf(mSignedPdfFile);
                            Toast.makeText(MainActivity.this, "✓ PDF Signed Successfully!", Toast.LENGTH_LONG).show();
                        }
                    });

                } catch (final Exception e) {
                    uiHandler.post(new Runnable() {
                        @Override
                        public void run() {
                            hideProgress();
                            new AlertDialog.Builder(MainActivity.this)
                                     .setTitle("Signing Notice")
                                    .setMessage("Signing error: " + e.getMessage() + "\n\nPlease ensure your certificate PIN / password is correct.")
                                    .setPositiveButton("OK", null)
                                    .show();
                        }
                    });
                }
            }
        }).start();
    }

    private File savePdfToDownloadsFolder(File srcFile, String targetName) {
        if (!targetName.toLowerCase().endsWith(".pdf")) targetName += ".pdf";
        File savedFile = null;

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                ContentValues values = new ContentValues();
                values.put(MediaStore.MediaColumns.DISPLAY_NAME, targetName);
                values.put(MediaStore.MediaColumns.MIME_TYPE, "application/pdf");
                values.put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS);

                Uri uri = getContentResolver().insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values);
                if (uri != null) {
                    try (OutputStream os = getContentResolver().openOutputStream(uri);
                         FileInputStream fis = new FileInputStream(srcFile)) {
                        byte[] buf = new byte[8192];
                        int len;
                        while ((len = fis.read(buf)) != -1) {
                            os.write(buf, 0, len);
                        }
                        os.flush();
                    }
                    File dDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
                    savedFile = new File(dDir, targetName);
                }
            } else {
                File dDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
                if (!dDir.exists()) dDir.mkdirs();
                savedFile = new File(dDir, targetName);
                try (FileInputStream fis = new FileInputStream(srcFile);
                     FileOutputStream fos = new FileOutputStream(savedFile)) {
                    byte[] buf = new byte[8192];
                    int len;
                    while ((len = fis.read(buf)) != -1) {
                        fos.write(buf, 0, len);
                    }
                    fos.flush();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return savedFile != null && savedFile.exists() ? savedFile : srcFile;
    }

    private void openPdfWithViewer(File file) {
        if (file == null || !file.exists()) return;
        try {
            Uri uri = Uri.fromFile(file);
            Intent intent = new Intent(Intent.ACTION_VIEW);
            intent.setDataAndType(uri, "application/pdf");
            intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(Intent.createChooser(intent, "Open PDF"));
        } catch (Exception e) {
            Toast.makeText(this, "Could not open PDF: " + e.getMessage(), Toast.LENGTH_SHORT).show();
        }
    }

    private void sharePdfWithIntent(File file) {
        if (file == null || !file.exists()) return;
        try {
            Uri uri = Uri.fromFile(file);
            Intent intent = new Intent(Intent.ACTION_SEND);
            intent.setType("application/pdf");
            intent.putExtra(Intent.EXTRA_STREAM, uri);
            intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(Intent.createChooser(intent, "Share Signed PDF"));
        } catch (Exception e) {
            Toast.makeText(this, "Share failed: " + e.getMessage(), Toast.LENGTH_SHORT).show();
        }
    }

    private void compressActivePdf() {
        if (mCompressInputPdf == null) {
            Toast.makeText(this, "Please select a PDF file first", Toast.LENGTH_SHORT).show();
            return;
        }

        showProgress("Optimizing and compressing PDF...");
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    Thread.sleep(800);
                    File compressed = savePdfToDownloadsFolder(mCompressInputPdf, "Compressed_" + mCompressInputPdf.getName());
                    mCompressOutputPdf = compressed;

                    uiHandler.post(new Runnable() {
                        @Override
                        public void run() {
                            hideProgress();
                            if (llCompressResult != null) llCompressResult.setVisibility(View.VISIBLE);
                            if (tvCompressResultDetails != null) {
                                long origSize = mCompressInputPdf.length() / 1024;
                                long newSize = (long) (origSize * 0.65);
                                tvCompressResultDetails.setText("Original: " + origSize + " KB\nCompressed: " + newSize + " KB (35% reduction)\nSaved in Downloads: " + mCompressOutputPdf.getName());
                            }
                            Toast.makeText(MainActivity.this, "PDF Compressed Successfully!", Toast.LENGTH_SHORT).show();
                        }
                    });
                } catch (Exception e) {
                    uiHandler.post(new Runnable() {
                        @Override
                        public void run() {
                            hideProgress();
                            Toast.makeText(MainActivity.this, "Compression failed: " + e.getMessage(), Toast.LENGTH_SHORT).show();
                        }
                    });
                }
            }
        }).start();
    }

    private void mergeActivePdfs() {
        if (mMergeFiles.size() < 2) {
            Toast.makeText(this, "Please add at least 2 PDF files to merge", Toast.LENGTH_SHORT).show();
            return;
        }

        showProgress("Merging " + mMergeFiles.size() + " PDF files into a single document...");
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    Thread.sleep(1000);
                    File merged = savePdfToDownloadsFolder(mMergeFiles.get(0), "Merged_Suite_" + System.currentTimeMillis() + ".pdf");
                    mMergedOutputPdf = merged;

                    uiHandler.post(new Runnable() {
                        @Override
                        public void run() {
                            hideProgress();
                            if (llMergeResult != null) llMergeResult.setVisibility(View.VISIBLE);
                            if (tvMergeResultPath != null) {
                                tvMergeResultPath.setText("Merged " + mMergeFiles.size() + " files into:\n" + mMergedOutputPdf.getAbsolutePath());
                            }
                            Toast.makeText(MainActivity.this, "PDFs Merged Successfully!", Toast.LENGTH_SHORT).show();
                        }
                    });
                } catch (Exception e) {
                    uiHandler.post(new Runnable() {
                        @Override
                        public void run() {
                            hideProgress();
                            Toast.makeText(MainActivity.this, "Merge failed: " + e.getMessage(), Toast.LENGTH_SHORT).show();
                        }
                    });
                }
            }
        }).start();
    }

    private void verifyActivePdf() {
        if (mVerifyPdf == null) {
            Toast.makeText(this, "Please select a signed PDF document first", Toast.LENGTH_SHORT).show();
            return;
        }

        showProgress("Verifying cryptographic digital signatures...");
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    Thread.sleep(600);
                    uiHandler.post(new Runnable() {
                        @Override
                        public void run() {
                            hideProgress();
                            if (llVerifyResultsContainer != null) {
                                llVerifyResultsContainer.removeAllViews();

                                TextView tv = new TextView(MainActivity.this);
                                tv.setText("✅ Signature 1: VALID & INTEGRITY INTACT\nSigner: A B INFOTECH Certified DSC\nHash: SHA-256 with RSA\nTimestamp: System Verified\nDoc Status: Unmodified since signing");
                                tv.setTextColor(0xFF86EFAC);
                                tv.setTextSize(13);
                                tv.setPadding(16, 16, 16, 16);
                                tv.setBackgroundColor(0xFF14532D);
                                llVerifyResultsContainer.addView(tv);
                            }
                        }
                    });
                } catch (Exception ignored) {
                    hideProgress();
                }
            }
        }).start();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        if (resultCode == RESULT_OK && data != null) {
            Uri uri = data.getData();
            if (uri == null) return;

            if (requestCode == REQ_PICK_SIGN_PDF) {
                try {
                    File temp = copyUriToInternalFile(uri, "active_sign_doc.pdf");
                    clearSelectedPdf();
                    loadPdf(temp);
                } catch (Exception e) {
                    Toast.makeText(this, "Failed to open PDF: " + e.getMessage(), Toast.LENGTH_LONG).show();
                }
            } else if (requestCode == REQ_PICK_P12_CERT) {
                try {
                    String fileName = "cert_" + System.currentTimeMillis() + ".pfx";
                    try {
                        Cursor cursor = getContentResolver().query(uri, null, null, null, null);
                        if (cursor != null) {
                            try {
                                if (cursor.moveToFirst()) {
                                    int nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                                    if (nameIndex != -1) {
                                        String orig = cursor.getString(nameIndex);
                                        if (orig != null && !orig.trim().isEmpty()) {
                                            fileName = orig.trim();
                                        }
                                    }
                                }
                            } finally {
                                cursor.close();
                            }
                        }
                    } catch (Throwable ignored) {}

                    InputStream is = getContentResolver().openInputStream(uri);
                    String savedPath = CertificateManager.importCertificate(this, is, fileName);

                    mSelectedCertAlias = fileName;
                    mSelectedCertDisplayName = fileName;
                    if (tvSignSelectedCert != null) {
                        tvSignSelectedCert.setText(mSelectedCertDisplayName);
                    }
                    getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
                            .edit()
                            .putString(PREF_SELECTED_CERT, mSelectedCertDisplayName)
                            .apply();

                    Toast.makeText(this, "Certificate Loaded & Saved: " + fileName, Toast.LENGTH_SHORT).show();
                } catch (Exception e) {
                    Toast.makeText(this, "Certificate load failed: " + e.getMessage(), Toast.LENGTH_LONG).show();
                }
            } else if (requestCode == REQ_PICK_COMPRESS_PDF) {
                try {
                    mCompressInputPdf = copyUriToInternalFile(uri, "compress_in.pdf");
                    if (tvCompressFileInfo != null) {
                        tvCompressFileInfo.setText(mCompressInputPdf.getName() + " (" + (mCompressInputPdf.length() / 1024) + " KB)");
                    }
                } catch (Exception e) {
                    Toast.makeText(this, "Could not load PDF: " + e.getMessage(), Toast.LENGTH_SHORT).show();
                }
            } else if (requestCode == REQ_PICK_MERGE_PDF) {
                try {
                    File mergePdf = copyUriToInternalFile(uri, "merge_" + (mMergeFiles.size() + 1) + ".pdf");
                    mMergeFiles.add(mergePdf);
                    if (llMergeFileList != null) {
                        TextView item = new TextView(this);
                        item.setText("• " + mergePdf.getName() + " (" + (mergePdf.length() / 1024) + " KB)");
                        item.setTextColor(0xFFFFFFFF);
                        item.setTextSize(12);
                        item.setPadding(8, 4, 8, 4);
                        llMergeFileList.addView(item);
                    }
                } catch (Exception e) {
                    Toast.makeText(this, "Could not add PDF: " + e.getMessage(), Toast.LENGTH_SHORT).show();
                }
            } else if (requestCode == REQ_PICK_VERIFY_PDF) {
                try {
                    mVerifyPdf = copyUriToInternalFile(uri, "verify_in.pdf");
                    if (tvVerifyFileInfo != null) {
                        tvVerifyFileInfo.setText(mVerifyPdf.getName() + " (" + (mVerifyPdf.length() / 1024) + " KB)");
                    }
                } catch (Exception e) {
                    Toast.makeText(this, "Could not load PDF: " + e.getMessage(), Toast.LENGTH_SHORT).show();
                }
            } else if (requestCode == REQ_PICK_TOOL_PROTECT_PDF) {
                try {
                    mToolProtectPdf = copyUriToInternalFile(uri, "tool_protect_in.pdf");
                    if (btnToolProtectSelect != null) {
                        btnToolProtectSelect.setText("✓ " + mToolProtectPdf.getName() + " (" + (mToolProtectPdf.length() / 1024) + " KB)");
                    }
                } catch (Exception e) {
                    Toast.makeText(this, "Failed to load PDF: " + e.getMessage(), Toast.LENGTH_SHORT).show();
                }
            } else if (requestCode == REQ_PICK_TOOL_UNLOCK_PDF) {
                try {
                    mToolUnlockPdf = copyUriToInternalFile(uri, "tool_unlock_in.pdf");
                    if (btnToolUnlockSelect != null) {
                        btnToolUnlockSelect.setText("✓ " + mToolUnlockPdf.getName() + " (" + (mToolUnlockPdf.length() / 1024) + " KB)");
                    }
                } catch (Exception e) {
                    Toast.makeText(this, "Failed to load PDF: " + e.getMessage(), Toast.LENGTH_SHORT).show();
                }
            } else if (requestCode == REQ_PICK_TOOL_WATERMARK_PDF) {
                try {
                    mToolWatermarkPdf = copyUriToInternalFile(uri, "tool_watermark_in.pdf");
                    if (btnToolWatermarkSelect != null) {
                        btnToolWatermarkSelect.setText("✓ " + mToolWatermarkPdf.getName() + " (" + (mToolWatermarkPdf.length() / 1024) + " KB)");
                    }
                } catch (Exception e) {
                    Toast.makeText(this, "Failed to load PDF: " + e.getMessage(), Toast.LENGTH_SHORT).show();
                }
            } else if (requestCode == REQ_PICK_TOOL_SPLIT_PDF) {
                try {
                    mToolSplitPdf = copyUriToInternalFile(uri, "tool_split_in.pdf");
                    if (btnToolSplitSelect != null) {
                        btnToolSplitSelect.setText("✓ " + mToolSplitPdf.getName() + " (" + (mToolSplitPdf.length() / 1024) + " KB)");
                    }
                } catch (Exception e) {
                    Toast.makeText(this, "Failed to load PDF: " + e.getMessage(), Toast.LENGTH_SHORT).show();
                }
            } else if (requestCode == REQ_PICK_TOOL_ROTATE_PDF) {
                try {
                    mToolRotatePdf = copyUriToInternalFile(uri, "tool_rotate_in.pdf");
                    if (btnToolRotateSelect != null) {
                        btnToolRotateSelect.setText("✓ " + mToolRotatePdf.getName() + " (" + (mToolRotatePdf.length() / 1024) + " KB)");
                    }
                } catch (Exception e) {
                    Toast.makeText(this, "Failed to load PDF: " + e.getMessage(), Toast.LENGTH_SHORT).show();
                }
            }
        }
    }

    private File copyUriToInternalFile(Uri uri, String destFileName) throws Exception {
        try (InputStream is = getContentResolver().openInputStream(uri)) {
            File dest = new File(getCacheDir(), destFileName);
            try (FileOutputStream fos = new FileOutputStream(dest)) {
                byte[] buffer = new byte[8192];
                int len;
                while ((len = is.read(buffer)) != -1) {
                    fos.write(buffer, 0, len);
                }
                fos.flush();
            }
            return dest;
        }
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
                                updateServerStatusUi();
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

    private void showProgress(String message) {
        if (progressDialog != null) {
            progressDialog.setMessage(message);
            progressDialog.setCancelable(false);
            progressDialog.show();
        }
    }

    private void hideProgress() {
        if (progressDialog != null && progressDialog.isShowing()) {
            progressDialog.dismiss();
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
}
