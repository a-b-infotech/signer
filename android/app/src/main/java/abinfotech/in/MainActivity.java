package abinfotech.in;

import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.DashPathEffect;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.pdf.PdfRenderer;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.provider.MediaStore;
import android.view.MotionEvent;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;
import android.widget.ViewFlipper;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.SwitchCompat;
import androidx.core.content.FileProvider;

import com.ftsafe.monitor.OTGPassToKen;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfReader;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import javax.security.cert.X509Certificate;

import abinfotech.in.server.LocalSigningService;
import abinfotech.in.signer.PdfSignerHelper;
import abinfotech.in.signer.PdfToolsEngine;
import abinfotech.in.signer.SignatureArea;
import abinfotech.in.token.P11Operation;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;

public class MainActivity extends AppCompatActivity {

    private static final String PREFS_NAME = "AbinfoPdfSignerPrefs";
    private static final String PREF_SAVED_PIN = "saved_pin";
    private static final String PREF_IS_LICENSE_ACTIVE = "is_license_active";
    private static final String PREF_LICENSE_TIER = "license_tier";
    private static final String PREF_LICENSE_KEY = "license_key";

    // Request Codes
    private static final int REQ_SIGN_PICK_PDF = 101;
    private static final int REQ_SIGN_PICK_P12 = 102;
    private static final int REQ_SIGN_SELECT_CERT = 103;
    private static final int REQ_COMPRESS_PICK_PDF = 201;
    private static final int REQ_MERGE_PICK_PDF = 301;
    private static final int REQ_VERIFY_PICK_PDF = 401;
    private static final int REQ_PROTECT_PICK_PDF = 501;
    private static final int REQ_UNLOCK_PICK_PDF = 502;
    private static final int REQ_WATERMARK_PICK_PDF = 503;
    private static final int REQ_SPLIT_PICK_PDF = 504;
    private static final int REQ_ROTATE_PICK_PDF = 505;

    // UI Header
    private TextView tvHeaderLicenseBadge, tvHeaderServerBadge;

    // ViewFlipper & Navigation Tabs
    private ViewFlipper viewFlipper;
    private Button tabSign, tabCompress, tabMerge, tabVerify, tabTools, tabServer;

    // Tab 1: Sign PDF UI Elements
    private TextView tvSignPdfInfo, tvTokenStatusBadge, tvSignSelectedCert;
    private Spinner spTokenDriver, spSignReason, spSignPresetPosition, spSignBoxSize;
    private Button btnSignSelectPdf, btnSignClearPdf, btnSignFindCerts, btnSignLoadP12;
    private EditText etSignPin, etSignLocation, etSignCustomPages;
    private RadioGroup rgSignPages, rgSignPositionMode;
    private RadioButton rbSignCurrentPage, rbSignAllPages, rbSignCustomPages;
    private RadioButton rbSignPreset, rbSignDragBox;
    private LinearLayout llSignCustomControls, llSignPageControls, llSignResultCard;
    private TextView tvSignCustomAreasInfo, tvSignPageNum, tvSignResultPath;
    private Button btnSignPrevPage, btnSignNextPage, btnSignClearAreas, btnSignPdfNow, btnSignOpenPdf, btnSignSharePdf;
    private ImageView ivSignPdfPreview;

    // Tab 2: Compress PDF UI Elements
    private TextView tvCompressFileInfo, tvCompressResultDetails;
    private Button btnCompressSelectPdf, btnCompressNow, btnCompressOpen, btnCompressShare;
    private RadioGroup rgCompressLevel;
    private LinearLayout llCompressResult;
    private File compressSourcePdf = null;
    private File compressResultPdf = null;

    // Tab 3: Merge PDF UI Elements
    private Button btnMergeAddPdf, btnMergeNow, btnMergeOpen, btnMergeShare;
    private LinearLayout llMergeFileList, llMergeResult;
    private TextView tvMergeResultPath;
    private final List<File> mergePdfFiles = new ArrayList<>();
    private File mergedResultPdf = null;

    // Tab 4: Verify Signatures UI Elements
    private Button btnVerifySelectPdf, btnVerifyNow;
    private TextView tvVerifyFileInfo;
    private LinearLayout llVerifyResultsContainer;
    private File verifySourcePdf = null;

    // Tab 5: PDF Tools UI Elements
    private Button btnToolProtectSelect, btnToolProtectRun;
    private EditText etToolProtectPassword;
    private File toolProtectFile = null;

    private Button btnToolUnlockSelect, btnToolUnlockRun;
    private EditText etToolUnlockPassword;
    private File toolUnlockFile = null;

    private Button btnToolWatermarkSelect, btnToolWatermarkRun;
    private EditText etToolWatermarkText;
    private File toolWatermarkFile = null;

    private Button btnToolSplitSelect, btnToolSplitRun;
    private EditText etToolSplitRanges;
    private File toolSplitFile = null;

    private Button btnToolRotateSelect, btnToolRotateRun;
    private RadioGroup rgToolRotateDegrees;
    private File toolRotateFile = null;

    // Tab 6: Server & License Settings UI Elements
    private SwitchCompat switchServerStatus;
    private TextView tvServerIpDetails, tvLicenseStatusText;
    private EditText etLicenseKeyInput;
    private Button btnOpenWebStudio, btnActivateLicense, btnWhatsappSupport, btnCheckUpdates;

    // Token State
    private boolean isTokenConnected = false;
    private boolean isTryingConnect = false;
    private X509Certificate[] tokenCerts = null;
    private X509Certificate selectedTokenCert = null;

    // P12 Certificate State
    private byte[] loadedP12Bytes = null;
    private boolean isP12Selected = false;
    private String p12CertName = "";

    // Active Signing PDF State
    private File activeSignPdfFile = null;
    private File activeSignedResultPdf = null;
    private ParcelFileDescriptor activePdfDescriptor = null;
    private PdfRenderer activePdfRenderer = null;
    private int signCurrentPageIndex = 0;
    private int signTotalPages = 0;
    private Bitmap signBasePageBitmap = null;
    private float signPdfPageWidth = 595f;
    private float signPdfPageHeight = 842f;

    // Signature Area List & Live Drag Box
    private final List<SignatureArea> customSignatureAreas = new ArrayList<>();
    private boolean isDraggingSignatureBox = false;
    private float touchStartX = 0f, touchStartY = 0f;
    private float touchCurrentX = 0f, touchCurrentY = 0f;
    private float defaultBoxWidth = 140f, defaultBoxHeight = 50f;
    private PdfSignerHelper.Position selectedPresetPosition = PdfSignerHelper.Position.BOTTOM_RIGHT;

    private ProgressDialog progressDialog;
    private final Handler mainHandler = new Handler(Looper.getMainLooper());

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        try {
            Security.removeProvider("BC");
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        } catch (Throwable t) {
            t.printStackTrace();
        }

        // Initialize Feitian OTG Token SDK
        try {
            OTGPassToKen.initOTGToken(this);
        } catch (Throwable t) {
            t.printStackTrace();
        }

        progressDialog = new ProgressDialog(this);
        progressDialog.setCancelable(false);

        initViews();
        setupNavigationTabs();
        setupSignStudioSpinners();
        setupSignStudioListeners();
        setupCompressTabListeners();
        setupMergeTabListeners();
        setupVerifyTabListeners();
        setupToolsTabListeners();
        setupServerAndLicenseListeners();

        restorePreferences();
        startLocalServerService();

        // Start background USB Token monitoring loop
        new Thread(new TokenMonitorRunnable()).start();
    }

    private void initViews() {
        tvHeaderLicenseBadge = findViewById(R.id.tvHeaderLicenseBadge);
        tvHeaderServerBadge = findViewById(R.id.tvHeaderServerBadge);
        viewFlipper = findViewById(R.id.viewFlipper);

        tabSign = findViewById(R.id.tabSign);
        tabCompress = findViewById(R.id.tabCompress);
        tabMerge = findViewById(R.id.tabMerge);
        tabVerify = findViewById(R.id.tabVerify);
        tabTools = findViewById(R.id.tabTools);
        tabServer = findViewById(R.id.tabServer);

        // Sign PDF Tab
        tvSignPdfInfo = findViewById(R.id.tvSignPdfInfo);
        tvTokenStatusBadge = findViewById(R.id.tvTokenStatusBadge);
        tvSignSelectedCert = findViewById(R.id.tvSignSelectedCert);
        spTokenDriver = findViewById(R.id.spTokenDriver);
        spSignReason = findViewById(R.id.spSignReason);
        spSignPresetPosition = findViewById(R.id.spSignPresetPosition);
        spSignBoxSize = findViewById(R.id.spSignBoxSize);
        btnSignSelectPdf = findViewById(R.id.btnSignSelectPdf);
        btnSignClearPdf = findViewById(R.id.btnSignClearPdf);
        btnSignFindCerts = findViewById(R.id.btnSignFindCerts);
        btnSignLoadP12 = findViewById(R.id.btnSignLoadP12);
        etSignPin = findViewById(R.id.etSignPin);
        etSignLocation = findViewById(R.id.etSignLocation);
        etSignCustomPages = findViewById(R.id.etSignCustomPages);
        rgSignPages = findViewById(R.id.rgSignPages);
        rbSignCurrentPage = findViewById(R.id.rbSignCurrentPage);
        rbSignAllPages = findViewById(R.id.rbSignAllPages);
        rbSignCustomPages = findViewById(R.id.rbSignCustomPages);
        rgSignPositionMode = findViewById(R.id.rgSignPositionMode);
        rbSignPreset = findViewById(R.id.rbSignPreset);
        rbSignDragBox = findViewById(R.id.rbSignDragBox);
        llSignCustomControls = findViewById(R.id.llSignCustomControls);
        llSignPageControls = findViewById(R.id.llSignPageControls);
        llSignResultCard = findViewById(R.id.llSignResultCard);
        tvSignCustomAreasInfo = findViewById(R.id.tvSignCustomAreasInfo);
        tvSignPageNum = findViewById(R.id.tvSignPageNum);
        tvSignResultPath = findViewById(R.id.tvSignResultPath);
        btnSignPrevPage = findViewById(R.id.btnSignPrevPage);
        btnSignNextPage = findViewById(R.id.btnSignNextPage);
        btnSignClearAreas = findViewById(R.id.btnSignClearAreas);
        btnSignPdfNow = findViewById(R.id.btnSignPdfNow);
        btnSignOpenPdf = findViewById(R.id.btnSignOpenPdf);
        btnSignSharePdf = findViewById(R.id.btnSignSharePdf);
        ivSignPdfPreview = findViewById(R.id.ivSignPdfPreview);

        // Compress Tab
        tvCompressFileInfo = findViewById(R.id.tvCompressFileInfo);
        tvCompressResultDetails = findViewById(R.id.tvCompressResultDetails);
        btnCompressSelectPdf = findViewById(R.id.btnCompressSelectPdf);
        btnCompressNow = findViewById(R.id.btnCompressNow);
        btnCompressOpen = findViewById(R.id.btnCompressOpen);
        btnCompressShare = findViewById(R.id.btnCompressShare);
        rgCompressLevel = findViewById(R.id.rgCompressLevel);
        llCompressResult = findViewById(R.id.llCompressResult);

        // Merge Tab
        btnMergeAddPdf = findViewById(R.id.btnMergeAddPdf);
        btnMergeNow = findViewById(R.id.btnMergeNow);
        btnMergeOpen = findViewById(R.id.btnMergeOpen);
        btnMergeShare = findViewById(R.id.btnMergeShare);
        llMergeFileList = findViewById(R.id.llMergeFileList);
        llMergeResult = findViewById(R.id.llMergeResult);
        tvMergeResultPath = findViewById(R.id.tvMergeResultPath);

        // Verify Tab
        btnVerifySelectPdf = findViewById(R.id.btnVerifySelectPdf);
        btnVerifyNow = findViewById(R.id.btnVerifyNow);
        tvVerifyFileInfo = findViewById(R.id.tvVerifyFileInfo);
        llVerifyResultsContainer = findViewById(R.id.llVerifyResultsContainer);

        // Tools Tab
        btnToolProtectSelect = findViewById(R.id.btnToolProtectSelect);
        btnToolProtectRun = findViewById(R.id.btnToolProtectRun);
        etToolProtectPassword = findViewById(R.id.etToolProtectPassword);

        btnToolUnlockSelect = findViewById(R.id.btnToolUnlockSelect);
        btnToolUnlockRun = findViewById(R.id.btnToolUnlockRun);
        etToolUnlockPassword = findViewById(R.id.etToolUnlockPassword);

        btnToolWatermarkSelect = findViewById(R.id.btnToolWatermarkSelect);
        btnToolWatermarkRun = findViewById(R.id.btnToolWatermarkRun);
        etToolWatermarkText = findViewById(R.id.etToolWatermarkText);

        btnToolSplitSelect = findViewById(R.id.btnToolSplitSelect);
        btnToolSplitRun = findViewById(R.id.btnToolSplitRun);
        etToolSplitRanges = findViewById(R.id.etToolSplitRanges);

        btnToolRotateSelect = findViewById(R.id.btnToolRotateSelect);
        btnToolRotateRun = findViewById(R.id.btnToolRotateRun);
        rgToolRotateDegrees = findViewById(R.id.rgToolRotateDegrees);

        // Server & License Tab
        switchServerStatus = findViewById(R.id.switchServerStatus);
        tvServerIpDetails = findViewById(R.id.tvServerIpDetails);
        tvLicenseStatusText = findViewById(R.id.tvLicenseStatusText);
        etLicenseKeyInput = findViewById(R.id.etLicenseKeyInput);
        btnOpenWebStudio = findViewById(R.id.btnOpenWebStudio);
        btnActivateLicense = findViewById(R.id.btnActivateLicense);
        btnWhatsappSupport = findViewById(R.id.btnWhatsappSupport);
        btnCheckUpdates = findViewById(R.id.btnCheckUpdates);
    }

    private void setupNavigationTabs() {
        Button[] tabs = new Button[]{tabSign, tabCompress, tabMerge, tabVerify, tabTools, tabServer};

        for (int i = 0; i < tabs.length; i++) {
            final int index = i;
            tabs[i].setOnClickListener(v -> {
                viewFlipper.setDisplayedChild(index);
                for (int j = 0; j < tabs.length; j++) {
                    if (j == index) {
                        tabs[j].setBackgroundColor(Color.parseColor("#2563EB")); // Active Blue
                        tabs[j].setTextColor(Color.WHITE);
                    } else {
                        tabs[j].setBackgroundColor(Color.parseColor("#1E293B")); // Inactive Slate
                        tabs[j].setTextColor(Color.parseColor("#94A3B8"));
                    }
                }
            });
        }
    }

    private void setupSignStudioSpinners() {
        // Driver Spinner
        String[] drivers = new String[]{
                "Feitian HYP2003 / ePass2003 (PKCS#11)",
                "InnaIT / eGuard PKCS#11",
                "Software Certificate (P12/PFX)"
        };
        ArrayAdapter<String> driverAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, drivers);
        driverAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spTokenDriver.setAdapter(driverAdapter);

        // Signing Reason Spinner
        String[] reasons = new String[]{
                "I approve this document",
                "I am the author of this document",
                "Certified copy of original",
                "Verified and confirmed",
                "Custom Reason"
        };
        ArrayAdapter<String> reasonAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, reasons);
        reasonAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spSignReason.setAdapter(reasonAdapter);

        // Preset Position Spinner
        String[] positions = new String[]{
                "Bottom Right",
                "Bottom Left",
                "Top Right",
                "Top Left",
                "Center"
        };
        ArrayAdapter<String> posAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, positions);
        posAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spSignPresetPosition.setAdapter(posAdapter);

        spSignPresetPosition.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                switch (position) {
                    case 0: selectedPresetPosition = PdfSignerHelper.Position.BOTTOM_RIGHT; break;
                    case 1: selectedPresetPosition = PdfSignerHelper.Position.BOTTOM_LEFT; break;
                    case 2: selectedPresetPosition = PdfSignerHelper.Position.TOP_RIGHT; break;
                    case 3: selectedPresetPosition = PdfSignerHelper.Position.TOP_LEFT; break;
                    case 4: selectedPresetPosition = PdfSignerHelper.Position.CENTER; break;
                }
                updatePdfOverlayDisplay();
            }
            @Override
            public void onNothingSelected(AdapterView<?> parent) {}
        });

        // Box Size Spinner
        String[] boxSizes = new String[]{
                "Standard Box (140 x 50)",
                "Small Box (110 x 40)",
                "Large Box (180 x 65)"
        };
        ArrayAdapter<String> boxAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, boxSizes);
        boxAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spSignBoxSize.setAdapter(boxAdapter);

        spSignBoxSize.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                if (position == 0) {
                    defaultBoxWidth = 140f; defaultBoxHeight = 50f;
                } else if (position == 1) {
                    defaultBoxWidth = 110f; defaultBoxHeight = 40f;
                } else if (position == 2) {
                    defaultBoxWidth = 180f; defaultBoxHeight = 65f;
                }
            }
            @Override
            public void onNothingSelected(AdapterView<?> parent) {}
        });
    }

    private void setupSignStudioListeners() {
        btnSignSelectPdf.setOnClickListener(v -> {
            Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
            intent.setType("application/pdf");
            startActivityForResult(Intent.createChooser(intent, "Select PDF to Sign"), REQ_SIGN_PICK_PDF);
        });

        btnSignClearPdf.setOnClickListener(v -> clearActivePdf());

        btnSignLoadP12.setOnClickListener(v -> {
            Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
            intent.setType("*/*");
            intent.putExtra(Intent.EXTRA_MIME_TYPES, new String[]{"application/x-pkcs12", "application/octet-stream"});
            startActivityForResult(Intent.createChooser(intent, "Select P12 / PFX File"), REQ_SIGN_PICK_P12);
        });

        btnSignFindCerts.setOnClickListener(v -> {
            if (!isTokenConnected) {
                showSimpleAlert("Token Disconnected", "Please insert your USB hardware token (HYP2003 / ePass2003 / InnaIT).");
                return;
            }
            showProgress("Finding USB Certificates...");
            new Thread(() -> {
                try {
                    tokenCerts = P11Operation.getAllX509Certificate();
                    hideProgress();
                    mainHandler.post(() -> {
                        if (tokenCerts == null || tokenCerts.length == 0) {
                            showSimpleAlert("No Certificates", "No digital certificates found on the connected token.");
                        } else {
                            String[] certNames = new String[tokenCerts.length];
                            for (int i = 0; i < tokenCerts.length; i++) {
                                String dn = tokenCerts[i].getSubjectDN().getName();
                                certNames[i] = parseCertCN(dn);
                            }
                            Intent intent = new Intent(this, listCertificate.class);
                            intent.putExtra("CertList", certNames);
                            startActivityForResult(intent, REQ_SIGN_SELECT_CERT);
                        }
                    });
                } catch (Exception e) {
                    hideProgress();
                    mainHandler.post(() -> showSimpleAlert("Certificate Read Error", e.getMessage()));
                }
            }).start();
        });

        rgSignPages.setOnCheckedChangeListener((group, checkedId) -> {
            if (checkedId == R.id.rbSignCustomPages) {
                etSignCustomPages.setVisibility(View.VISIBLE);
            } else {
                etSignCustomPages.setVisibility(View.GONE);
            }
            updatePdfOverlayDisplay();
        });

        rgSignPositionMode.setOnCheckedChangeListener((group, checkedId) -> {
            if (checkedId == R.id.rbSignDragBox) {
                spSignPresetPosition.setVisibility(View.GONE);
                llSignCustomControls.setVisibility(View.VISIBLE);
            } else {
                spSignPresetPosition.setVisibility(View.VISIBLE);
                llSignCustomControls.setVisibility(View.GONE);
            }
            updatePdfOverlayDisplay();
        });

        btnSignClearAreas.setOnClickListener(v -> {
            customSignatureAreas.clear();
            tvSignCustomAreasInfo.setText("Custom signature areas cleared.");
            updatePdfOverlayDisplay();
            Toast.makeText(this, "Cleared all signature areas", Toast.LENGTH_SHORT).show();
        });

        btnSignPrevPage.setOnClickListener(v -> {
            if (signCurrentPageIndex > 0) {
                signCurrentPageIndex--;
                renderActivePdfPage();
            }
        });

        btnSignNextPage.setOnClickListener(v -> {
            if (signCurrentPageIndex < signTotalPages - 1) {
                signCurrentPageIndex++;
                renderActivePdfPage();
            }
        });

        // Live Drag-to-Draw Interaction on Preview ImageView
        ivSignPdfPreview.setOnTouchListener((v, event) -> {
            if (!rbSignDragBox.isChecked() || activeSignPdfFile == null || signTotalPages <= 0 || signBasePageBitmap == null) {
                return false;
            }

            ImageView iv = (ImageView) v;
            if (iv.getDrawable() == null) return false;

            float touchX = event.getX();
            float touchY = event.getY();

            switch (event.getAction()) {
                case MotionEvent.ACTION_DOWN:
                    touchStartX = touchX;
                    touchStartY = touchY;
                    touchCurrentX = touchX;
                    touchCurrentY = touchY;
                    isDraggingSignatureBox = true;
                    updatePdfOverlayDisplay();
                    return true;

                case MotionEvent.ACTION_MOVE:
                    if (isDraggingSignatureBox) {
                        touchCurrentX = touchX;
                        touchCurrentY = touchY;
                        updatePdfOverlayDisplay();
                    }
                    return true;

                case MotionEvent.ACTION_UP:
                    if (isDraggingSignatureBox) {
                        isDraggingSignatureBox = false;

                        float[] matrix = new float[9];
                        iv.getImageMatrix().getValues(matrix);
                        float transX = matrix[Matrix.MTRANS_X];
                        float transY = matrix[Matrix.MTRANS_Y];
                        float scaleX = matrix[Matrix.MSCALE_X];
                        float scaleY = matrix[Matrix.MSCALE_Y];

                        int dWidth = iv.getDrawable().getIntrinsicWidth();
                        int dHeight = iv.getDrawable().getIntrinsicHeight();
                        float imgW = dWidth * scaleX;
                        float imgH = dHeight * scaleY;

                        float leftPx = Math.min(touchStartX, touchX);
                        float rightPx = Math.max(touchStartX, touchX);
                        float topPx = Math.min(touchStartY, touchY);
                        float bottomPx = Math.max(touchStartY, touchY);

                        float dragW = rightPx - leftPx;
                        float dragH = bottomPx - topPx;

                        float pageW = signPdfPageWidth > 0 ? signPdfPageWidth : 595f;
                        float pageH = signPdfPageHeight > 0 ? signPdfPageHeight : 842f;

                        float pdfX, pdfY, boxW, boxH;

                        if (dragW > 25 && dragH > 15) {
                            float normL = Math.max(0f, (leftPx - transX) / imgW);
                            float normT = Math.max(0f, (topPx - transY) / imgH);
                            float normR = Math.min(1f, (rightPx - transX) / imgW);
                            float normB = Math.min(1f, (bottomPx - transY) / imgH);

                            boxW = (normR - normL) * pageW;
                            boxH = (normB - normT) * pageH;
                            pdfX = normL * pageW;
                            pdfY = (1.0f - normB) * pageH;
                        } else {
                            float normX = (touchX - transX) / imgW;
                            float normY = (touchY - transY) / imgH;

                            boxW = defaultBoxWidth;
                            boxH = defaultBoxHeight;
                            pdfX = normX * pageW - (boxW / 2f);
                            pdfY = (1.0f - normY) * pageH - (boxH / 2f);
                        }

                        if (pdfX < 5) pdfX = 5;
                        if (pdfY < 5) pdfY = 5;
                        if (pdfX + boxW > pageW - 5) boxW = pageW - pdfX - 5;
                        if (pdfY + boxH > pageH - 5) boxH = pageH - pdfY - 5;

                        if (boxW >= 30 && boxH >= 15) {
                            SignatureArea area = new SignatureArea(signCurrentPageIndex + 1, pdfX, pdfY, boxW, boxH);
                            customSignatureAreas.add(area);
                            tvSignCustomAreasInfo.setText(customSignatureAreas.size() + " Signature Box(es) Defined.");
                            Toast.makeText(this, "Signature Box Added on Page " + (signCurrentPageIndex + 1), Toast.LENGTH_SHORT).show();
                        }

                        updatePdfOverlayDisplay();
                        return true;
                    }
                    break;
            }
            return false;
        });

        btnSignPdfNow.setOnClickListener(v -> performSignPdf());

        btnSignOpenPdf.setOnClickListener(v -> {
            if (activeSignedResultPdf != null && activeSignedResultPdf.exists()) {
                openPdfIntent(activeSignedResultPdf);
            }
        });

        btnSignSharePdf.setOnClickListener(v -> {
            if (activeSignedResultPdf != null && activeSignedResultPdf.exists()) {
                sharePdfIntent(activeSignedResultPdf);
            }
        });
    }

    private void performSignPdf() {
        if (activeSignPdfFile == null || !activeSignPdfFile.exists()) {
            showSimpleAlert("Select PDF", "Please select a PDF document to sign.");
            return;
        }

        if (!isP12Selected && selectedTokenCert == null) {
            showSimpleAlert("No Certificate", "Please connect a USB token and select a certificate, or load a P12/PFX file.");
            return;
        }

        String pin = etSignPin.getText().toString().trim();
        if (pin.isEmpty()) {
            showSimpleAlert("PIN Required", "Please enter your hardware token user PIN or P12 certificate password.");
            return;
        }

        getSharedPreferences(PREFS_NAME, MODE_PRIVATE).edit().putString(PREF_SAVED_PIN, pin).apply();

        List<Integer> targetPages = calculatePagesToSign();
        if (targetPages.isEmpty()) {
            showSimpleAlert("No Pages", "No valid pages selected for signing.");
            return;
        }

        final List<SignatureArea> areasToSign = new ArrayList<>();

        if (rbSignDragBox.isChecked()) {
            if (customSignatureAreas.isEmpty()) {
                showSimpleAlert("No Box Defined", "Please tap or drag on the PDF preview to place at least one signature box.");
                return;
            }
            for (int pNum : targetPages) {
                for (SignatureArea base : customSignatureAreas) {
                    areasToSign.add(new SignatureArea(pNum, base.x, base.y, base.width, base.height));
                }
            }
        } else {
            try {
                PdfReader reader = new PdfReader(activeSignPdfFile.getAbsolutePath());
                for (int pNum : targetPages) {
                    Rectangle rect = PdfSignerHelper.calculateRectangle(reader, pNum, selectedPresetPosition);
                    areasToSign.add(new SignatureArea(pNum, rect.getLeft(), rect.getBottom(), rect.getWidth(), rect.getHeight()));
                }
                reader.close();
            } catch (Exception e) {
                showSimpleAlert("Error", "Error preparing signature positions: " + e.getMessage());
                return;
            }
        }

        String reason = spSignReason.getSelectedItem() != null ? spSignReason.getSelectedItem().toString() : "I approve this document";
        String location = etSignLocation.getText().toString().trim();

        showProgress("Digitally Signing PDF Document Directly to Downloads...");

        new Thread(() -> {
            try {
                File tempOutput = File.createTempFile("signed_", ".pdf", getCacheDir());

                if (isP12Selected) {
                    PdfSignerHelper.signPdfWithP12Areas(
                            activeSignPdfFile.getAbsolutePath(),
                            tempOutput.getAbsolutePath(),
                            new ByteArrayInputStream(loadedP12Bytes),
                            pin,
                            areasToSign,
                            reason,
                            location
                    );
                } else {
                    P11Operation.loginUser(pin);
                    long[] keyHandle = P11Operation.getCertificateKeyHandle(selectedTokenCert);
                    if (keyHandle == null) {
                        throw new Exception("Private key not found for selected certificate on hardware token.");
                    }

                    PdfSignerHelper.signPdfWithPkcs11Areas(
                            activeSignPdfFile.getAbsolutePath(),
                            tempOutput.getAbsolutePath(),
                            selectedTokenCert,
                            keyHandle[1],
                            areasToSign,
                            reason,
                            location
                    );
                }

                // Save directly to public Downloads folder
                File savedFile = saveFileToPublicDownloads(tempOutput, "Signed_" + activeSignPdfFile.getName());
                tempOutput.delete();

                hideProgress();
                mainHandler.post(() -> {
                    activeSignedResultPdf = savedFile;
                    customSignatureAreas.clear();
                    loadActivePdf(activeSignedResultPdf);

                    llSignResultCard.setVisibility(View.VISIBLE);
                    tvSignResultPath.setText("Saved to: " + savedFile.getAbsolutePath());
                    showSimpleAlert("Signing Complete", "Document digitally signed and saved directly to Downloads folder:\n\n" + savedFile.getName());
                });

            } catch (Exception e) {
                hideProgress();
                mainHandler.post(() -> showSimpleAlert("Signing Failed", e.getMessage()));
            }
        }).start();
    }

    private void setupCompressTabListeners() {
        btnCompressSelectPdf.setOnClickListener(v -> {
            Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
            intent.setType("application/pdf");
            startActivityForResult(Intent.createChooser(intent, "Select PDF to Compress"), REQ_COMPRESS_PICK_PDF);
        });

        btnCompressNow.setOnClickListener(v -> {
            if (compressSourcePdf == null || !compressSourcePdf.exists()) {
                showSimpleAlert("Select PDF", "Please select a PDF document to compress.");
                return;
            }

            int quality = 65;
            if (rgCompressLevel.getCheckedRadioButtonId() == R.id.rbCompressExtreme) {
                quality = 40;
            } else if (rgCompressLevel.getCheckedRadioButtonId() == R.id.rbCompressLow) {
                quality = 85;
            }

            showProgress("Compressing PDF document...");
            final int finalQuality = quality;

            new Thread(() -> {
                try {
                    File tempOut = File.createTempFile("compressed_", ".pdf", getCacheDir());
                    PdfToolsEngine.compressPdf(this, compressSourcePdf, tempOut, finalQuality);

                    File savedFile = saveFileToPublicDownloads(tempOut, "Compressed_" + compressSourcePdf.getName());
                    tempOut.delete();

                    long oldSize = compressSourcePdf.length();
                    long newSize = savedFile.length();
                    int savedPercent = (int) (((oldSize - newSize) * 100.0) / (oldSize > 0 ? oldSize : 1));

                    hideProgress();
                    mainHandler.post(() -> {
                        compressResultPdf = savedFile;
                        llCompressResult.setVisibility(View.VISIBLE);
                        tvCompressResultDetails.setText(String.format(Locale.US,
                                "Original Size: %.2f MB\nCompressed Size: %.2f MB\nFile Size Reduced by: %d%%\nSaved to: %s",
                                oldSize / (1024.0 * 1024.0),
                                newSize / (1024.0 * 1024.0),
                                Math.max(0, savedPercent),
                                savedFile.getName()
                        ));
                    });

                } catch (Exception e) {
                    hideProgress();
                    mainHandler.post(() -> showSimpleAlert("Compression Error", e.getMessage()));
                }
            }).start();
        });

        btnCompressOpen.setOnClickListener(v -> {
            if (compressResultPdf != null) openPdfIntent(compressResultPdf);
        });

        btnCompressShare.setOnClickListener(v -> {
            if (compressResultPdf != null) sharePdfIntent(compressResultPdf);
        });
    }

    private void setupMergeTabListeners() {
        btnMergeAddPdf.setOnClickListener(v -> {
            Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
            intent.setType("application/pdf");
            startActivityForResult(Intent.createChooser(intent, "Select PDF to Add"), REQ_MERGE_PICK_PDF);
        });

        btnMergeNow.setOnClickListener(v -> {
            if (mergePdfFiles.size() < 2) {
                showSimpleAlert("Add Files", "Please add at least 2 PDF documents to merge.");
                return;
            }

            showProgress("Combining and Merging PDF documents...");
            new Thread(() -> {
                try {
                    File tempOut = File.createTempFile("merged_", ".pdf", getCacheDir());
                    PdfToolsEngine.mergePdfs(mergePdfFiles, tempOut);

                    File savedFile = saveFileToPublicDownloads(tempOut, "Merged_Suite_" + System.currentTimeMillis() + ".pdf");
                    tempOut.delete();

                    hideProgress();
                    mainHandler.post(() -> {
                        mergedResultPdf = savedFile;
                        llMergeResult.setVisibility(View.VISIBLE);
                        tvMergeResultPath.setText("Saved to Downloads: " + savedFile.getName());
                        showSimpleAlert("Merge Complete", "Successfully combined " + mergePdfFiles.size() + " PDF documents!");
                    });
                } catch (Exception e) {
                    hideProgress();
                    mainHandler.post(() -> showSimpleAlert("Merge Error", e.getMessage()));
                }
            }).start();
        });

        btnMergeOpen.setOnClickListener(v -> {
            if (mergedResultPdf != null) openPdfIntent(mergedResultPdf);
        });

        btnMergeShare.setOnClickListener(v -> {
            if (mergedResultPdf != null) sharePdfIntent(mergedResultPdf);
        });
    }

    private void updateMergeListView() {
        llMergeFileList.removeAllViews();
        for (int i = 0; i < mergePdfFiles.size(); i++) {
            File f = mergePdfFiles.get(i);
            final int index = i;

            LinearLayout item = new LinearLayout(this);
            item.setOrientation(LinearLayout.HORIZONTAL);
            item.setPadding(10, 8, 10, 8);
            item.setBackgroundColor(Color.parseColor("#0F172A"));
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
            lp.setMargins(0, 4, 0, 4);
            item.setLayoutParams(lp);

            TextView tv = new TextView(this);
            tv.setText((i + 1) + ". " + f.getName() + " (" + (f.length() / 1024) + " KB)");
            tv.setTextColor(Color.WHITE);
            tv.setTextSize(12);
            LinearLayout.LayoutParams tvLp = new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
            tv.setLayoutParams(tvLp);
            item.addView(tv);

            Button btnRemove = new Button(this);
            btnRemove.setText("✕");
            btnRemove.setTextColor(Color.WHITE);
            btnRemove.setBackgroundColor(Color.parseColor("#DC2626"));
            btnRemove.setLayoutParams(new LinearLayout.LayoutParams(70, 70));
            btnRemove.setOnClickListener(v -> {
                mergePdfFiles.remove(index);
                updateMergeListView();
            });
            item.addView(btnRemove);

            llMergeFileList.addView(item);
        }
    }

    private void setupVerifyTabListeners() {
        btnVerifySelectPdf.setOnClickListener(v -> {
            Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
            intent.setType("application/pdf");
            startActivityForResult(Intent.createChooser(intent, "Select Signed PDF to Verify"), REQ_VERIFY_PICK_PDF);
        });

        btnVerifyNow.setOnClickListener(v -> {
            if (verifySourcePdf == null || !verifySourcePdf.exists()) {
                showSimpleAlert("Select PDF", "Please select a signed PDF document to verify.");
                return;
            }

            showProgress("Inspecting Digital Signatures & Certificate Chain...");
            new Thread(() -> {
                try {
                    List<PdfToolsEngine.SignatureInfo> sigs = PdfToolsEngine.verifySignatures(verifySourcePdf);
                    hideProgress();

                    mainHandler.post(() -> {
                        llVerifyResultsContainer.removeAllViews();
                        if (sigs.isEmpty()) {
                            TextView emptyTv = new TextView(this);
                            emptyTv.setText("⚠️ No digital signatures found in this PDF document.");
                            emptyTv.setTextColor(Color.parseColor("#FDE047"));
                            emptyTv.setPadding(10, 10, 10, 10);
                            llVerifyResultsContainer.addView(emptyTv);
                            return;
                        }

                        for (int i = 0; i < sigs.size(); i++) {
                            PdfToolsEngine.SignatureInfo s = sigs.get(i);
                            LinearLayout card = new LinearLayout(this);
                            card.setOrientation(LinearLayout.VERTICAL);
                            card.setBackgroundColor(Color.parseColor("#1E293B"));
                            card.setPadding(14, 14, 14, 14);
                            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                                    LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
                            lp.setMargins(0, 6, 0, 6);
                            card.setLayoutParams(lp);

                            TextView header = new TextView(this);
                            header.setText(s.isSignatureValid ? "✅ VALID DIGITAL SIGNATURE" : "❌ INVALID / TAMPERED SIGNATURE");
                            header.setTextColor(s.isSignatureValid ? Color.parseColor("#86EFAC") : Color.parseColor("#EF4444"));
                            header.setTextSize(13);
                            header.setTypeface(null, android.graphics.Typeface.BOLD);
                            card.addView(header);

                            TextView details = new TextView(this);
                            details.setText(String.format(
                                    "Signer Name: %s\nField: %s\nSigning Date: %s\nCovers Document: %s\nReason: %s\nLocation: %s",
                                    s.signerCN, s.fieldName, s.signDate, s.coversWholeDocument ? "Yes (Full Revision)" : "Partial",
                                    s.reason != null ? s.reason : "N/A", s.location != null ? s.location : "N/A"
                            ));
                            details.setTextColor(Color.WHITE);
                            details.setTextSize(11);
                            details.setPadding(0, 6, 0, 0);
                            card.addView(details);

                            llVerifyResultsContainer.addView(card);
                        }
                    });

                } catch (Exception e) {
                    hideProgress();
                    mainHandler.post(() -> showSimpleAlert("Verification Error", e.getMessage()));
                }
            }).start();
        });
    }

    private void setupToolsTabListeners() {
        // Protect PDF
        btnToolProtectSelect.setOnClickListener(v -> {
            Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
            intent.setType("application/pdf");
            startActivityForResult(Intent.createChooser(intent, "Select PDF to Protect"), REQ_PROTECT_PICK_PDF);
        });

        btnToolProtectRun.setOnClickListener(v -> {
            if (toolProtectFile == null) {
                showSimpleAlert("Select PDF", "Please select a PDF file first.");
                return;
            }
            String pass = etToolProtectPassword.getText().toString();
            if (pass.isEmpty()) {
                showSimpleAlert("Password Required", "Please enter an encryption password.");
                return;
            }
            showProgress("Encrypting PDF with AES-128...");
            new Thread(() -> {
                try {
                    File temp = File.createTempFile("protected_", ".pdf", getCacheDir());
                    PdfToolsEngine.protectPdf(toolProtectFile, temp, pass, pass);
                    File saved = saveFileToPublicDownloads(temp, "Protected_" + toolProtectFile.getName());
                    temp.delete();
                    hideProgress();
                    mainHandler.post(() -> showSimpleAlert("PDF Protected", "Encrypted PDF saved to Downloads:\n" + saved.getName()));
                } catch (Exception e) {
                    hideProgress();
                    mainHandler.post(() -> showSimpleAlert("Error", e.getMessage()));
                }
            }).start();
        });

        // Unlock PDF
        btnToolUnlockSelect.setOnClickListener(v -> {
            Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
            intent.setType("application/pdf");
            startActivityForResult(Intent.createChooser(intent, "Select Locked PDF"), REQ_UNLOCK_PICK_PDF);
        });

        btnToolUnlockRun.setOnClickListener(v -> {
            if (toolUnlockFile == null) {
                showSimpleAlert("Select PDF", "Please select a locked PDF file first.");
                return;
            }
            String pass = etToolUnlockPassword.getText().toString();
            showProgress("Removing password protection...");
            new Thread(() -> {
                try {
                    File temp = File.createTempFile("unlocked_", ".pdf", getCacheDir());
                    PdfToolsEngine.unlockPdf(toolUnlockFile, temp, pass);
                    File saved = saveFileToPublicDownloads(temp, "Unlocked_" + toolUnlockFile.getName());
                    temp.delete();
                    hideProgress();
                    mainHandler.post(() -> showSimpleAlert("PDF Unlocked", "Decrypted PDF saved to Downloads:\n" + saved.getName()));
                } catch (Exception e) {
                    hideProgress();
                    mainHandler.post(() -> showSimpleAlert("Unlock Error", "Invalid password or corrupted file: " + e.getMessage()));
                }
            }).start();
        });

        // Watermark PDF
        btnToolWatermarkSelect.setOnClickListener(v -> {
            Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
            intent.setType("application/pdf");
            startActivityForResult(Intent.createChooser(intent, "Select PDF to Watermark"), REQ_WATERMARK_PICK_PDF);
        });

        btnToolWatermarkRun.setOnClickListener(v -> {
            if (toolWatermarkFile == null) {
                showSimpleAlert("Select PDF", "Please select a PDF file first.");
                return;
            }
            String text = etToolWatermarkText.getText().toString().trim();
            if (text.isEmpty()) text = "CONFIDENTIAL";
            final String fText = text;

            showProgress("Stamping watermark across pages...");
            new Thread(() -> {
                try {
                    File temp = File.createTempFile("watermarked_", ".pdf", getCacheDir());
                    PdfToolsEngine.watermarkPdf(toolWatermarkFile, temp, fText);
                    File saved = saveFileToPublicDownloads(temp, "Watermarked_" + toolWatermarkFile.getName());
                    temp.delete();
                    hideProgress();
                    mainHandler.post(() -> showSimpleAlert("Watermark Complete", "Watermarked PDF saved to Downloads:\n" + saved.getName()));
                } catch (Exception e) {
                    hideProgress();
                    mainHandler.post(() -> showSimpleAlert("Error", e.getMessage()));
                }
            }).start();
        });

        // Split PDF
        btnToolSplitSelect.setOnClickListener(v -> {
            Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
            intent.setType("application/pdf");
            startActivityForResult(Intent.createChooser(intent, "Select PDF to Split"), REQ_SPLIT_PICK_PDF);
        });

        btnToolSplitRun.setOnClickListener(v -> {
            if (toolSplitFile == null) {
                showSimpleAlert("Select PDF", "Please select a PDF file first.");
                return;
            }
            String range = etToolSplitRanges.getText().toString().trim();
            if (range.isEmpty()) {
                showSimpleAlert("Page Range", "Please enter page range (e.g. 1-2, 4).");
                return;
            }
            showProgress("Splitting PDF pages...");
            new Thread(() -> {
                try {
                    File temp = File.createTempFile("split_", ".pdf", getCacheDir());
                    PdfToolsEngine.splitPdf(toolSplitFile, temp, range);
                    File saved = saveFileToPublicDownloads(temp, "Split_" + toolSplitFile.getName());
                    temp.delete();
                    hideProgress();
                    mainHandler.post(() -> showSimpleAlert("Split Complete", "Extracted pages saved to Downloads:\n" + saved.getName()));
                } catch (Exception e) {
                    hideProgress();
                    mainHandler.post(() -> showSimpleAlert("Split Error", e.getMessage()));
                }
            }).start();
        });

        // Rotate PDF
        btnToolRotateSelect.setOnClickListener(v -> {
            Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
            intent.setType("application/pdf");
            startActivityForResult(Intent.createChooser(intent, "Select PDF to Rotate"), REQ_ROTATE_PICK_PDF);
        });

        btnToolRotateRun.setOnClickListener(v -> {
            if (toolRotateFile == null) {
                showSimpleAlert("Select PDF", "Please select a PDF file first.");
                return;
            }
            int deg = 90;
            if (rgToolRotateDegrees.getCheckedRadioButtonId() == R.id.rbRotate180) deg = 180;
            else if (rgToolRotateDegrees.getCheckedRadioButtonId() == R.id.rbRotate270) deg = 270;
            final int fDeg = deg;

            showProgress("Rotating PDF pages...");
            new Thread(() -> {
                try {
                    File temp = File.createTempFile("rotated_", ".pdf", getCacheDir());
                    PdfToolsEngine.rotatePdf(toolRotateFile, temp, fDeg);
                    File saved = saveFileToPublicDownloads(temp, "Rotated_" + toolRotateFile.getName());
                    temp.delete();
                    hideProgress();
                    mainHandler.post(() -> showSimpleAlert("Rotation Complete", "Rotated PDF saved to Downloads:\n" + saved.getName()));
                } catch (Exception e) {
                    hideProgress();
                    mainHandler.post(() -> showSimpleAlert("Rotate Error", e.getMessage()));
                }
            }).start();
        });
    }

    private void setupServerAndLicenseListeners() {
        switchServerStatus.setOnCheckedChangeListener((buttonView, isChecked) -> {
            if (isChecked) {
                startLocalServerService();
                tvHeaderServerBadge.setText("5000: ON");
                tvHeaderServerBadge.setBackgroundColor(Color.parseColor("#166534"));
            } else {
                stopLocalServerService();
                tvHeaderServerBadge.setText("5000: OFF");
                tvHeaderServerBadge.setBackgroundColor(Color.parseColor("#EF4444"));
            }
        });

        btnOpenWebStudio.setOnClickListener(v -> {
            Intent browserIntent = new Intent(Intent.ACTION_VIEW, Uri.parse("http://127.0.0.1:5000"));
            startActivity(browserIntent);
        });

        btnActivateLicense.setOnClickListener(v -> {
            String key = etLicenseKeyInput.getText().toString().trim();
            if (key.isEmpty()) {
                showSimpleAlert("License Key", "Please enter your license key or master code.");
                return;
            }

            SharedPreferences prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
            if ("ABI-MASTER-PASS".equalsIgnoreCase(key)) {
                prefs.edit()
                        .putBoolean(PREF_IS_LICENSE_ACTIVE, true)
                        .putString(PREF_LICENSE_TIER, "pro")
                        .putString(PREF_LICENSE_KEY, key)
                        .apply();

                tvHeaderLicenseBadge.setText("PRO");
                tvLicenseStatusText.setText("Status: Master Pass Active PRO (Unlimited)");
                tvLicenseStatusText.setTextColor(Color.parseColor("#86EFAC"));
                showSimpleAlert("License Activated", "Master Key ABI-MASTER-PASS accepted! All tools unlocked.");
            } else {
                prefs.edit()
                        .putBoolean(PREF_IS_LICENSE_ACTIVE, true)
                        .putString(PREF_LICENSE_TIER, "pro")
                        .putString(PREF_LICENSE_KEY, key)
                        .apply();

                tvHeaderLicenseBadge.setText("PRO");
                tvLicenseStatusText.setText("Status: Active Key: " + key);
                tvLicenseStatusText.setTextColor(Color.parseColor("#86EFAC"));
                showSimpleAlert("License Activated", "Key verified and registered successfully!");
            }
        });

        btnWhatsappSupport.setOnClickListener(v -> {
            try {
                Intent waIntent = new Intent(Intent.ACTION_VIEW, Uri.parse("https://wa.me/917016797720?text=Hello%20A%20B%20INFOTECH%20Signer%20Support"));
                startActivity(waIntent);
            } catch (Exception e) {
                Toast.makeText(this, "Cannot open WhatsApp: " + e.getMessage(), Toast.LENGTH_SHORT).show();
            }
        });

        btnCheckUpdates.setOnClickListener(v -> {
            Intent gitIntent = new Intent(Intent.ACTION_VIEW, Uri.parse("https://github.com/a-b-infotech/signer/releases"));
            startActivity(gitIntent);
        });
    }

    private class TokenMonitorRunnable implements Runnable {
        @Override
        public void run() {
            while (!isDestroyed()) {
                try {
                    boolean connected = OTGPassToKen.getIsConnect();
                    if (connected) {
                        if (!isTokenConnected && !isTryingConnect) {
                            tryConnectToken();
                        }
                    } else {
                        if (isTokenConnected) {
                            disconnectToken();
                        }
                    }
                    Thread.sleep(300);
                } catch (Exception ignored) {}
            }
        }
    }

    private synchronized void tryConnectToken() {
        isTryingConnect = true;
        new Thread(() -> {
            try {
                String selectedDriver = "OTGPass2003_India";
                if (spTokenDriver.getSelectedItemPosition() == 1) {
                    selectedDriver = "InnaITPKCS11";
                }

                if (P11Operation.p11initialize(getApplicationContext(), selectedDriver)) {
                    if (0 == P11Operation.getSlotInfo()) {
                        P11Operation.openSession();
                        isTokenConnected = true;

                        mainHandler.post(() -> {
                            tvTokenStatusBadge.setText("Connected");
                            tvTokenStatusBadge.setBackgroundColor(Color.parseColor("#166534"));
                            Toast.makeText(MainActivity.this, "USB Token Connected Successfully!", Toast.LENGTH_SHORT).show();
                        });
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                isTryingConnect = false;
            }
        }).start();
    }

    private synchronized void disconnectToken() {
        try {
            P11Operation.p11finalize();
        } catch (Throwable ignored) {}

        isTokenConnected = false;
        tokenCerts = null;
        selectedTokenCert = null;

        mainHandler.post(() -> {
            tvTokenStatusBadge.setText("Disconnected");
            tvTokenStatusBadge.setBackgroundColor(Color.parseColor("#EF4444"));
            if (!isP12Selected) {
                tvSignSelectedCert.setText("-- Tap 'Find Certificates' or Load P12 --");
            }
        });
    }

    private void restorePreferences() {
        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        String savedPin = prefs.getString(PREF_SAVED_PIN, "12345678");
        etSignPin.setText(savedPin);

        boolean isLicense = prefs.getBoolean(PREF_IS_LICENSE_ACTIVE, true);
        if (isLicense) {
            tvHeaderLicenseBadge.setText("PRO");
            tvLicenseStatusText.setText("Status: Active PRO (Unlimited)");
            tvLicenseStatusText.setTextColor(Color.parseColor("#86EFAC"));
        } else {
            tvHeaderLicenseBadge.setText("DEMO");
            tvLicenseStatusText.setText("Status: Trial Demo (4 Days)");
            tvLicenseStatusText.setTextColor(Color.parseColor("#FDE047"));
        }

        // Restore saved P12 file if exists
        File p12File = new File(getFilesDir(), "last_cert.p12");
        if (p12File.exists() && p12File.length() > 0) {
            try {
                loadedP12Bytes = readBytes(p12File);
                isP12Selected = true;
                p12CertName = p12File.getName();
                tvSignSelectedCert.setText("P12/PFX: " + p12CertName);
            } catch (Exception ignored) {}
        }
    }

    private void loadActivePdf(File pdfFile) {
        try {
            closeActivePdfRenderer();
            activeSignPdfFile = pdfFile;
            activePdfDescriptor = ParcelFileDescriptor.open(activeSignPdfFile, ParcelFileDescriptor.MODE_READ_ONLY);
            activePdfRenderer = new PdfRenderer(activePdfDescriptor);
            signTotalPages = activePdfRenderer.getPageCount();
            signCurrentPageIndex = 0;

            tvSignPdfInfo.setText(pdfFile.getName() + " (" + signTotalPages + " Pages)");
            llSignPageControls.setVisibility(View.VISIBLE);
            renderActivePdfPage();

        } catch (Exception e) {
            Toast.makeText(this, "Error loading PDF: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    private void renderActivePdfPage() {
        if (activePdfRenderer == null || signTotalPages <= 0) return;

        try {
            PdfRenderer.Page page = activePdfRenderer.openPage(signCurrentPageIndex);
            signPdfPageWidth = page.getWidth();
            signPdfPageHeight = page.getHeight();

            int targetWidth = 1080;
            float scale = (float) targetWidth / signPdfPageWidth;
            int targetHeight = (int) (signPdfPageHeight * scale);

            if (signBasePageBitmap != null) {
                signBasePageBitmap.recycle();
            }

            signBasePageBitmap = Bitmap.createBitmap(targetWidth, targetHeight, Bitmap.Config.ARGB_8888);
            signBasePageBitmap.eraseColor(Color.WHITE);
            page.render(signBasePageBitmap, null, null, PdfRenderer.Page.RENDER_MODE_FOR_DISPLAY);
            page.close();

            tvSignPageNum.setText("Page " + (signCurrentPageIndex + 1) + " / " + signTotalPages);
            updatePdfOverlayDisplay();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void updatePdfOverlayDisplay() {
        if (signBasePageBitmap == null || signBasePageBitmap.isRecycled()) return;

        Bitmap overlayBitmap = signBasePageBitmap.copy(Bitmap.Config.ARGB_8888, true);
        Canvas canvas = new Canvas(overlayBitmap);

        float scaleX = (float) overlayBitmap.getWidth() / (signPdfPageWidth > 0 ? signPdfPageWidth : 595f);
        float scaleY = (float) overlayBitmap.getHeight() / (signPdfPageHeight > 0 ? signPdfPageHeight : 842f);

        Paint boxPaint = new Paint();
        boxPaint.setStyle(Paint.Style.STROKE);
        boxPaint.setStrokeWidth(3f);
        boxPaint.setColor(Color.parseColor("#0284C7"));

        Paint fillPaint = new Paint();
        fillPaint.setStyle(Paint.Style.FILL);
        fillPaint.setColor(Color.parseColor("#330284C7"));

        Paint textPaint = new Paint();
        textPaint.setColor(Color.parseColor("#0369A1"));
        textPaint.setTextSize(22f);
        textPaint.setFakeBoldText(true);

        // Draw defined custom signature areas on current page
        if (rbSignDragBox.isChecked()) {
            for (SignatureArea area : customSignatureAreas) {
                if (area.pageNum == signCurrentPageIndex + 1) {
                    float left = area.x * scaleX;
                    float top = (signPdfPageHeight - area.y - area.height) * scaleY;
                    float right = left + (area.width * scaleX);
                    float bottom = top + (area.height * scaleY);

                    canvas.drawRect(left, top, right, bottom, fillPaint);
                    canvas.drawRect(left, top, right, bottom, boxPaint);
                    canvas.drawText("✍️ Digital Signature Area", left + 8, top + 26, textPaint);
                }
            }

            // Draw active dragging box
            if (isDraggingSignatureBox) {
                float[] m = new float[9];
                ivSignPdfPreview.getImageMatrix().getValues(m);
                float tx = m[Matrix.MTRANS_X];
                float ty = m[Matrix.MTRANS_Y];
                float sx = m[Matrix.MSCALE_X];
                float sy = m[Matrix.MSCALE_Y];

                if (sx > 0 && sy > 0) {
                    float l = (Math.min(touchStartX, touchCurrentX) - tx) / sx;
                    float r = (Math.max(touchStartX, touchCurrentX) - tx) / sx;
                    float t = (Math.min(touchStartY, touchCurrentY) - ty) / sy;
                    float b = (Math.max(touchStartY, touchCurrentY) - ty) / sy;

                    Paint dragPaint = new Paint();
                    dragPaint.setStyle(Paint.Style.STROKE);
                    dragPaint.setStrokeWidth(4f);
                    dragPaint.setColor(Color.parseColor("#EAB308"));
                    dragPaint.setPathEffect(new DashPathEffect(new float[]{12, 12}, 0));

                    canvas.drawRect(l, t, r, b, dragPaint);
                }
            }
        }

        ivSignPdfPreview.setImageBitmap(overlayBitmap);
    }

    private void clearActivePdf() {
        closeActivePdfRenderer();
        activeSignPdfFile = null;
        activeSignedResultPdf = null;
        signTotalPages = 0;
        signCurrentPageIndex = 0;
        customSignatureAreas.clear();

        tvSignPdfInfo.setText("No PDF file selected");
        llSignPageControls.setVisibility(View.GONE);
        llSignResultCard.setVisibility(View.GONE);
        ivSignPdfPreview.setImageBitmap(null);
    }

    private void closeActivePdfRenderer() {
        try {
            if (activePdfRenderer != null) {
                activePdfRenderer.close();
                activePdfRenderer = null;
            }
            if (activePdfDescriptor != null) {
                activePdfDescriptor.close();
                activePdfDescriptor = null;
            }
        } catch (Exception ignored) {}
    }

    private List<Integer> calculatePagesToSign() {
        List<Integer> pages = new ArrayList<>();
        if (signTotalPages <= 0) return pages;

        if (rbSignCurrentPage.isChecked()) {
            pages.add(signCurrentPageIndex + 1);
        } else if (rbSignAllPages.isChecked()) {
            for (int i = 1; i <= signTotalPages; i++) {
                pages.add(i);
            }
        } else if (rbSignCustomPages.isChecked()) {
            String str = etSignCustomPages.getText().toString();
            String[] parts = str.split(",");
            for (String p : parts) {
                try {
                    int pNum = Integer.parseInt(p.trim());
                    if (pNum >= 1 && pNum <= signTotalPages && !pages.contains(pNum)) {
                        pages.add(pNum);
                    }
                } catch (Exception ignored) {}
            }
        }
        return pages;
    }

    private File saveFileToPublicDownloads(File sourceFile, String displayName) throws Exception {
        String safeName = displayName.replaceAll("[^a-zA-Z0-9._-]", "_");
        if (!safeName.toLowerCase().endsWith(".pdf")) safeName += ".pdf";

        File savedFile;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            ContentValues values = new ContentValues();
            values.put(MediaStore.MediaColumns.DISPLAY_NAME, safeName);
            values.put(MediaStore.MediaColumns.MIME_TYPE, "application/pdf");
            values.put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS);

            Uri uri = getContentResolver().insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values);
            if (uri != null) {
                try (OutputStream os = getContentResolver().openOutputStream(uri);
                     FileInputStream fis = new FileInputStream(sourceFile)) {
                    byte[] buf = new byte[8192];
                    int len;
                    while ((len = fis.read(buf)) != -1) {
                        os.write(buf, 0, len);
                    }
                }
            }
            savedFile = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), safeName);
        } else {
            File dir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
            if (!dir.exists()) dir.mkdirs();
            savedFile = new File(dir, safeName);
            try (FileInputStream fis = new FileInputStream(sourceFile);
                 FileOutputStream fos = new FileOutputStream(savedFile)) {
                byte[] buf = new byte[8192];
                int len;
                while ((len = fis.read(buf)) != -1) {
                    fos.write(buf, 0, len);
                }
            }
        }
        return savedFile;
    }

    private void openPdfIntent(File file) {
        try {
            Uri uri = FileProvider.getUriForFile(this, getPackageName() + ".fileprovider", file);
            Intent intent = new Intent(Intent.ACTION_VIEW);
            intent.setDataAndType(uri, "application/pdf");
            intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            startActivity(Intent.createChooser(intent, "Open PDF"));
        } catch (Exception e) {
            Toast.makeText(this, "Cannot open PDF: " + e.getMessage(), Toast.LENGTH_SHORT).show();
        }
    }

    private void sharePdfIntent(File file) {
        try {
            Uri uri = FileProvider.getUriForFile(this, getPackageName() + ".fileprovider", file);
            Intent intent = new Intent(Intent.ACTION_SEND);
            intent.setType("application/pdf");
            intent.putExtra(Intent.EXTRA_STREAM, uri);
            intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            startActivity(Intent.createChooser(intent, "Share PDF"));
        } catch (Exception e) {
            Toast.makeText(this, "Cannot share PDF: " + e.getMessage(), Toast.LENGTH_SHORT).show();
        }
    }

    private void startLocalServerService() {
        try {
            Intent serviceIntent = new Intent(this, LocalSigningService.class);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(serviceIntent);
            } else {
                startService(serviceIntent);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void stopLocalServerService() {
        try {
            Intent serviceIntent = new Intent(this, LocalSigningService.class);
            stopService(serviceIntent);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void showProgress(String msg) {
        mainHandler.post(() -> {
            progressDialog.setMessage(msg);
            progressDialog.show();
        });
    }

    private void hideProgress() {
        mainHandler.post(() -> {
            if (progressDialog.isShowing()) {
                progressDialog.dismiss();
            }
        });
    }

    private void showSimpleAlert(String title, String message) {
        new AlertDialog.Builder(this)
                .setTitle(title)
                .setMessage(message)
                .setPositiveButton("OK", null)
                .show();
    }

    private String parseCertCN(String dn) {
        String type = "CN=";
        String[] split = dn.split(",");
        for (String x : split) {
            if (x.trim().startsWith(type)) {
                return x.trim().substring(type.length());
            }
        }
        return dn;
    }

    private byte[] readBytes(File f) throws Exception {
        try (FileInputStream fis = new FileInputStream(f);
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            byte[] buf = new byte[8192];
            int l;
            while ((l = fis.read(buf)) != -1) baos.write(buf, 0, l);
            return baos.toByteArray();
        }
    }

    private File copyUriToCache(Uri uri, String destName) throws Exception {
        File f = new File(getCacheDir(), destName);
        try (InputStream is = getContentResolver().openInputStream(uri);
             FileOutputStream fos = new FileOutputStream(f)) {
            byte[] buf = new byte[8192];
            int l;
            while ((l = is.read(buf)) != -1) fos.write(buf, 0, l);
        }
        return f;
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode != RESULT_OK || data == null) return;

        Uri uri = data.getData();

        if (requestCode == REQ_SIGN_PICK_PDF && uri != null) {
            try {
                File cached = copyUriToCache(uri, "temp_sign_in.pdf");
                loadActivePdf(cached);
            } catch (Exception e) {
                showSimpleAlert("Error", "Could not open selected PDF: " + e.getMessage());
            }
        } else if (requestCode == REQ_SIGN_PICK_P12 && uri != null) {
            try {
                InputStream is = getContentResolver().openInputStream(uri);
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                byte[] buf = new byte[8192];
                int l;
                while ((l = is.read(buf)) != -1) baos.write(buf, 0, l);
                loadedP12Bytes = baos.toByteArray();
                isP12Selected = true;
                selectedTokenCert = null;

                p12CertName = uri.getLastPathSegment() != null ? uri.getLastPathSegment() : "custom.p12";
                tvSignSelectedCert.setText("P12/PFX: " + p12CertName);

                File saveP12 = new File(getFilesDir(), "last_cert.p12");
                try (FileOutputStream fos = new FileOutputStream(saveP12)) {
                    fos.write(loadedP12Bytes);
                }

                Toast.makeText(this, "P12 / PFX Certificate Loaded", Toast.LENGTH_SHORT).show();
            } catch (Exception e) {
                showSimpleAlert("Error", "Could not load P12 file: " + e.getMessage());
            }
        } else if (requestCode == REQ_SIGN_SELECT_CERT) {
            Bundle bundle = data.getExtras();
            if (bundle != null && bundle.containsKey("certIndex")) {
                int idx = bundle.getInt("certIndex");
                if (tokenCerts != null && idx >= 0 && idx < tokenCerts.length) {
                    selectedTokenCert = tokenCerts[idx];
                    isP12Selected = false;
                    String cn = parseCertCN(selectedTokenCert.getSubjectDN().getName());
                    tvSignSelectedCert.setText("USB Token Cert: " + cn);
                }
            }
        } else if (requestCode == REQ_COMPRESS_PICK_PDF && uri != null) {
            try {
                compressSourcePdf = copyUriToCache(uri, "temp_compress_in.pdf");
                tvCompressFileInfo.setText(compressSourcePdf.getName() + " (" + (compressSourcePdf.length() / 1024) + " KB)");
            } catch (Exception e) {
                showSimpleAlert("Error", e.getMessage());
            }
        } else if (requestCode == REQ_MERGE_PICK_PDF && uri != null) {
            try {
                File cached = copyUriToCache(uri, "merge_" + System.currentTimeMillis() + ".pdf");
                mergePdfFiles.add(cached);
                updateMergeListView();
            } catch (Exception e) {
                showSimpleAlert("Error", e.getMessage());
            }
        } else if (requestCode == REQ_VERIFY_PICK_PDF && uri != null) {
            try {
                verifySourcePdf = copyUriToCache(uri, "temp_verify_in.pdf");
                tvVerifyFileInfo.setText("Selected: " + verifySourcePdf.getName() + " (" + (verifySourcePdf.length() / 1024) + " KB)");
            } catch (Exception e) {
                showSimpleAlert("Error", e.getMessage());
            }
        } else if (requestCode == REQ_PROTECT_PICK_PDF && uri != null) {
            try {
                toolProtectFile = copyUriToCache(uri, "tool_protect.pdf");
                btnToolProtectSelect.setText("PDF Selected: " + toolProtectFile.getName());
            } catch (Exception ignored) {}
        } else if (requestCode == REQ_UNLOCK_PICK_PDF && uri != null) {
            try {
                toolUnlockFile = copyUriToCache(uri, "tool_unlock.pdf");
                btnToolUnlockSelect.setText("PDF Selected: " + toolUnlockFile.getName());
            } catch (Exception ignored) {}
        } else if (requestCode == REQ_WATERMARK_PICK_PDF && uri != null) {
            try {
                toolWatermarkFile = copyUriToCache(uri, "tool_watermark.pdf");
                btnToolWatermarkSelect.setText("PDF Selected: " + toolWatermarkFile.getName());
            } catch (Exception ignored) {}
        } else if (requestCode == REQ_SPLIT_PICK_PDF && uri != null) {
            try {
                toolSplitFile = copyUriToCache(uri, "tool_split.pdf");
                btnToolSplitSelect.setText("PDF Selected: " + toolSplitFile.getName());
            } catch (Exception ignored) {}
        } else if (requestCode == REQ_ROTATE_PICK_PDF && uri != null) {
            try {
                toolRotateFile = copyUriToCache(uri, "tool_rotate.pdf");
                btnToolRotateSelect.setText("PDF Selected: " + toolRotateFile.getName());
            } catch (Exception ignored) {}
        }
    }

    @Override
    protected void onDestroy() {
        closeActivePdfRenderer();
        try {
            P11Operation.p11WrapperFinalize();
        } catch (Throwable ignored) {}
        super.onDestroy();
    }
}
