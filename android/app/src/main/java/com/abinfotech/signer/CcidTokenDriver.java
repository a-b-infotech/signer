package com.abinfotech.signer;

import android.content.Context;
import android.hardware.usb.UsbConstants;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbEndpoint;
import android.hardware.usb.UsbInterface;
import android.hardware.usb.UsbManager;
import android.util.Log;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

/**
 * Pure Java CCID (Chip Card Interface Device) USB OTG Driver
 * Directly communicates with USB Cryptographic Tokens (HYP2003, mToken, ProxKey, InnaIT, SafeNet)
 * across any Android device without requiring incompatible native C/C++ libraries.
 */
public class CcidTokenDriver {

    private static final String TAG = "CcidTokenDriver";

    public static class DetectedToken {
        public String name;
        public String brand;
        public int vendorId;
        public int productId;
        public UsbDevice device;
        public boolean hasCcidInterface;

        public DetectedToken(String name, String brand, int vendorId, int productId, UsbDevice device, boolean hasCcid) {
            this.name = name;
            this.brand = brand;
            this.vendorId = vendorId;
            this.productId = productId;
            this.device = device;
            this.hasCcidInterface = hasCcid;
        }
    }

    public static class CcidCertInfo {
        public String clientName;
        public String issuerName;
        public byte[] rawCertBytes;
        public X509Certificate x509Cert;
    }

    // Supported USB Token Hardware Signatures (India & Global PKI)
    // 1. HYP2003 / ePass2003 (Feitian / EnterSafe / HyperPKI)
    public static final int VID_FEITIAN = 0x096e;
    public static final int PID_EPASS2003 = 0x0405;
    public static final int PID_HYP2003_1 = 0x0807;
    public static final int PID_HYP2003_2 = 0x2003;

    // 2. mToken / CryptoID (Century Longmai PKI)
    // 0x055c is Beijing Century Longmai Technology Co., Ltd.
    public static final int VID_LONGMAI_1 = 0x055c;
    public static final int VID_LONGMAI_2 = 0x338c;
    public static final int VID_LONGMAI_3 = 0x4c4d; // 'LM'
    public static final int VID_LONGMAI_4 = 0x0925; // Lakeview / Longmai

    // 3. Watchdata ProxKey (Watchdata WDS)
    public static final int VID_WATCHDATA_1 = 0x163c;
    public static final int VID_WATCHDATA_2 = 0x04b5;
    public static final int VID_WATCHDATA_3 = 0x1059;
    public static final int VID_WATCHDATA_4 = 0x04b4;

    // 4. InnaIT Precision (Precision / eMudhra)
    public static final int VID_INNAIT_1 = 0x2ccf;
    public static final int VID_INNAIT_2 = 0x2007;
    public static final int VID_INNAIT_3 = 0x2ce3;

    // 5. SafeNet eToken (Gemalto / Thales)
    public static final int VID_SAFENET_1 = 0x0529;
    public static final int VID_SAFENET_2 = 0x08e6;

    public static DetectedToken scanForToken(Context context) {
        if (context == null) return null;
        UsbManager manager = (UsbManager) context.getSystemService(Context.USB_SERVICE);
        if (manager == null) return null;

        HashMap<String, UsbDevice> devices = manager.getDeviceList();
        if (devices == null || devices.isEmpty()) return null;

        for (UsbDevice dev : devices.values()) {
            int vid = dev.getVendorId();
            int pid = dev.getProductId();

            boolean hasCcid = false;
            for (int i = 0; i < dev.getInterfaceCount(); i++) {
                UsbInterface intf = dev.getInterface(i);
                // CCID class is 0x0B (11) or vendor specific 0xFF (255)
                if (intf.getInterfaceClass() == 11 || intf.getInterfaceClass() == UsbConstants.USB_CLASS_CSCID) {
                    hasCcid = true;
                    break;
                }
            }

            // Inspect USB product & manufacturer descriptor strings if accessible
            String prodName = "";
            String mfgName = "";
            try {
                if (dev.getProductName() != null) prodName = dev.getProductName().toLowerCase();
            } catch (Throwable ignored) {}
            try {
                if (dev.getManufacturerName() != null) mfgName = dev.getManufacturerName().toLowerCase();
            } catch (Throwable ignored) {}
            String combined = (prodName + " " + mfgName).trim();

            // Match by product string descriptor heuristics first
            if (combined.contains("mtoken") || combined.contains("longmai") || combined.contains("cryptoid")) {
                return new DetectedToken("mToken / CryptoID", "Century Longmai PKI", vid, pid, dev, hasCcid);
            }
            if (combined.contains("epass") || combined.contains("hyp2003") || combined.contains("feitian")
                    || combined.contains("entersafe") || combined.contains("hyperpki")) {
                return new DetectedToken("HYP2003 / ePass2003", "HyperPKI Feitian", vid, pid, dev, hasCcid);
            }
            if (combined.contains("proxkey") || combined.contains("watchdata")) {
                return new DetectedToken("Watchdata ProxKey", "Watchdata WDS", vid, pid, dev, hasCcid);
            }
            if (combined.contains("innait") || combined.contains("precision") || combined.contains("emudhra")) {
                return new DetectedToken("InnaIT Precision", "Precision / eMudhra", vid, pid, dev, hasCcid);
            }
            if (combined.contains("safenet") || combined.contains("etoken") || combined.contains("gemalto") || combined.contains("thales")) {
                return new DetectedToken("SafeNet eToken", "Gemalto / Thales", vid, pid, dev, hasCcid);
            }

            // Match by USB Vendor IDs
            // 1. mToken / CryptoID (Century Longmai - 0x055C, 0x338C, 0x4C4D, 0x0925)
            if (vid == VID_LONGMAI_1 || vid == VID_LONGMAI_2 || vid == VID_LONGMAI_3 || vid == VID_LONGMAI_4) {
                return new DetectedToken("mToken / CryptoID", "Century Longmai PKI", vid, pid, dev, hasCcid);
            }
            // 2. HYP2003 / ePass2003 (Feitian / EnterSafe - 0x096E)
            if (vid == VID_FEITIAN) {
                return new DetectedToken("HYP2003 / ePass2003", "HyperPKI Feitian", vid, pid, dev, hasCcid);
            }
            // 3. Watchdata ProxKey (0x163C, 0x04B5, 0x1059, 0x04B4)
            if (vid == VID_WATCHDATA_1 || vid == VID_WATCHDATA_2 || vid == VID_WATCHDATA_3 || vid == VID_WATCHDATA_4) {
                return new DetectedToken("Watchdata ProxKey", "Watchdata WDS", vid, pid, dev, hasCcid);
            }
            // 4. InnaIT Precision (0x2CCF, 0x2007, 0x2CE3)
            if (vid == VID_INNAIT_1 || vid == VID_INNAIT_2 || vid == VID_INNAIT_3) {
                return new DetectedToken("InnaIT Precision", "Precision / eMudhra", vid, pid, dev, hasCcid);
            }
            // 5. SafeNet eToken (0x0529, 0x08E6)
            if (vid == VID_SAFENET_1 || vid == VID_SAFENET_2) {
                return new DetectedToken("SafeNet eToken", "Gemalto / Thales", vid, pid, dev, hasCcid);
            }
            // Generic Smartcard / CCID
            if (hasCcid) {
                return new DetectedToken("Smartcard Token (CCID)", "USB PKI Token", vid, pid, dev, true);
            }
        }
        return null;
    }

    public static byte[] execCcidApdu(UsbDeviceConnection conn, UsbEndpoint outEp, UsbEndpoint inEp, byte[] apdu, int seq) {
        if (conn == null || outEp == null || inEp == null || apdu == null) return null;
        try {
            byte[] ccidMsg = new byte[10 + apdu.length];
            ccidMsg[0] = 0x6F; // PC_to_RDR_XfrBlock
            int len = apdu.length;
            ccidMsg[1] = (byte) (len & 0xFF);
            ccidMsg[2] = (byte) ((len >> 8) & 0xFF);
            ccidMsg[3] = (byte) ((len >> 16) & 0xFF);
            ccidMsg[4] = (byte) ((len >> 24) & 0xFF);
            ccidMsg[5] = 0x00; // Slot 0
            ccidMsg[6] = (byte) (seq & 0xFF);
            ccidMsg[7] = 0x00; // bBWI
            ccidMsg[8] = 0x00; // wLevelParameter
            ccidMsg[9] = 0x00;
            System.arraycopy(apdu, 0, ccidMsg, 10, apdu.length);

            int sent = conn.bulkTransfer(outEp, ccidMsg, ccidMsg.length, 3000);
            if (sent < 0) return null;

            byte[] respBuf = new byte[2048];
            int read = conn.bulkTransfer(inEp, respBuf, respBuf.length, 3000);
            if (read >= 10 && respBuf[0] == (byte) 0x80) { // RDR_to_PC_DataBlock
                int dwLength = (respBuf[1] & 0xFF) | ((respBuf[2] & 0xFF) << 8) | ((respBuf[3] & 0xFF) << 16) | ((respBuf[4] & 0xFF) << 24);
                if (dwLength > 0) {
                    byte[] apduResp = new byte[dwLength];
                    int firstChunk = Math.min(dwLength, Math.max(0, read - 10));
                    if (firstChunk > 0) {
                        System.arraycopy(respBuf, 10, apduResp, 0, firstChunk);
                    }
                    int received = firstChunk;
                    // Multi-packet loop: read all remaining USB packets until dwLength bytes are received
                    while (received < dwLength) {
                        byte[] chunk = new byte[Math.min(2048, dwLength - received)];
                        int r = conn.bulkTransfer(inEp, chunk, chunk.length, 3000);
                        if (r <= 0) break;
                        System.arraycopy(chunk, 0, apduResp, received, r);
                        received += r;
                    }

                    // Check if card returned 61 xx (SW1 = 0x61: xx bytes available for GET RESPONSE)
                    if (dwLength == 2 && (apduResp[0] & 0xFF) == 0x61) {
                        int le = apduResp[1] & 0xFF;
                        byte[] getRespApdu = new byte[]{0x00, (byte) 0xC0, 0x00, 0x00, (byte) (le == 0 ? 0x00 : le)};
                        byte[] getRespData = execCcidApdu(conn, outEp, inEp, getRespApdu, seq + 1);
                        if (getRespData != null && getRespData.length > 0) {
                            return getRespData;
                        }
                    } else if (dwLength == 2 && (apduResp[0] & 0xFF) == 0x6C) {
                        // SW1 = 0x6C: Wrong Le, retry with exact Le = SW2
                        byte correctLe = apduResp[1];
                        byte[] retryApdu = apdu.clone();
                        retryApdu[retryApdu.length - 1] = correctLe;
                        return execCcidApdu(conn, outEp, inEp, retryApdu, seq + 1);
                    }

                    return apduResp;
                } else if (dwLength == 0) {
                    return new byte[0];
                }
            } else if (read > 10) {
                // Fallback for non-standard CCID frames
                byte[] apduResp = new byte[read - 10];
                System.arraycopy(respBuf, 10, apduResp, 0, read - 10);
                return apduResp;
            }
        } catch (Throwable t) {
            Log.w(TAG, "execCcidApdu notice: " + t.getMessage());
        }
        return null;
    }

    public static CcidCertInfo parseX509Der(byte[] rawData) {
        if (rawData == null || rawData.length < 100) return null;
        try {
            // Find 0x30 0x82 start
            int start = -1;
            for (int i = 0; i < rawData.length - 4; i++) {
                if ((rawData[i] & 0xFF) == 0x30 && (rawData[i + 1] & 0xFF) == 0x82) {
                    start = i;
                    break;
                }
            }
            if (start < 0) return null;
            int certLen = (((rawData[start + 2] & 0xFF) << 8) | (rawData[start + 3] & 0xFF)) + 4;
            if (certLen <= 0 || certLen > rawData.length - start) {
                certLen = rawData.length - start;
            }

            byte[] certBytes = new byte[certLen];
            System.arraycopy(rawData, start, certBytes, 0, certLen);

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate x509 = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
            if (x509 != null) {
                // Rigorous client cert check (skips Root CA and Sub CA!)
                if (!CertificateManager.isClientCertificate(x509)) {
                    Log.d(TAG, "Skipping CA/chain certificate: " + x509.getSubjectDN());
                    return null;
                }
                CcidCertInfo ci = new CcidCertInfo();
                String sub = x509.getSubjectDN() != null ? x509.getSubjectDN().getName() : "";
                String iss = x509.getIssuerDN() != null ? x509.getIssuerDN().getName() : "";
                ci.clientName = CertificateManager.extractCommonName(sub);
                ci.issuerName = CertificateManager.extractCommonName(iss);
                ci.rawCertBytes = certBytes;
                ci.x509Cert = x509;
                Log.d(TAG, "✅ Client Certificate Found CN=" + ci.clientName + " Issuer=" + ci.issuerName);
                return ci;
            }
        } catch (Throwable t) {
            Log.w(TAG, "parseX509Der notice: " + t.getMessage());
        }
        return null;
    }

    public static List<CcidCertInfo> readCertificatesViaCcid(Context context, String pin) {
        List<CcidCertInfo> results = new ArrayList<>();
        DetectedToken token = scanForToken(context);
        if (token == null || token.device == null) return results;

        boolean connOk = UsbTokenManager.setupHardwareTokenConnection(context);
        if (!connOk) return results;

        UsbDeviceConnection conn = UsbTokenManager.getActiveConnection();
        UsbEndpoint inEp = UsbTokenManager.getBulkInEndpoint();
        UsbEndpoint outEp = UsbTokenManager.getBulkOutEndpoint();
        if (conn == null || inEp == null || outEp == null) return results;

        try {
            // 1. Power On Card (CCID PC_to_RDR_IccPowerOn - 0x62)
            byte[] pwrOn = new byte[]{0x62, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            conn.bulkTransfer(outEp, pwrOn, pwrOn.length, 1000);
            byte[] atrBuf = new byte[512];
            conn.bulkTransfer(inEp, atrBuf, atrBuf.length, 1000);

            int seq = 1;

            // 2. PIN verification if provided
            if (pin != null && !pin.trim().isEmpty()) {
                try {
                    byte[] pinBytes = pin.trim().getBytes("UTF-8");
                    // Standard ISO 7816 VERIFY
                    byte[] v1 = new byte[5 + pinBytes.length];
                    v1[0] = 0x00; v1[1] = 0x20; v1[2] = 0x00; v1[3] = 0x00; v1[4] = (byte) pinBytes.length;
                    System.arraycopy(pinBytes, 0, v1, 5, pinBytes.length);
                    execCcidApdu(conn, outEp, inEp, v1, seq++);

                    v1[3] = 0x01; // P2 = 0x01
                    execCcidApdu(conn, outEp, inEp, v1, seq++);

                    // SKF VERIFY PIN (80 38 00 00 len PIN)
                    byte[] v2 = new byte[5 + pinBytes.length];
                    v2[0] = (byte) 0x80; v2[1] = 0x38; v2[2] = 0x00; v2[3] = 0x00; v2[4] = (byte) pinBytes.length;
                    System.arraycopy(pinBytes, 0, v2, 5, pinBytes.length);
                    execCcidApdu(conn, outEp, inEp, v2, seq++);
                } catch (Throwable ignored) {}
            }

            // 3. SKF Protocol Strategy (for mToken / CryptoID and Chinese PKI tokens)
            try {
                // SKF_ENUM_APP: 80 22 00 00 00
                byte[] enumAppResp = execCcidApdu(conn, outEp, inEp, new byte[]{(byte) 0x80, 0x22, 0x00, 0x00, 0x00}, seq++);
                List<String> appNames = new ArrayList<>();
                if (enumAppResp != null && enumAppResp.length > 2) {
                    int start = 0;
                    for (int i = 0; i < enumAppResp.length - 2; i++) {
                        if (enumAppResp[i] == 0x00) {
                            if (i > start) {
                                String app = new String(enumAppResp, start, i - start, "UTF-8").trim();
                                if (!app.isEmpty()) appNames.add(app);
                            }
                            start = i + 1;
                        }
                    }
                }
                if (appNames.isEmpty()) {
                    appNames.add("ENTERPRISE");
                    appNames.add("UserApp");
                    appNames.add("mToken");
                    appNames.add("Default");
                }

                for (String appName : appNames) {
                    byte[] appBytes = appName.getBytes("UTF-8");
                    byte[] openAppApdu = new byte[5 + appBytes.length];
                    openAppApdu[0] = (byte) 0x80; openAppApdu[1] = 0x26; openAppApdu[2] = 0x00; openAppApdu[3] = 0x00;
                    openAppApdu[4] = (byte) appBytes.length;
                    System.arraycopy(appBytes, 0, openAppApdu, 5, appBytes.length);
                    byte[] openAppResp = execCcidApdu(conn, outEp, inEp, openAppApdu, seq++);
                    if (openAppResp == null || openAppResp.length < 2) continue;

                    // Verify PIN inside the opened application
                    if (pin != null && !pin.trim().isEmpty()) {
                        try {
                            byte[] pinBytes = pin.trim().getBytes("UTF-8");
                            // SKF_VerifyPIN: 80 38 01 00 len PIN (User PIN)
                            byte[] vPinUser = new byte[5 + pinBytes.length];
                            vPinUser[0] = (byte) 0x80; vPinUser[1] = 0x38; vPinUser[2] = 0x01; vPinUser[3] = 0x00; vPinUser[4] = (byte) pinBytes.length;
                            System.arraycopy(pinBytes, 0, vPinUser, 5, pinBytes.length);
                            execCcidApdu(conn, outEp, inEp, vPinUser, seq++);

                            // 80 38 00 00 len PIN
                            vPinUser[2] = 0x00;
                            execCcidApdu(conn, outEp, inEp, vPinUser, seq++);

                            // ISO VERIFY: 00 20 00 81 len PIN / 00 20 00 01
                            byte[] vIso = new byte[5 + pinBytes.length];
                            vIso[0] = 0x00; vIso[1] = 0x20; vIso[2] = 0x00; vIso[3] = (byte) 0x81; vIso[4] = (byte) pinBytes.length;
                            System.arraycopy(pinBytes, 0, vIso, 5, pinBytes.length);
                            execCcidApdu(conn, outEp, inEp, vIso, seq++);

                            vIso[3] = 0x01;
                            execCcidApdu(conn, outEp, inEp, vIso, seq++);
                        } catch (Throwable ignored) {}
                    }

                    // Enumerate containers: SKF_ENUM_CONT: 80 46 00 00 00
                    byte[] enumContResp = execCcidApdu(conn, outEp, inEp, new byte[]{(byte) 0x80, 0x46, 0x00, 0x00, 0x00}, seq++);
                    List<String> contNames = new ArrayList<>();
                    if (enumContResp != null && enumContResp.length > 2) {
                        int cstart = 0;
                        for (int i = 0; i < enumContResp.length - 2; i++) {
                            if (enumContResp[i] == 0x00) {
                                if (i > cstart) {
                                    String cont = new String(enumContResp, cstart, i - cstart, "UTF-8").trim();
                                    if (!cont.isEmpty()) contNames.add(cont);
                                }
                                cstart = i + 1;
                            }
                        }
                    }
                    if (contNames.isEmpty()) {
                        contNames.add("Container1");
                        contNames.add("Container01");
                        contNames.add("User1");
                        contNames.add("SignCert");
                        contNames.add("Default");
                    }

                    for (String contName : contNames) {
                        byte[] contBytes = contName.getBytes("UTF-8");
                        byte[] openContApdu = new byte[5 + contBytes.length];
                        openContApdu[0] = (byte) 0x80; openContApdu[1] = 0x42; openContApdu[2] = 0x00; openContApdu[3] = 0x00;
                        openContApdu[4] = (byte) contBytes.length;
                        System.arraycopy(contBytes, 0, openContApdu, 5, contBytes.length);
                        execCcidApdu(conn, outEp, inEp, openContApdu, seq++);

                        // Export Certificate: 80 48 00 00 00 (Sign cert) / 80 48 01 00 00 / 80 44 ...
                        byte[][] expApdus = new byte[][]{
                            new byte[]{(byte) 0x80, 0x48, 0x00, 0x00, 0x00},
                            new byte[]{(byte) 0x80, 0x48, 0x01, 0x00, 0x00},
                            new byte[]{(byte) 0x80, 0x44, 0x00, 0x00, 0x00},
                            new byte[]{(byte) 0x80, 0x44, 0x01, 0x00, 0x00}
                        };
                        for (byte[] expApdu : expApdus) {
                            byte[] certResp = execCcidApdu(conn, outEp, inEp, expApdu, seq++);
                            if (certResp != null && certResp.length > 50) {
                                CcidCertInfo certInfo = parseX509Der(certResp);
                                if (certInfo != null) {
                                    results.add(certInfo);
                                }
                            }
                        }
                    }
                }
            } catch (Throwable t) {
                Log.w(TAG, "SKF probe notice: " + t.getMessage());
            }

            // 4. ISO 7816-4 EF File Scanning Strategy (Universally works across all tokens)
            if (results.isEmpty()) {
                try {
                    // Select Master File 3F00
                    execCcidApdu(conn, outEp, inEp, new byte[]{0x00, (byte) 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00}, seq++);

                    // Candidate EFs across Indian & Global PKI USB tokens
                    int[] candidateEfs = new int[]{
                        0x0001, 0x0002, 0x0003, 0x0004, 0x7001, 0x7002, 0x7003,
                        0x3401, 0x3402, 0x3403, 0x3411, 0x5015, 0x4545, 0xC001, 0x2F02, 0x3F01
                    };

                    for (int ef : candidateEfs) {
                        byte hi = (byte) ((ef >> 8) & 0xFF);
                        byte lo = (byte) (ef & 0xFF);

                        // Try SELECT FILE
                        byte[] selResp = execCcidApdu(conn, outEp, inEp, new byte[]{0x00, (byte) 0xA4, 0x00, 0x00, 0x02, hi, lo}, seq++);
                        if (selResp == null || selResp.length < 2) {
                            selResp = execCcidApdu(conn, outEp, inEp, new byte[]{0x00, (byte) 0xA4, 0x02, 0x00, 0x02, hi, lo}, seq++);
                        }
                        if (selResp == null || selResp.length < 2) {
                            selResp = execCcidApdu(conn, outEp, inEp, new byte[]{0x00, (byte) 0xA4, 0x00, 0x04, 0x02, hi, lo}, seq++);
                        }

                        // Read binary chunk (offset 0, up to 256 bytes)
                        byte[] binResp = execCcidApdu(conn, outEp, inEp, new byte[]{0x00, (byte) 0xB0, 0x00, 0x00, 0x00}, seq++);
                        if (binResp != null && binResp.length > 10) {
                            int derStart = -1;
                            for (int k = 0; k < binResp.length - 4; k++) {
                                if ((binResp[k] & 0xFF) == 0x30 && (binResp[k + 1] & 0xFF) == 0x82) {
                                    derStart = k;
                                    break;
                                }
                            }
                            if (derStart >= 0) {
                                int certLen = (((binResp[derStart + 2] & 0xFF) << 8) | (binResp[derStart + 3] & 0xFF)) + 4;
                                if (certLen > 250 && certLen < 8192) {
                                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                                    baos.write(binResp, derStart, binResp.length - derStart);

                                    int curOffset = binResp.length - derStart;
                                    while (baos.size() < certLen && curOffset < certLen + 256) {
                                        byte offHi = (byte) ((curOffset >> 8) & 0xFF);
                                        byte offLo = (byte) (curOffset & 0xFF);
                                        int toRead = Math.min(256, certLen - baos.size());
                                        byte[] chunkCmd = new byte[]{0x00, (byte) 0xB0, offHi, offLo, (byte) (toRead == 256 ? 0x00 : toRead)};
                                        byte[] chunkResp = execCcidApdu(conn, outEp, inEp, chunkCmd, seq++);
                                        if (chunkResp == null || chunkResp.length <= 2) break;
                                        int copyLen = chunkResp.length;
                                        if (chunkResp.length >= 2 && (chunkResp[chunkResp.length - 2] & 0xFF) == 0x90 && (chunkResp[chunkResp.length - 1] & 0xFF) == 0x00) {
                                            copyLen -= 2;
                                        }
                                        if (copyLen <= 0) break;
                                        baos.write(chunkResp, 0, copyLen);
                                        curOffset += copyLen;
                                    }

                                    byte[] fullBytes = baos.toByteArray();
                                    CcidCertInfo cinfo = parseX509Der(fullBytes);
                                    if (cinfo != null) {
                                        results.add(cinfo);
                                    }
                                }
                            }
                        }
                    }
                } catch (Throwable t) {
                    Log.w(TAG, "EF scan notice: " + t.getMessage());
                }
            }
        } catch (Throwable t) {
            Log.e(TAG, "CCID cert read exception: " + t.getMessage(), t);
        }
        return results;
    }
}
