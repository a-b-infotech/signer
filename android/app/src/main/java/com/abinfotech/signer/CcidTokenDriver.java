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
 * Directly communicates with USB Cryptographic Tokens (HYP2003, mToken, ProxKey, InnaIT)
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

    public static byte[] sendApduCommand(Context context, DetectedToken token, byte[] apdu) {
        if (token == null || token.device == null) return null;
        UsbManager manager = (UsbManager) context.getSystemService(Context.USB_SERVICE);
        if (manager == null || !manager.hasPermission(token.device)) return null;

        UsbDeviceConnection conn = manager.openDevice(token.device);
        if (conn == null) return null;

        try {
            UsbInterface ccidInterface = null;
            UsbEndpoint outEndpoint = null;
            UsbEndpoint inEndpoint = null;

            for (int i = 0; i < token.device.getInterfaceCount(); i++) {
                UsbInterface intf = token.device.getInterface(i);
                for (int j = 0; j < intf.getEndpointCount(); j++) {
                    UsbEndpoint ep = intf.getEndpoint(j);
                    if (ep.getType() == UsbConstants.USB_ENDPOINT_XFER_BULK) {
                        if (ep.getDirection() == UsbConstants.USB_DIR_OUT) outEndpoint = ep;
                        if (ep.getDirection() == UsbConstants.USB_DIR_IN) inEndpoint = ep;
                    }
                }
                if (outEndpoint != null && inEndpoint != null) {
                    ccidInterface = intf;
                    break;
                }
            }

            if (ccidInterface != null) {
                conn.claimInterface(ccidInterface, true);

                // Optional power on to ensure card ready
                byte[] pwrOn = new byte[]{0x62, 0, 0, 0, 0, 0, 0, 0, 0, 0};
                conn.bulkTransfer(outEndpoint, pwrOn, pwrOn.length, 1000);
                byte[] atrBuf = new byte[512];
                conn.bulkTransfer(inEndpoint, atrBuf, atrBuf.length, 1000);

                // Build CCID PC_to_RDR_XfrBlock (0x6F) message
                byte[] ccidMsg = new byte[10 + apdu.length];
                ccidMsg[0] = 0x6F; // Message Type
                int len = apdu.length;
                ccidMsg[1] = (byte) (len & 0xFF);
                ccidMsg[2] = (byte) ((len >> 8) & 0xFF);
                ccidMsg[3] = (byte) ((len >> 16) & 0xFF);
                ccidMsg[4] = (byte) ((len >> 24) & 0xFF);
                ccidMsg[5] = 0x00; // Slot number
                ccidMsg[6] = 0x01; // Sequence number
                System.arraycopy(apdu, 0, ccidMsg, 10, apdu.length);

                conn.bulkTransfer(outEndpoint, ccidMsg, ccidMsg.length, 3000);

                byte[] respBuf = new byte[1024];
                int read = conn.bulkTransfer(inEndpoint, respBuf, respBuf.length, 3000);
                if (read > 10) {
                    byte[] apduResp = new byte[read - 10];
                    System.arraycopy(respBuf, 10, apduResp, 0, read - 10);
                    return apduResp;
                }
            }
        } catch (Exception ignored) {
        } finally {
            try { conn.close(); } catch (Throwable ignored) {}
        }
        return null;
    }

    public static byte[] execCcidApdu(UsbDeviceConnection conn, UsbEndpoint outEp, UsbEndpoint inEp, byte[] apdu, int seq) {
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
            System.arraycopy(apdu, 0, ccidMsg, 10, apdu.length);

            conn.bulkTransfer(outEp, ccidMsg, ccidMsg.length, 3000);

            byte[] respBuf = new byte[2048];
            int read = conn.bulkTransfer(inEp, respBuf, respBuf.length, 3000);
            if (read > 10) {
                byte[] apduResp = new byte[read - 10];
                System.arraycopy(respBuf, 10, apduResp, 0, read - 10);
                return apduResp;
            }
        } catch (Throwable ignored) {}
        return null;
    }

    public static List<CcidCertInfo> readCertificatesViaCcid(Context context, String pin) {
        List<CcidCertInfo> results = new ArrayList<>();
        DetectedToken token = scanForToken(context);
        if (token == null || token.device == null) return results;

        UsbManager manager = (UsbManager) context.getSystemService(Context.USB_SERVICE);
        if (manager == null || !manager.hasPermission(token.device)) return results;

        UsbDeviceConnection conn = manager.openDevice(token.device);
        if (conn == null) return results;

        try {
            UsbInterface ccidIntf = null;
            UsbEndpoint outEp = null;
            UsbEndpoint inEp = null;

            for (int i = 0; i < token.device.getInterfaceCount(); i++) {
                UsbInterface intf = token.device.getInterface(i);
                for (int j = 0; j < intf.getEndpointCount(); j++) {
                    UsbEndpoint ep = intf.getEndpoint(j);
                    if (ep.getType() == UsbConstants.USB_ENDPOINT_XFER_BULK) {
                        if (ep.getDirection() == UsbConstants.USB_DIR_OUT) outEp = ep;
                        if (ep.getDirection() == UsbConstants.USB_DIR_IN) inEp = ep;
                    }
                }
                if (outEp != null && inEp != null) {
                    ccidIntf = intf;
                    break;
                }
            }

            if (ccidIntf == null) return results;
            conn.claimInterface(ccidIntf, true);

            // 1. Power On Card (CCID PC_to_RDR_IccPowerOn - 0x62)
            byte[] pwrOn = new byte[]{0x62, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            conn.bulkTransfer(outEp, pwrOn, pwrOn.length, 3000);
            byte[] atrBuf = new byte[1024];
            conn.bulkTransfer(inEp, atrBuf, atrBuf.length, 3000);

            int seq = 1;

            // 2. If PIN provided, attempt VERIFY PIN APDUs
            if (pin != null && !pin.trim().isEmpty()) {
                try {
                    byte[] pinBytes = pin.trim().getBytes("UTF-8");
                    byte[] verifyApdu = new byte[5 + pinBytes.length];
                    verifyApdu[0] = 0x00;
                    verifyApdu[1] = 0x20;
                    verifyApdu[2] = 0x00;
                    verifyApdu[3] = 0x00; // P2 = 0x00
                    verifyApdu[4] = (byte) pinBytes.length;
                    System.arraycopy(pinBytes, 0, verifyApdu, 5, pinBytes.length);
                    execCcidApdu(conn, outEp, inEp, verifyApdu, seq++);

                    verifyApdu[3] = 0x01; // P2 = 0x01
                    execCcidApdu(conn, outEp, inEp, verifyApdu, seq++);
                } catch (Throwable ignored) {}
            }

            // 3. Select PKCS#15 Application / Master File
            // AID: PKCS#15 A000000063504B43532D3135
            byte[] selPkcs15 = new byte[]{
                0x00, (byte)0xA4, 0x04, 0x00, 0x0C,
                (byte)0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35
            };
            execCcidApdu(conn, outEp, inEp, selPkcs15, seq++);

            // Or Select MF: 3F 00
            byte[] selMf = new byte[]{0x00, (byte)0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00};
            execCcidApdu(conn, outEp, inEp, selMf, seq++);

            // 4. Candidate Elementary Files (EF) for X.509 Certificates across tokens
            int[] candidateEfs = new int[]{0x3401, 0x3411, 0x5015, 0x4545, 0xC001, 0x2F02, 0x3F01, 0x3402, 0x3403};

            for (int ef : candidateEfs) {
                try {
                    byte hi = (byte) ((ef >> 8) & 0xFF);
                    byte lo = (byte) (ef & 0xFF);

                    // SELECT FILE
                    byte[] selFile = new byte[]{0x00, (byte)0xA4, 0x00, 0x00, 0x02, hi, lo};
                    byte[] selResp = execCcidApdu(conn, outEp, inEp, selFile, seq++);
                    if (selResp == null || selResp.length < 2) {
                        selFile[2] = 0x02;
                        selResp = execCcidApdu(conn, outEp, inEp, selFile, seq++);
                    }

                    // READ BINARY first chunk (offset 0, up to 256 bytes)
                    byte[] readBin = new byte[]{0x00, (byte)0xB0, 0x00, 0x00, 0x00};
                    byte[] binResp = execCcidApdu(conn, outEp, inEp, readBin, seq++);

                    if (binResp != null && binResp.length > 10) {
                        // Scan for ASN.1 DER sequence: 0x30 0x82
                        int derStart = -1;
                        for (int k = 0; k < binResp.length - 4; k++) {
                            if ((binResp[k] & 0xFF) == 0x30 && (binResp[k + 1] & 0xFF) == 0x82) {
                                derStart = k;
                                break;
                            }
                        }

                        if (derStart >= 0) {
                            int certLen = (((binResp[derStart + 2] & 0xFF) << 8) | (binResp[derStart + 3] & 0xFF)) + 4;
                            if (certLen > 300 && certLen < 8192) {
                                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                                baos.write(binResp, derStart, binResp.length - derStart);

                                int currentOffset = binResp.length - derStart;
                                while (baos.size() < certLen && currentOffset < certLen + 256) {
                                    byte offHi = (byte) ((currentOffset >> 8) & 0xFF);
                                    byte offLo = (byte) (currentOffset & 0xFF);
                                    int toRead = Math.min(256, certLen - baos.size());
                                    byte[] chunkCmd = new byte[]{0x00, (byte)0xB0, offHi, offLo, (byte)(toRead == 256 ? 0x00 : toRead)};
                                    byte[] chunkResp = execCcidApdu(conn, outEp, inEp, chunkCmd, seq++);
                                    if (chunkResp == null || chunkResp.length <= 2) break;
                                    int copyLen = chunkResp.length;
                                    if (chunkResp.length >= 2 && (chunkResp[chunkResp.length - 2] & 0xFF) == 0x90 && (chunkResp[chunkResp.length - 1] & 0xFF) == 0x00) {
                                        copyLen -= 2;
                                    }
                                    if (copyLen <= 0) break;
                                    baos.write(chunkResp, 0, copyLen);
                                    currentOffset += copyLen;
                                }

                                byte[] fullCertBytes = baos.toByteArray();
                                if (fullCertBytes.length >= certLen) {
                                    try {
                                        CertificateFactory cf = CertificateFactory.getInstance("X.509");
                                        X509Certificate x509 = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(fullCertBytes));
                                        if (x509 != null) {
                                            String subDn = x509.getSubjectDN() != null ? x509.getSubjectDN().getName() : "";
                                            String issDn = x509.getIssuerDN() != null ? x509.getIssuerDN().getName() : "";
                                            String cn = CertificateManager.extractCommonName(subDn);
                                            String issCn = CertificateManager.extractCommonName(issDn);

                                            if (CertificateManager.isClientCertificate(x509)) {
                                                CcidCertInfo info = new CcidCertInfo();
                                                info.clientName = cn;
                                                info.issuerName = issCn;
                                                info.rawCertBytes = fullCertBytes;
                                                info.x509Cert = x509;
                                                results.add(info);
                                            }
                                        }
                                    } catch (Throwable parseErr) {
                                        Log.w(TAG, "DER parse notice: " + parseErr.getMessage());
                                    }
                                }
                            }
                        }
                    }
                } catch (Throwable ignoredEf) {}
            }
        } catch (Throwable t) {
            Log.w(TAG, "readCertificatesViaCcid notice: " + t.getMessage());
        } finally {
            try { conn.close(); } catch (Throwable ignored) {}
        }

        return results;
    }
}

