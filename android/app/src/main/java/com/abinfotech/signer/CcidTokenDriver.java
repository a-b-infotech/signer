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
    public static final int VID_LONGMAI_5 = 0x24a4; // Longmai USB Key

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

            // CRITICAL: Hardware USB Vendor IDs have HIGHEST PRIORITY!
            // This prevents mToken / CryptoID (0x055c) from being misidentified as SafeNet eToken.
            // 1. mToken / CryptoID (Century Longmai - 0x055C, 0x338C, 0x4C4D, 0x0925, 0x24A4)
            if (vid == VID_LONGMAI_1 || vid == VID_LONGMAI_2 || vid == VID_LONGMAI_3 || vid == VID_LONGMAI_4 || vid == VID_LONGMAI_5) {
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

            // Secondary: Inspect USB product & manufacturer descriptor strings
            String prodName = "";
            String mfgName = "";
            try {
                if (dev.getProductName() != null) prodName = dev.getProductName().toLowerCase();
            } catch (Throwable ignored) {}
            try {
                if (dev.getManufacturerName() != null) mfgName = dev.getManufacturerName().toLowerCase();
            } catch (Throwable ignored) {}
            String combined = (prodName + " " + mfgName).trim();

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
            if ((combined.contains("safenet") || combined.contains("gemalto") || combined.contains("thales") || combined.contains("etoken"))
                    && !combined.contains("mtoken") && !combined.contains("longmai") && !combined.contains("cryptoid")
                    && !combined.contains("hyp2003") && !combined.contains("feitian") && !combined.contains("epass")
                    && !combined.contains("proxkey") && !combined.contains("watchdata")
                    && !combined.contains("innait") && !combined.contains("precision")) {
                return new DetectedToken("SafeNet eToken", "Gemalto / Thales", vid, pid, dev, hasCcid);
            }

            // Generic Smartcard / CCID
            if (hasCcid) {
                return new DetectedToken("Smartcard Token (CCID)", "USB PKI Token", vid, pid, dev, true);
            }
        }
        return null;
    }

    public static byte[] execRawCcidBlock(UsbDeviceConnection conn, UsbEndpoint outEp, UsbEndpoint inEp, byte[] apdu, int seq) {
        if (conn == null || outEp == null || inEp == null || apdu == null) return null;
        try {
            UsbInterface activeIntf = UsbTokenManager.getActiveInterface();
            int intfClass = activeIntf != null ? activeIntf.getInterfaceClass() : 11;
            boolean isCcidClass = (intfClass == 11 || intfClass == UsbConstants.USB_CLASS_CSCID);

            if (!isCcidClass) {
                // Raw vendor bulk: send APDU directly without CCID wrapper!
                int sent = conn.bulkTransfer(outEp, apdu, apdu.length, 3000);
                if (sent < 0) return null;
                byte[] rawBuf = new byte[4096];
                int read = conn.bulkTransfer(inEp, rawBuf, rawBuf.length, 3000);
                if (read <= 0) return null;
                byte[] res = new byte[read];
                System.arraycopy(rawBuf, 0, res, 0, read);
                return res;
            }

            // CCID PC_to_RDR_XfrBlock (0x6F)
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

            byte[] respBuf = new byte[4096];
            int read = conn.bulkTransfer(inEp, respBuf, respBuf.length, 3000);

            // Handle CCID time extension request (bmCommandStatus = 10b: 0x80 only)
            int waitLoop = 0;
            while (read >= 10 && ((respBuf[7] & 0xC0) == 0x80) && waitLoop++ < 5) {
                read = conn.bulkTransfer(inEp, respBuf, respBuf.length, 2000);
            }

            if (read >= 10 && respBuf[0] == (byte) 0x80) { // RDR_to_PC_DataBlock
                int dwLength = (respBuf[1] & 0xFF) | ((respBuf[2] & 0xFF) << 8) | ((respBuf[3] & 0xFF) << 16) | ((respBuf[4] & 0xFF) << 24);
                if (dwLength > 0) {
                    byte[] apduResp = new byte[dwLength];
                    int firstChunk = Math.min(dwLength, Math.max(0, read - 10));
                    if (firstChunk > 0) {
                        System.arraycopy(respBuf, 10, apduResp, 0, firstChunk);
                    }
                    int received = firstChunk;
                    while (received < dwLength) {
                        byte[] chunk = new byte[Math.min(2048, dwLength - received)];
                        int r = conn.bulkTransfer(inEp, chunk, chunk.length, 3000);
                        if (r <= 0) break;
                        System.arraycopy(chunk, 0, apduResp, received, r);
                        received += r;
                    }
                    return apduResp;
                } else {
                    return new byte[0];
                }
            } else if (read >= 2) {
                // If device returned raw APDU response even on Class 11
                int sw1 = respBuf[read - 2] & 0xFF;
                if (sw1 == 0x90 || sw1 == 0x61 || sw1 == 0x6C || sw1 == 0x6A || sw1 == 0x69 || sw1 == 0x6E || sw1 == 0x6D) {
                    byte[] apduResp = new byte[read];
                    System.arraycopy(respBuf, 0, apduResp, 0, read);
                    return apduResp;
                } else if (read > 10) {
                    byte[] apduResp = new byte[read - 10];
                    System.arraycopy(respBuf, 10, apduResp, 0, read - 10);
                    return apduResp;
                }
            }
        } catch (Throwable t) {
            Log.w(TAG, "execRawCcidBlock notice: " + t.getMessage());
        }
        return null;
    }

    public static byte[] execCcidApdu(UsbDeviceConnection conn, UsbEndpoint outEp, UsbEndpoint inEp, byte[] apdu, int seq) {
        byte[] resp = execRawCcidBlock(conn, outEp, inEp, apdu, seq);
        if (resp == null || resp.length < 2) return resp;

        int sw1 = resp[resp.length - 2] & 0xFF;
        int sw2 = resp[resp.length - 1] & 0xFF;

        // 1. Wrong Le: 6C xx -> retry with exact Le = sw2
        if (resp.length == 2 && sw1 == 0x6C) {
            byte[] retryApdu = apdu.clone();
            retryApdu[retryApdu.length - 1] = (byte) sw2;
            return execCcidApdu(conn, outEp, inEp, retryApdu, seq + 1);
        }

        // 2. Chained GET RESPONSE: 61 xx (or 9F xx) -> fetch data chunks until completion
        if (sw1 == 0x61 || sw1 == 0x9F) {
            ByteArrayOutputStream fullStream = new ByteArrayOutputStream();
            if (resp.length > 2) {
                fullStream.write(resp, 0, resp.length - 2);
            }
            int remaining = sw2;
            int nextSeq = seq + 1;
            int loop = 0;
            while (loop++ < 30) {
                byte le = (byte) (remaining == 0 ? 0x00 : remaining);
                byte[] getRespCmd = new byte[]{0x00, (byte) 0xC0, 0x00, 0x00, le};
                byte[] chunk = execRawCcidBlock(conn, outEp, inEp, getRespCmd, nextSeq++);
                if (chunk == null || chunk.length < 2) break;
                int csw1 = chunk[chunk.length - 2] & 0xFF;
                int csw2 = chunk[chunk.length - 1] & 0xFF;
                int cDataLen = chunk.length - 2;
                if (cDataLen > 0) {
                    fullStream.write(chunk, 0, cDataLen);
                }
                if (csw1 == 0x61 || csw1 == 0x9F) {
                    remaining = csw2;
                } else {
                    fullStream.write(chunk, chunk.length - 2, 2);
                    break;
                }
            }
            byte[] assembled = fullStream.toByteArray();
            if (assembled.length >= 2) return assembled;
        }

        return resp;
    }

    public static List<CcidCertInfo> parseAllX509Der(byte[] rawData) {
        List<CcidCertInfo> results = new ArrayList<>();
        if (rawData == null || rawData.length < 100) return results;

        int cursor = 0;
        while (cursor < rawData.length - 4) {
            int start = -1;
            int certLen = -1;
            for (int i = cursor; i < rawData.length - 4; i++) {
                if ((rawData[i] & 0xFF) == 0x30) {
                    int tag2 = rawData[i + 1] & 0xFF;
                    if (tag2 == 0x82 && i + 3 < rawData.length) {
                        start = i;
                        certLen = (((rawData[i + 2] & 0xFF) << 8) | (rawData[i + 3] & 0xFF)) + 4;
                        break;
                    } else if (tag2 == 0x81 && i + 2 < rawData.length) {
                        start = i;
                        certLen = (rawData[i + 2] & 0xFF) + 3;
                        break;
                    }
                }
            }
            if (start < 0 || certLen <= 50 || certLen > rawData.length - start) {
                if (start >= 0) cursor = start + 2;
                else break;
                continue;
            }

            byte[] certBytes = new byte[certLen];
            System.arraycopy(rawData, start, certBytes, 0, certLen);
            try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate x509 = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
                if (x509 != null) {
                    // Rigorous client certificate filter: strictly skips Root CA and Sub-CAs!
                    if (CertificateManager.isClientCertificate(x509)) {
                        CcidCertInfo ci = new CcidCertInfo();
                        String sub = x509.getSubjectDN() != null ? x509.getSubjectDN().getName() : "";
                        String iss = x509.getIssuerDN() != null ? x509.getIssuerDN().getName() : "";
                        ci.clientName = CertificateManager.extractCommonName(sub);
                        ci.issuerName = CertificateManager.extractCommonName(iss);
                        ci.rawCertBytes = certBytes;
                        ci.x509Cert = x509;
                        results.add(ci);
                        Log.d(TAG, "✅ Client Certificate Found CN=" + ci.clientName + " Issuer=" + ci.issuerName);
                    } else {
                        Log.d(TAG, "Skipping CA/chain certificate: " + x509.getSubjectDN());
                    }
                }
            } catch (Throwable t) {
                Log.w(TAG, "parseAllX509Der cert parse notice: " + t.getMessage());
            }
            cursor = start + certLen;
        }
        return results;
    }

    public static CcidCertInfo parseX509Der(byte[] rawData) {
        List<CcidCertInfo> list = parseAllX509Der(rawData);
        return (!list.isEmpty()) ? list.get(0) : null;
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
            UsbInterface activeIntf = UsbTokenManager.getActiveInterface();
            int intfClass = activeIntf != null ? activeIntf.getInterfaceClass() : 11;
            boolean isCcidClass = (intfClass == 11 || intfClass == UsbConstants.USB_CLASS_CSCID);

            // 1. Power On Card only if CCID Class (PC_to_RDR_IccPowerOn - 0x62)
            if (isCcidClass) {
                try {
                    byte[] pwrOn = new byte[]{0x62, 0, 0, 0, 0, 0, 0, 0, 0, 0};
                    conn.bulkTransfer(outEp, pwrOn, pwrOn.length, 1000);
                    byte[] atrBuf = new byte[512];
                    conn.bulkTransfer(inEp, atrBuf, atrBuf.length, 1000);
                } catch (Throwable ignored) {}
            }

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

                    v1[3] = (byte) 0x80; // P2 = 0x80
                    execCcidApdu(conn, outEp, inEp, v1, seq++);

                    // SKF VERIFY PIN (80 38 00 00 len PIN and 80 38 01 00 len PIN)
                    byte[] v2 = new byte[5 + pinBytes.length];
                    v2[0] = (byte) 0x80; v2[1] = 0x38; v2[2] = 0x00; v2[3] = 0x00; v2[4] = (byte) pinBytes.length;
                    System.arraycopy(pinBytes, 0, v2, 5, pinBytes.length);
                    execCcidApdu(conn, outEp, inEp, v2, seq++);

                    v2[2] = 0x01;
                    execCcidApdu(conn, outEp, inEp, v2, seq++);
                } catch (Throwable ignored) {}
            }

            // 3. PRIMARY STRATEGY: ISO 7816-4 EF & DF File Scanning (Directly reads certificate without PIN across Indian tokens!)
            try {
                // Select Master File 3F00
                execCcidApdu(conn, outEp, inEp, new byte[]{0x00, (byte) 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00}, seq++);

                // Candidate EFs for Indian & Global PKI USB tokens (mToken / CryptoID, ePass2003, ProxKey, InnaIT)
                int[] candidateEfs = new int[]{
                    0x7001, 0x7002, 0x7003, // Indian DSC Sign, Encrypt, CA
                    0xC001, 0xC002, 0xC003, // Longmai mToken Container Certs
                    0x4545,                 // Longmai mToken DSC EF
                    0x3401, 0x3402, 0x3403, 0x3411, // Feitian / EnterSafe
                    0x0001, 0x0002, 0x0003, 0x0004,
                    0x5015, 0x5031, 0x5032, 0x5034, // PKCS#15
                    0x2F02, 0x3F01
                };

                for (int ef : candidateEfs) {
                    byte hi = (byte) ((ef >> 8) & 0xFF);
                    byte lo = (byte) (ef & 0xFF);

                    byte[] selResp = execCcidApdu(conn, outEp, inEp, new byte[]{0x00, (byte) 0xA4, 0x00, 0x00, 0x02, hi, lo}, seq++);
                    if (selResp == null || selResp.length < 2) {
                        selResp = execCcidApdu(conn, outEp, inEp, new byte[]{0x00, (byte) 0xA4, 0x02, 0x00, 0x02, hi, lo}, seq++);
                    }
                    if (selResp == null || selResp.length < 2) {
                        selResp = execCcidApdu(conn, outEp, inEp, new byte[]{0x00, (byte) 0xA4, 0x00, 0x04, 0x02, hi, lo}, seq++);
                    }

                    ByteArrayOutputStream fileStream = new ByteArrayOutputStream();
                    int fileOffset = 0;
                    while (fileStream.size() < 4096) {
                        byte offHi = (byte) ((fileOffset >> 8) & 0xFF);
                        byte offLo = (byte) (fileOffset & 0xFF);
                        byte[] chunkCmd = new byte[]{0x00, (byte) 0xB0, offHi, offLo, 0x00};
                        byte[] chunkResp = execCcidApdu(conn, outEp, inEp, chunkCmd, seq++);
                        if (chunkResp == null || chunkResp.length <= 2) break;

                        int sw1 = chunkResp[chunkResp.length - 2] & 0xFF;
                        int sw2 = chunkResp[chunkResp.length - 1] & 0xFF;
                        int dataLen = chunkResp.length - 2;

                        if (sw1 == 0x90 && sw2 == 0x00) {
                            if (dataLen <= 0) break;
                            fileStream.write(chunkResp, 0, dataLen);
                            fileOffset += dataLen;
                            if (dataLen < 256) break;
                        } else if (sw1 == 0x6C) {
                            chunkCmd[4] = (byte) sw2;
                            byte[] retryChunk = execCcidApdu(conn, outEp, inEp, chunkCmd, seq++);
                            if (retryChunk != null && retryChunk.length > 2) {
                                int rlen = retryChunk.length - 2;
                                int rsw1 = retryChunk[retryChunk.length - 2] & 0xFF;
                                if (rsw1 == 0x90 && rlen > 0) {
                                    fileStream.write(retryChunk, 0, rlen);
                                    fileOffset += rlen;
                                }
                            }
                            break;
                        } else if (sw1 == 0x67) {
                            // Wrong length: retry with standard 128-byte chunk
                            chunkCmd[4] = (byte) 0x80;
                            byte[] retryChunk = execCcidApdu(conn, outEp, inEp, chunkCmd, seq++);
                            if (retryChunk != null && retryChunk.length > 2) {
                                int rlen = retryChunk.length - 2;
                                int rsw1 = retryChunk[retryChunk.length - 2] & 0xFF;
                                if (rsw1 == 0x90 && rlen > 0) {
                                    fileStream.write(retryChunk, 0, rlen);
                                    fileOffset += rlen;
                                }
                            }
                            break;
                        } else {
                            break;
                        }
                    }

                    byte[] fullFile = fileStream.toByteArray();
                    if (fullFile.length > 100) {
                        List<CcidCertInfo> cinfos = parseAllX509Der(fullFile);
                        if (!cinfos.isEmpty()) {
                            results.addAll(cinfos);
                        }
                    }
                }

                // If direct EF didn't return, try under Dedicated Files (DF)
                if (results.isEmpty()) {
                    int[] candidateDfs = new int[]{0x1100, 0xDF01, 0xDF02, 0xDF03, 0x5015};
                    for (int df : candidateDfs) {
                        byte dhi = (byte) ((df >> 8) & 0xFF);
                        byte dlo = (byte) (df & 0xFF);
                        execCcidApdu(conn, outEp, inEp, new byte[]{0x00, (byte) 0xA4, 0x00, 0x00, 0x02, dhi, dlo}, seq++);

                        for (int subEf : new int[]{0x0001, 0x0002, 0x7001, 0xC001, 0x4545}) {
                            byte shi = (byte) ((subEf >> 8) & 0xFF);
                            byte slo = (byte) (subEf & 0xFF);
                            execCcidApdu(conn, outEp, inEp, new byte[]{0x00, (byte) 0xA4, 0x00, 0x00, 0x02, shi, slo}, seq++);

                            ByteArrayOutputStream dfStream = new ByteArrayOutputStream();
                            int dfOffset = 0;
                            while (dfStream.size() < 4096) {
                                byte offHi = (byte) ((dfOffset >> 8) & 0xFF);
                                byte offLo = (byte) (dfOffset & 0xFF);
                                byte[] dCmd = new byte[]{0x00, (byte) 0xB0, offHi, offLo, 0x00};
                                byte[] dResp = execCcidApdu(conn, outEp, inEp, dCmd, seq++);
                                if (dResp == null || dResp.length <= 2) break;
                                int ds1 = dResp[dResp.length - 2] & 0xFF;
                                int dlen = dResp.length - 2;
                                if (ds1 == 0x90 && dlen > 0) {
                                    dfStream.write(dResp, 0, dlen);
                                    dfOffset += dlen;
                                    if (dlen < 256) break;
                                } else break;
                            }
                            byte[] dfFile = dfStream.toByteArray();
                            if (dfFile.length > 100) {
                                List<CcidCertInfo> dInfos = parseAllX509Der(dfFile);
                                if (!dInfos.isEmpty()) {
                                    results.addAll(dInfos);
                                    break;
                                }
                            }
                        }
                        if (!results.isEmpty()) break;
                    }
                }
            } catch (Throwable t) {
                Log.w(TAG, "EF scan notice: " + t.getMessage());
            }

            // 4. SECONDARY STRATEGY: PKCS#15 and Longmai Application AID Selection
            if (results.isEmpty()) {
                try {
                    byte[][] pkcs15Aids = new byte[][]{
                        new byte[]{0x00, (byte) 0xA4, 0x04, 0x00, 0x0C, (byte) 0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35, 0x00},
                        new byte[]{0x00, (byte) 0xA4, 0x04, 0x00, 0x0B, (byte) 0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35},
                        new byte[]{0x00, (byte) 0xA4, 0x04, 0x00, 0x08, (byte) 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00},
                        new byte[]{0x00, (byte) 0xA4, 0x04, 0x00, 0x08, (byte) 0xD1, 0x56, 0x00, 0x01, 0x32, 0x00, 0x00, 0x00},
                        new byte[]{0x00, (byte) 0xA4, 0x04, 0x00, 0x08, (byte) 0xD1, 0x56, 0x00, 0x01, 0x32, 0x03, 0x00, 0x01},
                        new byte[]{0x00, (byte) 0xA4, 0x04, 0x00, 0x07, (byte) 0xA0, 0x00, 0x00, 0x00, 0x18, 0x43, 0x4D},
                        new byte[]{0x00, (byte) 0xA4, 0x04, 0x00, 0x07, (byte) 0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00},
                        new byte[]{0x00, (byte) 0xA4, 0x04, 0x00, 0x08, (byte) 0xA0, 0x00, 0x00, 0x01, 0x51, 0x53, 0x50, 0x49}
                    };
                    for (byte[] paid : pkcs15Aids) {
                        byte[] pResp = execCcidApdu(conn, outEp, inEp, paid, seq++);
                        if (pResp != null && pResp.length >= 2) {
                            int psw1 = pResp[pResp.length - 2] & 0xFF;
                            if (psw1 == 0x90 || psw1 == 0x61) {
                                int[] p15Efs = new int[]{0x7001, 0x7002, 0xC001, 0x3401, 0x5031, 0x5032, 0x5034};
                                for (int pef : p15Efs) {
                                    byte phi = (byte) ((pef >> 8) & 0xFF);
                                    byte plo = (byte) (pef & 0xFF);
                                    execCcidApdu(conn, outEp, inEp, new byte[]{0x00, (byte) 0xA4, 0x00, 0x00, 0x02, phi, plo}, seq++);
                                    ByteArrayOutputStream p15Stream = new ByteArrayOutputStream();
                                    int p15Off = 0;
                                    while (p15Stream.size() < 3072) {
                                        byte offHi = (byte) ((p15Off >> 8) & 0xFF);
                                        byte offLo = (byte) (p15Off & 0xFF);
                                        byte[] cCmd = new byte[]{0x00, (byte) 0xB0, offHi, offLo, 0x00};
                                        byte[] cResp = execCcidApdu(conn, outEp, inEp, cCmd, seq++);
                                        if (cResp == null || cResp.length <= 2) break;
                                        int cs1 = cResp[cResp.length - 2] & 0xFF;
                                        int dlen = cResp.length - 2;
                                        if (cs1 == 0x90 && dlen > 0) {
                                            p15Stream.write(cResp, 0, dlen);
                                            p15Off += dlen;
                                            if (dlen < 256) break;
                                        } else break;
                                    }
                                    byte[] p15Data = p15Stream.toByteArray();
                                    if (p15Data.length > 50) {
                                        List<CcidCertInfo> p15Certs = parseAllX509Der(p15Data);
                                        if (!p15Certs.isEmpty()) {
                                            results.addAll(p15Certs);
                                            break;
                                        }
                                    }
                                }
                                if (!results.isEmpty()) break;
                            }
                        }
                    }
                } catch (Throwable t) {
                    Log.w(TAG, "PKCS15 probe notice: " + t.getMessage());
                }
            }

            // 5. TERTIARY STRATEGY: SKF Protocol (mToken / CryptoID & Chinese PKI tokens)
            if (results.isEmpty()) {
                try {
                    // SKF_ENUM_APP: 80 22 00 00 00 or 80 36 00 00 00
                    byte[] enumAppResp = execCcidApdu(conn, outEp, inEp, new byte[]{(byte) 0x80, 0x22, 0x00, 0x00, 0x00}, seq++);
                    if (enumAppResp == null || enumAppResp.length <= 2) {
                        enumAppResp = execCcidApdu(conn, outEp, inEp, new byte[]{(byte) 0x80, 0x36, 0x00, 0x00, 0x00}, seq++);
                    }
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
                        appNames.add("PKI");
                    }

                    for (String appName : appNames) {
                        byte[] appBytes = appName.getBytes("UTF-8");
                        byte[] openAppApdu = new byte[5 + appBytes.length];
                        openAppApdu[0] = (byte) 0x80; openAppApdu[1] = 0x26; openAppApdu[2] = 0x00; openAppApdu[3] = 0x00;
                        openAppApdu[4] = (byte) appBytes.length;
                        System.arraycopy(appBytes, 0, openAppApdu, 5, appBytes.length);
                        byte[] openAppResp = execCcidApdu(conn, outEp, inEp, openAppApdu, seq++);
                        if (openAppResp == null || openAppResp.length < 2) continue;

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
                            contNames.add("Sign");
                        }

                        for (String contName : contNames) {
                            byte[] contBytes = contName.getBytes("UTF-8");
                            byte[] openContApdu = new byte[5 + contBytes.length];
                            openContApdu[0] = (byte) 0x80; openContApdu[1] = 0x42; openContApdu[2] = 0x00; openContApdu[3] = 0x00;
                            openContApdu[4] = (byte) contBytes.length;
                            System.arraycopy(contBytes, 0, openContApdu, 5, contBytes.length);
                            execCcidApdu(conn, outEp, inEp, openContApdu, seq++);

                            byte[][] expApdus = new byte[][]{
                                new byte[]{(byte) 0x80, 0x48, 0x01, 0x00, 0x00},
                                new byte[]{(byte) 0x80, 0x48, 0x00, 0x00, 0x00},
                                new byte[]{(byte) 0x80, 0x4E, 0x01, 0x00, 0x00},
                                new byte[]{(byte) 0x80, 0x44, 0x01, 0x00, 0x00}
                            };
                            for (byte[] expApdu : expApdus) {
                                byte[] certResp = execCcidApdu(conn, outEp, inEp, expApdu, seq++);
                                if (certResp != null && certResp.length > 50) {
                                    List<CcidCertInfo> certInfos = parseAllX509Der(certResp);
                                    if (!certInfos.isEmpty()) {
                                        results.addAll(certInfos);
                                    }
                                }
                            }
                        }
                    }
                } catch (Throwable t) {
                    Log.w(TAG, "SKF probe notice: " + t.getMessage());
                }
            }

            // 6. QUATERNARY STRATEGY: PIV / FIPS 201 Strategy (for mToken CryptoFIPS / PIV mode)
            if (results.isEmpty()) {
                try {
                    byte[][] pivAids = new byte[][]{
                        new byte[]{0x00, (byte) 0xA4, 0x04, 0x00, 0x09, (byte) 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00},
                        new byte[]{0x00, (byte) 0xA4, 0x04, 0x00, 0x05, (byte) 0xA0, 0x00, 0x00, 0x03, 0x08}
                    };
                    for (byte[] selAid : pivAids) {
                        byte[] selResp = execCcidApdu(conn, outEp, inEp, selAid, seq++);
                        if (selResp != null && selResp.length >= 2) {
                            int sw1 = selResp[selResp.length - 2] & 0xFF;
                            if (sw1 == 0x90 || sw1 == 0x61) {
                                byte[][] pivGetCerts = new byte[][]{
                                    new byte[]{0x00, (byte) 0xCB, 0x3F, (byte) 0xFF, 0x05, 0x5C, 0x03, 0x5F, (byte) 0xC1, 0x05, 0x00},
                                    new byte[]{0x00, (byte) 0xCB, 0x3F, (byte) 0xFF, 0x05, 0x5C, 0x03, 0x5F, (byte) 0xC1, 0x0A, 0x00},
                                    new byte[]{0x00, (byte) 0xCB, 0x3F, (byte) 0xFF, 0x05, 0x5C, 0x03, 0x5F, (byte) 0xC1, 0x01, 0x00},
                                    new byte[]{0x00, (byte) 0xCB, 0x3F, (byte) 0xFF, 0x05, 0x5C, 0x03, 0x5F, (byte) 0xC1, 0x0B, 0x00}
                                };
                                for (byte[] pcmd : pivGetCerts) {
                                    byte[] presp = execCcidApdu(conn, outEp, inEp, pcmd, seq++);
                                    if (presp != null && presp.length > 50) {
                                        List<CcidCertInfo> cinfos = parseAllX509Der(presp);
                                        if (!cinfos.isEmpty()) {
                                            results.addAll(cinfos);
                                        }
                                    }
                                }
                            }
                        }
                    }
                } catch (Throwable t) {
                    Log.w(TAG, "PIV probe notice: " + t.getMessage());
                }
            }
        } catch (Throwable t) {
            Log.e(TAG, "CCID cert read exception: " + t.getMessage(), t);
        }
        return results;
    }
}
