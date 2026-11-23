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
    // 1. HYP2003 / ePass2003 (Feitian / HyperPKI Hypersecu)
    public static final int VID_FEITIAN = 0x096e;      // Feitian Technologies (Old ePass2003)
    public static final int VID_HYPERSECU_1 = 0x2ccf;  // Hypersecu Information Systems (NEW HYP2003)
    public static final int VID_HYPERSECU_2 = 0x2ce3;  // Hypersecu secondary (HYP2003)
    public static final int VID_HYPERSECU_3 = 0x2003;  // HYP2003 hardware variant
    public static final int PID_EPASS2003 = 0x0405;
    public static final int PID_HYP2003_1 = 0x0807;
    public static final int PID_HYP2003_2 = 0x2003;

    // 2. mToken / CryptoID (Century Longmai PKI)
    // 0x055c is Beijing Century Longmai Technology Co., Ltd.
    public static final int VID_LONGMAI_1 = 0x055c;
    public static final int VID_LONGMAI_2 = 0x4c4d; // 'LM'
    public static final int VID_LONGMAI_3 = 0x0925; // Lakeview / Longmai
    public static final int VID_LONGMAI_4 = 0x24a4; // Longmai USB Key

    // 3. Watchdata ProxKey (Watchdata WDS)
    public static final int VID_WATCHDATA_1 = 0x163c;
    public static final int VID_WATCHDATA_2 = 0x24dc;
    public static final int VID_WATCHDATA_3 = 0x04b5;
    public static final int VID_WATCHDATA_4 = 0x1059;
    public static final int VID_WATCHDATA_5 = 0x04b4;

    // 4. InnaIT Precision (Precision Biometric India)
    public static final int VID_INNAIT_1 = 0x338c; // Precision Biometric India Pvt. Ltd. (InnaIT Key)
    public static final int VID_INNAIT_2 = 0x2617; // Precision Biometrics
    public static final int VID_INNAIT_3 = 0x2007; // InnaIT variant
    public static final int VID_INNAIT_4 = 0x08c3; // Precise Biometrics / Precision

    // 5. SafeNet eToken (Gemalto / Thales)
    public static final int VID_SAFENET_1 = 0x0529;
    public static final int VID_SAFENET_2 = 0x08e6;

    public static boolean isHyp2003(int vid) {
        return vid == VID_FEITIAN || vid == VID_HYPERSECU_1 || vid == VID_HYPERSECU_2 || vid == VID_HYPERSECU_3;
    }

    public static boolean isMToken(int vid) {
        return vid == VID_LONGMAI_1 || vid == VID_LONGMAI_2 || vid == VID_LONGMAI_3 || vid == VID_LONGMAI_4;
    }

    public static boolean isProxKey(int vid) {
        return vid == VID_WATCHDATA_1 || vid == VID_WATCHDATA_2 || vid == VID_WATCHDATA_3 || vid == VID_WATCHDATA_4 || vid == VID_WATCHDATA_5;
    }

    public static boolean isInnait(int vid) {
        return vid == VID_INNAIT_1 || vid == VID_INNAIT_2 || vid == VID_INNAIT_3 || vid == VID_INNAIT_4;
    }

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
            // 1. HYP2003 / ePass2003 (Feitian / Hypersecu - 0x096E, 0x2CCF, 0x2CE3, 0x2003)
            if (isHyp2003(vid) || pid == PID_EPASS2003 || pid == PID_HYP2003_1 || pid == PID_HYP2003_2) {
                return new DetectedToken("HYP2003 / ePass2003", "HyperPKI Feitian", vid, pid, dev, hasCcid);
            }
            // 2. mToken / CryptoID (Century Longmai - 0x055C, 0x4C4D, 0x0925, 0x24A4)
            if (isMToken(vid)) {
                return new DetectedToken("mToken / CryptoID", "Century Longmai PKI", vid, pid, dev, hasCcid);
            }
            // 3. Watchdata ProxKey (0x163C, 0x24DC, 0x04B5, 0x1059, 0x04B4)
            if (isProxKey(vid)) {
                return new DetectedToken("Watchdata ProxKey", "Watchdata WDS", vid, pid, dev, hasCcid);
            }
            // 4. InnaIT Precision (0x338C, 0x2617, 0x2007, 0x08C3)
            if (isInnait(vid)) {
                return new DetectedToken("InnaIT Precision", "Precision Biometrics", vid, pid, dev, hasCcid);
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

            if (combined.contains("epass") || combined.contains("hyp2003") || combined.contains("hyp 2003")
                    || combined.contains("feitian") || combined.contains("entersafe")
                    || combined.contains("hyperpki") || combined.contains("hypersecu")) {
                return new DetectedToken("HYP2003 / ePass2003", "HyperPKI Feitian", vid, pid, dev, hasCcid);
            }
            if (combined.contains("mtoken") || combined.contains("longmai") || combined.contains("cryptoid")) {
                return new DetectedToken("mToken / CryptoID", "Century Longmai PKI", vid, pid, dev, hasCcid);
            }
            if (combined.contains("proxkey") || combined.contains("watchdata") || combined.contains("wdassist")) {
                return new DetectedToken("Watchdata ProxKey", "Watchdata WDS", vid, pid, dev, hasCcid);
            }
            if (combined.contains("innait") || combined.contains("precision biometric") || combined.contains("precision key")) {
                return new DetectedToken("InnaIT Precision", "Precision Biometrics", vid, pid, dev, hasCcid);
            }
            if ((combined.contains("safenet") || combined.contains("gemalto") || combined.contains("thales") || combined.contains("etoken"))
                    && !combined.contains("mtoken") && !combined.contains("longmai") && !combined.contains("cryptoid")
                    && !combined.contains("hyp2003") && !combined.contains("feitian") && !combined.contains("epass")
                    && !combined.contains("proxkey") && !combined.contains("watchdata")
                    && !combined.contains("innait")) {
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
            // Drain residual endpoint data to prevent desync
            try {
                byte[] drain = new byte[1024];
                while (conn.bulkTransfer(inEp, drain, drain.length, 50) > 0) {}
            } catch (Throwable ignored) {}

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
        List<CcidCertInfo> fallbackList = new ArrayList<>();
        if (rawData == null || rawData.length < 50) return results;

        // 1. Try Java's standard CertificateFactory.generateCertificates (handles concatenated & PKCS#7 certs natively)
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            java.util.Collection<? extends java.security.cert.Certificate> certs = cf.generateCertificates(new ByteArrayInputStream(rawData));
            if (certs != null && !certs.isEmpty()) {
                for (java.security.cert.Certificate c : certs) {
                    if (c instanceof X509Certificate) {
                        X509Certificate x509 = (X509Certificate) c;
                        String sub = x509.getSubjectDN() != null ? x509.getSubjectDN().getName() : "";
                        String iss = x509.getIssuerDN() != null ? x509.getIssuerDN().getName() : "";
                        String clientName = CertificateManager.extractCommonName(sub);
                        String issuerName = CertificateManager.extractCommonName(iss);

                        if (CertificateManager.isClientCertificate(x509)) {
                            CcidCertInfo ci = new CcidCertInfo();
                            ci.clientName = clientName;
                            ci.issuerName = issuerName;
                            ci.rawCertBytes = x509.getEncoded();
                            ci.x509Cert = x509;
                            results.add(ci);
                            Log.d(TAG, "✅ CertificateFactory parsed client certificate: CN=" + clientName);
                        } else if (!sub.equalsIgnoreCase(iss)) {
                            CcidCertInfo fallback = new CcidCertInfo();
                            fallback.clientName = clientName;
                            fallback.issuerName = issuerName;
                            fallback.rawCertBytes = x509.getEncoded();
                            fallback.x509Cert = x509;
                            fallbackList.add(fallback);
                        }
                    }
                }
            }
        } catch (Throwable ignored) {}

        if (!results.isEmpty()) return results;

        // 2. Scan byte-by-byte for ASN.1 DER sequence: 30 82 <len_hi> <len_lo>
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
                if (start >= 0) cursor = start + 1;
                else break;
                continue;
            }

            boolean parsedOk = false;
            byte[] certBytes = new byte[certLen];
            System.arraycopy(rawData, start, certBytes, 0, certLen);
            try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate x509 = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
                if (x509 != null) {
                    parsedOk = true;
                    String sub = x509.getSubjectDN() != null ? x509.getSubjectDN().getName() : "";
                    String iss = x509.getIssuerDN() != null ? x509.getIssuerDN().getName() : "";
                    String clientName = CertificateManager.extractCommonName(sub);
                    String issuerName = CertificateManager.extractCommonName(iss);

                    if (CertificateManager.isClientCertificate(x509)) {
                        CcidCertInfo ci = new CcidCertInfo();
                        ci.clientName = clientName;
                        ci.issuerName = issuerName;
                        ci.rawCertBytes = certBytes;
                        ci.x509Cert = x509;
                        results.add(ci);
                        Log.d(TAG, "✅ Client Certificate Found CN=" + ci.clientName + " Issuer=" + ci.issuerName);
                    } else if (!sub.equalsIgnoreCase(iss)) {
                        CcidCertInfo fallback = new CcidCertInfo();
                        fallback.clientName = clientName;
                        fallback.issuerName = issuerName;
                        fallback.rawCertBytes = certBytes;
                        fallback.x509Cert = x509;
                        fallbackList.add(fallback);
                    }
                }
            } catch (Throwable t) {
                // Try direct ASN.1 Common Name extraction if CertificateFactory failed on wrapper
                String extractedCn = extractCnFromDer(certBytes);
                if (extractedCn != null && !extractedCn.isEmpty()) {
                    CcidCertInfo ci = new CcidCertInfo();
                    ci.clientName = extractedCn;
                    ci.issuerName = "Hardware Token CA";
                    ci.rawCertBytes = certBytes;
                    results.add(ci);
                    parsedOk = true;
                    Log.d(TAG, "✅ Direct ASN.1 extracted client cert: CN=" + extractedCn);
                }
            }
            cursor = parsedOk ? (start + certLen) : (start + 1);
        }

        if (results.isEmpty() && !fallbackList.isEmpty()) {
            results.addAll(fallbackList);
        }

        // Fallback: If no certificate found through sequence framing, scan entire raw data directly
        if (results.isEmpty() && rawData != null && rawData.length > 50) {
            String fallbackCn = extractCnFromDer(rawData);
            if (fallbackCn != null && !fallbackCn.isEmpty()) {
                CcidCertInfo ci = new CcidCertInfo();
                ci.clientName = fallbackCn;
                ci.issuerName = "Hardware Token CA";
                ci.rawCertBytes = rawData;
                results.add(ci);
                Log.d(TAG, "✅ Raw data ASN.1 extracted client cert: CN=" + fallbackCn);
            }
        }

        return results;
    }

    public static String extractCnFromDer(byte[] der) {
        if (der == null || der.length < 10) return null;
        byte[] oid = new byte[]{0x06, 0x03, 0x55, 0x04, 0x03}; // 2.5.4.3 (id-at-commonName)
        List<String> allCns = new ArrayList<>();

        for (int i = 0; i <= der.length - 10; i++) {
            boolean match = true;
            for (int j = 0; j < 5; j++) {
                if (der[i + j] != oid[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                int strTag = der[i + 5] & 0xFF;
                int lenByte = der[i + 6] & 0xFF;
                int vOffset = i + 7;
                int len = lenByte;

                if (lenByte == 0x81 && i + 7 < der.length) {
                    len = der[i + 7] & 0xFF;
                    vOffset = i + 8;
                } else if (lenByte == 0x82 && i + 8 < der.length) {
                    len = ((der[i + 7] & 0xFF) << 8) | (der[i + 8] & 0xFF);
                    vOffset = i + 9;
                }

                if (len > 0 && vOffset + len <= der.length) {
                    try {
                        String s;
                        if (strTag == 0x1E) { // BMPString (UTF-16BE)
                            s = new String(der, vOffset, len, "UTF-16BE").trim();
                        } else {
                            s = new String(der, vOffset, len, "UTF-8").trim();
                        }
                        if (!s.isEmpty()) {
                            allCns.add(s);
                        }
                    } catch (Throwable ignored) {}
                }
            }
        }

        if (allCns.isEmpty()) return null;

        // Filter out known CA / Sub-CA Common Names to isolate genuine client/subscriber CN
        List<String> clientCandidates = new ArrayList<>();
        for (String cn : allCns) {
            String lower = cn.toLowerCase();
            boolean isCa = lower.contains("sub ca") || lower.contains("sub-ca") || lower.contains("subca")
                    || lower.contains("root ca") || lower.contains("root-ca") || lower.contains("rootca")
                    || lower.contains("certifying authority") || lower.contains("certification authority")
                    || lower.contains("cca india") || lower.contains("intermediate ca") || lower.contains("issuing ca")
                    || lower.endsWith(" ca") || lower.startsWith("ca ") || lower.equals("ca");
            if (!isCa) {
                clientCandidates.add(cn);
            }
        }

        if (!clientCandidates.isEmpty()) {
            // Subject CN is always after Issuer CN in TBSCertificate, return the last client candidate
            return clientCandidates.get(clientCandidates.size() - 1);
        }

        return allCns.get(allCns.size() - 1);
    }

    public static CcidCertInfo parseX509Der(byte[] rawData) {
        List<CcidCertInfo> list = parseAllX509Der(rawData);
        return (!list.isEmpty()) ? list.get(0) : null;
    }

    public static boolean selectIsoFile(UsbDeviceConnection conn, UsbEndpoint outEp, UsbEndpoint inEp, int p1, int p2, int fid, int[] seqHolder) {
        byte hi = (byte) ((fid >> 8) & 0xFF);
        byte lo = (byte) (fid & 0xFF);
        byte[] cmd = new byte[]{0x00, (byte) 0xA4, (byte) p1, (byte) p2, 0x02, hi, lo};
        byte[] resp = execCcidApdu(conn, outEp, inEp, cmd, seqHolder[0]++);
        if (resp != null && resp.length >= 2) {
            int sw1 = resp[resp.length - 2] & 0xFF;
            return (sw1 == 0x90 || sw1 == 0x61 || sw1 == 0x62);
        }
        return false;
    }

    public static boolean selectFileFlexible(UsbDeviceConnection conn, UsbEndpoint outEp, UsbEndpoint inEp, int fid, int[] seqHolder) {
        int[] p2Options = new int[]{0x00, 0x0C, 0x04};
        int[] p1Options = new int[]{0x00, 0x02, 0x01};
        for (int p1 : p1Options) {
            for (int p2 : p2Options) {
                if (selectIsoFile(conn, outEp, inEp, p1, p2, fid, seqHolder)) {
                    return true;
                }
            }
        }
        return false;
    }

    public static byte[] readEntireBinaryFile(UsbDeviceConnection conn, UsbEndpoint outEp, UsbEndpoint inEp, int[] seqHolder) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        int offset = 0;
        int preferredChunk = 0x00; // 0x00 = ask for 256 bytes

        while (offset < 8192) {
            byte offHi = (byte) ((offset >> 8) & 0xFF);
            byte offLo = (byte) (offset & 0xFF);
            byte[] cmd = new byte[]{0x00, (byte) 0xB0, offHi, offLo, (byte) preferredChunk};
            byte[] resp = execCcidApdu(conn, outEp, inEp, cmd, seqHolder[0]++);

            if (resp == null || resp.length < 2) break;

            int sw1 = resp[resp.length - 2] & 0xFF;
            int sw2 = resp[resp.length - 1] & 0xFF;
            int dataLen = resp.length - 2;

            if (sw1 == 0x90 && sw2 == 0x00) {
                if (dataLen <= 0) break;
                stream.write(resp, 0, dataLen);
                offset += dataLen;
                int expectedLen = (preferredChunk == 0x00) ? 256 : (preferredChunk & 0xFF);
                if (dataLen < expectedLen) {
                    break;
                }
            } else if (sw1 == 0x62 && (sw2 == 0x82 || sw2 == 0x00)) {
                if (dataLen > 0) {
                    stream.write(resp, 0, dataLen);
                    offset += dataLen;
                }
                break;
            } else if (sw1 == 0x6C) {
                // Exact Le requested by token (e.g. 128 bytes = 0x80)
                preferredChunk = sw2;
                continue;
            } else if (sw1 == 0x67) {
                // Wrong length - fallback to smaller chunks
                if (preferredChunk == 0x00) {
                    preferredChunk = 0x80;
                    continue;
                } else if (preferredChunk == 0x80) {
                    preferredChunk = 0x40;
                    continue;
                } else {
                    break;
                }
            } else if (sw1 == 0x6B) {
                // Offset outside EF - end of file reached gracefully
                break;
            } else {
                break;
            }
        }
        return stream.toByteArray();
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
            // Drain residual endpoint data to prevent desync
            try {
                byte[] drain = new byte[1024];
                while (conn.bulkTransfer(inEp, drain, drain.length, 50) > 0) {}
            } catch (Throwable ignored) {}

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
            int[] seqHolder = new int[]{seq};

            // 2. WATCHDATA PROXKEY SPECIALIZED SCAN (3F00 -> 3F18 -> 0040 / 7001 / 0001)
            try {
                selectFileFlexible(conn, outEp, inEp, 0x3F00, seqHolder);
                if (selectFileFlexible(conn, outEp, inEp, 0x3F18, seqHolder)) {
                    for (int wdef : new int[]{0x0040, 0x7001, 0x0001, 0x0002}) {
                        if (selectFileFlexible(conn, outEp, inEp, wdef, seqHolder)) {
                            byte[] wdData = readEntireBinaryFile(conn, outEp, inEp, seqHolder);
                            if (wdData != null && wdData.length > 50) {
                                List<CcidCertInfo> wdInfos = parseAllX509Der(wdData);
                                if (!wdInfos.isEmpty()) {
                                    results.addAll(wdInfos);
                                    Log.d(TAG, "✅ Watchdata ProxKey 3F18/0040 retrieved cert CN=" + wdInfos.get(0).clientName);
                                    break;
                                }
                            }
                        }
                    }
                }
            } catch (Throwable t) {
                Log.w(TAG, "Watchdata 3F18 scan notice: " + t.getMessage());
            }

            // 3. MTOKEN / LONGMAI SPECIALIZED SCAN (3F00 -> 1100 -> C001 / C002 / 7001 / 4545)
            if (results.isEmpty()) {
                try {
                    selectFileFlexible(conn, outEp, inEp, 0x3F00, seqHolder);
                    if (selectFileFlexible(conn, outEp, inEp, 0x1100, seqHolder)) {
                        for (int mef : new int[]{0xC001, 0xC002, 0x7001, 0x4545}) {
                            if (selectFileFlexible(conn, outEp, inEp, mef, seqHolder)) {
                                byte[] mData = readEntireBinaryFile(conn, outEp, inEp, seqHolder);
                                if (mData != null && mData.length > 50) {
                                    List<CcidCertInfo> mInfos = parseAllX509Der(mData);
                                    if (!mInfos.isEmpty()) {
                                        results.addAll(mInfos);
                                        Log.d(TAG, "✅ mToken 1100/C001 retrieved cert CN=" + mInfos.get(0).clientName);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                } catch (Throwable t) {
                    Log.w(TAG, "mToken 1100 scan notice: " + t.getMessage());
                }
            }

            // 4. DIRECT GET DATA FOR MTOKEN & SMARTCARD TOKENS
            if (results.isEmpty()) {
                try {
                    byte[][] getDataCmds = new byte[][]{
                        new byte[]{0x00, (byte) 0xCA, 0x01, 0x01, 0x00},
                        new byte[]{(byte) 0x80, (byte) 0xCA, 0x01, 0x01, 0x00},
                        new byte[]{0x00, (byte) 0xCA, 0x01, 0x02, 0x00},
                        new byte[]{0x00, (byte) 0xCA, 0x00, 0x01, 0x00}
                    };
                    for (byte[] gd : getDataCmds) {
                        byte[] gresp = execCcidApdu(conn, outEp, inEp, gd, seqHolder[0]++);
                        if (gresp != null && gresp.length > 50) {
                            List<CcidCertInfo> gcinfos = parseAllX509Der(gresp);
                            if (!gcinfos.isEmpty()) {
                                results.addAll(gcinfos);
                                Log.d(TAG, "✅ GET_DATA APDU retrieved client cert CN=" + gcinfos.get(0).clientName);
                                break;
                            }
                        }
                    }
                } catch (Throwable t) {
                    Log.w(TAG, "GET_DATA probe notice: " + t.getMessage());
                }
            }

            // 5. UNIVERSAL ISO 7816-4 EF SCANNING UNDER 3F00 (Indian DSC & Global PKI)
            if (results.isEmpty()) {
                try {
                    selectFileFlexible(conn, outEp, inEp, 0x3F00, seqHolder);
                    int[] candidateEfs = new int[]{
                        0x7001, 0x7002, 0x7003, // Indian DSC Sign, Encrypt, CA
                        0xC001, 0xC002, 0xC003, // Longmai mToken Container Certs
                        0x4545,                 // Longmai mToken DSC EF
                        0x0040,                 // Watchdata ProxKey Cert EF
                        0x3401, 0x3402, 0x3403, 0x3411, // Feitian / EnterSafe
                        0x0001, 0x0002, 0x0003, 0x0004,
                        0x5015, 0x5031, 0x5032, 0x5034, // PKCS#15
                        0x2F02, 0x3F01
                    };

                    for (int ef : candidateEfs) {
                        if (selectFileFlexible(conn, outEp, inEp, ef, seqHolder)) {
                            byte[] fullFile = readEntireBinaryFile(conn, outEp, inEp, seqHolder);
                            if (fullFile != null && fullFile.length > 50) {
                                List<CcidCertInfo> cinfos = parseAllX509Der(fullFile);
                                if (!cinfos.isEmpty()) {
                                    results.addAll(cinfos);
                                    Log.d(TAG, "✅ EF 0x" + Integer.toHexString(ef) + " retrieved cert CN=" + cinfos.get(0).clientName);
                                }
                            }
                        }
                    }
                } catch (Throwable t) {
                    Log.w(TAG, "Universal EF scan notice: " + t.getMessage());
                }
            }

            // 6. INNAIT & DEDICATED FILES (1100, DF01, 5015, DF02)
            if (results.isEmpty()) {
                try {
                    int[] candidateDfs = new int[]{0x1100, 0xDF01, 0xDF02, 0xDF03, 0x5015};
                    for (int df : candidateDfs) {
                        selectFileFlexible(conn, outEp, inEp, 0x3F00, seqHolder);
                        if (selectFileFlexible(conn, outEp, inEp, df, seqHolder)) {
                            for (int subEf : new int[]{0x7001, 0x7002, 0x0001, 0x0002, 0x5031, 0x5032, 0xC001}) {
                                if (selectFileFlexible(conn, outEp, inEp, subEf, seqHolder)) {
                                    byte[] dfFile = readEntireBinaryFile(conn, outEp, inEp, seqHolder);
                                    if (dfFile != null && dfFile.length > 50) {
                                        List<CcidCertInfo> dInfos = parseAllX509Der(dfFile);
                                        if (!dInfos.isEmpty()) {
                                            results.addAll(dInfos);
                                            Log.d(TAG, "✅ DF 0x" + Integer.toHexString(df) + " retrieved cert CN=" + dInfos.get(0).clientName);
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        if (!results.isEmpty()) break;
                    }
                } catch (Throwable t) {
                    Log.w(TAG, "DF scan notice: " + t.getMessage());
                }
            }
            seq = seqHolder[0];

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
                                    seqHolder[0] = seq;
                                    byte[] p15Data = readEntireBinaryFile(conn, outEp, inEp, seqHolder);
                                    seq = seqHolder[0];

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

    public static byte[] signViaCcid(Context context, String pin, byte[] digestInfo) throws Exception {
        if (digestInfo == null || digestInfo.length == 0) {
            throw new Exception("Digest info to sign is empty");
        }
        DetectedToken token = scanForToken(context);
        if (token == null || token.device == null) {
            throw new Exception("No hardware USB token detected");
        }

        boolean connOk = UsbTokenManager.setupHardwareTokenConnection(context);
        if (!connOk) {
            throw new Exception("Could not open USB connection to token");
        }

        UsbDeviceConnection conn = UsbTokenManager.getActiveConnection();
        UsbEndpoint inEp = UsbTokenManager.getBulkInEndpoint();
        UsbEndpoint outEp = UsbTokenManager.getBulkOutEndpoint();
        if (conn == null || inEp == null || outEp == null) {
            throw new Exception("USB endpoints not available");
        }

        int seq = 1;

        // 1. Verify PIN if provided
        if (pin != null && !pin.trim().isEmpty()) {
            byte[] pinBytes = pin.trim().getBytes("UTF-8");
            byte[][] verifyApdus = new byte[][]{
                    buildApdu((byte) 0x00, (byte) 0x20, (byte) 0x00, (byte) 0x80, pinBytes),
                    buildApdu((byte) 0x00, (byte) 0x20, (byte) 0x00, (byte) 0x01, pinBytes),
                    buildApdu((byte) 0x80, (byte) 0x22, (byte) 0x00, (byte) 0x00, pinBytes)
            };
            for (byte[] vapdu : verifyApdus) {
                try {
                    execCcidApdu(conn, outEp, inEp, vapdu, seq++);
                } catch (Throwable ignored) {}
            }
        }

        // 2. Perform RSA Signing via PSO or SKF
        byte[][] signApdus = new byte[][]{
                buildApduWithLe((byte) 0x00, (byte) 0x2A, (byte) 0x9E, (byte) 0x9A, digestInfo, (byte) 0x00),
                buildApdu((byte) 0x00, (byte) 0x2A, (byte) 0x9E, (byte) 0x9A, digestInfo),
                buildApduWithLe((byte) 0x80, (byte) 0x4C, (byte) 0x00, (byte) 0x00, digestInfo, (byte) 0x00),
                buildApdu((byte) 0x80, (byte) 0x4C, (byte) 0x00, (byte) 0x00, digestInfo)
        };

        for (byte[] sapdu : signApdus) {
            try {
                byte[] resp = execCcidApdu(conn, outEp, inEp, sapdu, seq++);
                if (resp != null && resp.length >= 128) {
                    int sw1 = resp[resp.length - 2] & 0xFF;
                    int sw2 = resp[resp.length - 1] & 0xFF;
                    if (sw1 == 0x90 && sw2 == 0x00) {
                        byte[] sig = new byte[resp.length - 2];
                        System.arraycopy(resp, 0, sig, 0, sig.length);
                        return sig;
                    } else if (resp.length == 128 || resp.length == 256 || resp.length == 384 || resp.length == 512) {
                        return resp;
                    }
                }
            } catch (Throwable ignored) {}
        }

        throw new Exception("USB Token did not return RSA signature via CCID APDU.");
    }

    private static byte[] buildApdu(byte cla, byte ins, byte p1, byte p2, byte[] data) {
        int dlen = (data != null) ? data.length : 0;
        byte[] apdu = new byte[5 + dlen];
        apdu[0] = cla;
        apdu[1] = ins;
        apdu[2] = p1;
        apdu[3] = p2;
        apdu[4] = (byte) dlen;
        if (dlen > 0) {
            System.arraycopy(data, 0, apdu, 5, dlen);
        }
        return apdu;
    }

    private static byte[] buildApduWithLe(byte cla, byte ins, byte p1, byte p2, byte[] data, byte le) {
        int dlen = (data != null) ? data.length : 0;
        byte[] apdu = new byte[6 + dlen];
        apdu[0] = cla;
        apdu[1] = ins;
        apdu[2] = p1;
        apdu[3] = p2;
        apdu[4] = (byte) dlen;
        if (dlen > 0) {
            System.arraycopy(data, 0, apdu, 5, dlen);
        }
        apdu[apdu.length - 1] = le;
        return apdu;
    }
}
