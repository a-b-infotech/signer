package com.abinfotech.signer;

import android.content.Context;
import android.util.Log;

import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.MakeSignature;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;

import javax.crypto.Cipher;

import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * Standard PDF Digital Signer Engine using iText 5.5.13 and BouncyCastle CMS.
 * Produces Adobe Acrobat / Global PKI compliant visible digital signatures
 * supporting both USB Hardware Tokens (ePass2003, mToken, ProxKey, InnaIT) and P12/PFX software certificates.
 */
public class PdfSignerEngine {

    private static final String TAG = "PdfSignerEngine";

    static {
        try {
            if (Security.getProvider("BC") == null) {
                try {
                    Class<?> bcClass = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
                    Security.addProvider((java.security.Provider) bcClass.getDeclaredConstructor().newInstance());
                } catch (Throwable ignored) {}
            }
        } catch (Throwable t) {
            Log.w(TAG, "Notice checking BouncyCastle provider: " + t.getMessage());
        }
    }

    public enum Position {
        BOTTOM_RIGHT,
        BOTTOM_LEFT,
        TOP_RIGHT,
        TOP_LEFT,
        CENTER
    }

    public static Rectangle calculateRectangle(PdfReader reader, int pageNum, Position position, float width, float height) {
        Rectangle pageSize = reader.getPageSizeWithRotation(pageNum);
        if (width <= 0) width = 150;
        if (height <= 0) height = 50;
        float margin = 20;

        float lX = margin;
        float lY = margin;

        if (position == null) position = Position.BOTTOM_RIGHT;

        switch (position) {
            case BOTTOM_RIGHT:
                lX = pageSize.getWidth() - width - margin;
                lY = margin;
                break;
            case BOTTOM_LEFT:
                lX = margin;
                lY = margin;
                break;
            case TOP_RIGHT:
                lX = pageSize.getWidth() - width - margin;
                lY = pageSize.getHeight() - height - margin;
                break;
            case TOP_LEFT:
                lX = margin;
                lY = pageSize.getHeight() - height - margin;
                break;
            case CENTER:
                lX = (pageSize.getWidth() - width) / 2;
                lY = (pageSize.getHeight() - height) / 2;
                break;
        }

        return new Rectangle(lX, lY, lX + width, lY + height);
    }

    public static class PKCS11ExternalSignature implements ExternalSignature {
        private final long privateKeyHandle;
        private final String hashAlg;

        public PKCS11ExternalSignature(long privateKeyHandle, String hashAlg) {
            this.privateKeyHandle = privateKeyHandle;
            this.hashAlg = hashAlg != null ? hashAlg : DigestAlgorithms.SHA256;
        }

        @Override
        public String getHashAlgorithm() {
            return hashAlg;
        }

        @Override
        public String getEncryptionAlgorithm() {
            return "RSA";
        }

        @Override
        public byte[] sign(byte[] message) throws GeneralSecurityException {
            try {
                byte[] prefix;
                if (DigestAlgorithms.SHA1.equalsIgnoreCase(hashAlg)) {
                    prefix = new byte[]{
                            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
                    };
                } else {
                    prefix = new byte[]{
                            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
                    };
                }

                byte[] digestInfo = new byte[prefix.length + message.length];
                System.arraycopy(prefix, 0, digestInfo, 0, prefix.length);
                System.arraycopy(message, 0, digestInfo, prefix.length, message.length);

                try {
                    return P11Operation.signData(digestInfo, privateKeyHandle, PKCS11Constants.CKM_RSA_PKCS);
                } catch (Exception e1) {
                    return P11Operation.signData(message, privateKeyHandle, PKCS11Constants.CKM_RSA_PKCS);
                }
            } catch (Exception e) {
                throw new GeneralSecurityException("PKCS11 Hardware Signing Error: " + e.getMessage(), e);
            }
        }
    }

    public static class CcidExternalSignature implements ExternalSignature {
        private final Context context;
        private final String pin;
        private final String hashAlg;

        public CcidExternalSignature(Context context, String pin, String hashAlg) {
            this.context = context;
            this.pin = pin;
            this.hashAlg = hashAlg != null ? hashAlg : DigestAlgorithms.SHA256;
        }

        @Override
        public String getHashAlgorithm() {
            return hashAlg;
        }

        @Override
        public String getEncryptionAlgorithm() {
            return "RSA";
        }

        @Override
        public byte[] sign(byte[] message) throws GeneralSecurityException {
            try {
                byte[] prefix;
                if (DigestAlgorithms.SHA1.equalsIgnoreCase(hashAlg)) {
                    prefix = new byte[]{
                            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
                    };
                } else {
                    prefix = new byte[]{
                            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
                    };
                }

                byte[] digestInfo = new byte[prefix.length + message.length];
                System.arraycopy(prefix, 0, digestInfo, 0, prefix.length);
                System.arraycopy(message, 0, digestInfo, prefix.length, message.length);

                return CcidTokenDriver.signViaCcid(context, pin, digestInfo);
            } catch (Exception e) {
                throw new GeneralSecurityException("CCID USB Token Sign Error: " + e.getMessage(), e);
            }
        }
    }

    public static class CustomPrivateKeySignature implements ExternalSignature {
        private final PrivateKey pk;
        private final String hashAlg;
        private final String provider;

        public CustomPrivateKeySignature(PrivateKey pk, String hashAlg, String provider) {
            this.pk = pk;
            this.hashAlg = hashAlg != null ? hashAlg : DigestAlgorithms.SHA256;
            this.provider = provider;
        }

        @Override
        public String getHashAlgorithm() {
            return hashAlg;
        }

        @Override
        public String getEncryptionAlgorithm() {
            return "RSA";
        }

        @Override
        public byte[] sign(byte[] message) throws GeneralSecurityException {
            try {
                byte[] prefix;
                if (DigestAlgorithms.SHA1.equalsIgnoreCase(hashAlg)) {
                    prefix = new byte[]{
                            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
                    };
                } else {
                    prefix = new byte[]{
                            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
                    };
                }

                byte[] digestInfo = new byte[prefix.length + message.length];
                System.arraycopy(prefix, 0, digestInfo, 0, prefix.length);
                System.arraycopy(message, 0, digestInfo, prefix.length, message.length);

                Cipher cipher;
                try {
                    cipher = (provider != null) ? Cipher.getInstance("RSA/ECB/PKCS1Padding", provider) : Cipher.getInstance("RSA/ECB/PKCS1Padding");
                } catch (Throwable e) {
                    cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                }
                cipher.init(Cipher.ENCRYPT_MODE, pk);
                return cipher.doFinal(digestInfo);
            } catch (Exception e) {
                throw new GeneralSecurityException("Software PrivateKey Signing Error: " + e.getMessage(), e);
            }
        }
    }

    public static String buildLayer2Text(X509Certificate cert, String reason, String location) {
        StringBuilder sb = new StringBuilder();
        sb.append("Digitally signed by:\n");

        String cn = getDNField(cert, "CN");
        sb.append("Name:- ").append(cn != null ? cn : "Authorized Signer").append("\n");

        String org = getDNField(cert, "O");
        if (org != null && !org.isEmpty()) {
            sb.append("Organization:- ").append(org).append("\n");
        }

        String country = getDNField(cert, "C");
        if (country != null && !country.isEmpty()) {
            sb.append("Country:- ").append(country).append("\n");
        }

        SimpleDateFormat sdf = new SimpleDateFormat("yyyy.MM.dd HH:mm:ss 'IST'", Locale.US);
        sdf.setTimeZone(TimeZone.getTimeZone("GMT+05:30"));
        sb.append("Date:- ").append(sdf.format(new Date())).append("\n");

        if (reason != null && !reason.trim().isEmpty()) {
            sb.append("Reason:- ").append(reason.trim()).append("\n");
        }

        if (location != null && !location.trim().isEmpty()) {
            sb.append("Location:- ").append(location.trim()).append("\n");
        }

        return sb.toString();
    }

    public static String getDNField(X509Certificate cert, String fieldName) {
        if (cert == null || cert.getSubjectDN() == null) return null;
        String dn = cert.getSubjectDN().getName();
        if (dn == null || dn.isEmpty()) return null;

        if ("CN".equalsIgnoreCase(fieldName)) {
            return CertificateManager.extractCommonName(dn);
        }

        String fieldUpper = fieldName.toUpperCase();
        String prefix1 = fieldUpper + "=";
        String prefix2 = "";
        switch (fieldUpper) {
            case "L": prefix2 = "2.5.4.7="; break;
            case "ST": prefix2 = "2.5.4.8="; break;
            case "C": prefix2 = "2.5.4.6="; break;
            case "CN": prefix2 = "2.5.4.3="; break;
            case "O": prefix2 = "2.5.4.10="; break;
            case "OU": prefix2 = "2.5.4.11="; break;
        }

        String[] split = dn.split(",");
        for (String x : split) {
            String trimmed = x.trim();
            String upper = trimmed.toUpperCase();
            if (upper.startsWith(prefix1)) {
                return trimmed.substring(prefix1.length()).trim();
            }
            if (!prefix2.isEmpty() && upper.startsWith(prefix2)) {
                return trimmed.substring(prefix2.length()).trim();
            }
        }
        return null;
    }

    public static byte[] signPdfWithAreas(
            byte[] inputPdfBytes,
            ExternalSignature externalSignature,
            Certificate[] chain,
            X509Certificate signerCert,
            List<SignatureArea> areas,
            String reason,
            String location
    ) throws Exception {
        if (inputPdfBytes == null || inputPdfBytes.length == 0) {
            throw new Exception("Input PDF bytes cannot be empty");
        }
        if (areas == null || areas.isEmpty()) {
            throw new Exception("At least one signature area is required");
        }

        byte[] currentBytes = inputPdfBytes;

        for (int i = 0; i < areas.size(); i++) {
            SignatureArea area = areas.get(i);

            PdfReader reader = new PdfReader(currentBytes);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            // Append mode: preserve existing content and signatures
            PdfStamper stamper = PdfStamper.createSignature(reader, baos, '\0', null, true);
            PdfSignatureAppearance appearance = stamper.getSignatureAppearance();

            Calendar signDate = Calendar.getInstance(TimeZone.getTimeZone("GMT+05:30"));
            appearance.setSignDate(signDate);

            if (reason != null && !reason.trim().isEmpty()) {
                appearance.setReason(reason.trim());
            }
            if (location != null && !location.trim().isEmpty()) {
                appearance.setLocation(location.trim());
            }

            Rectangle rect = area.toRectangle();
            String sigFieldName = "ABInfo_Signature_" + (i + 1) + "_" + System.currentTimeMillis();
            appearance.setVisibleSignature(rect, Math.max(1, area.pageNum), sigFieldName);

            // Render visible text layer
            appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.DESCRIPTION);
            String layer2Text = buildLayer2Text(signerCert, reason, location);
            appearance.setLayer2Text(layer2Text);

            ExternalDigest digest = new BouncyCastleDigest();
            MakeSignature.signDetached(
                    appearance,
                    digest,
                    externalSignature,
                    chain,
                    null,
                    null,
                    null,
                    20000, // Reserve 20k bytes for cryptographic signature
                    MakeSignature.CryptoStandard.CMS
            );

            reader.close();
            currentBytes = baos.toByteArray();
        }

        return currentBytes;
    }

    public static File signPdfFile(
            Context context,
            File inputFile,
            File outputFile,
            String certAlias,
            String pin,
            String reason,
            String location,
            List<SignatureArea> areas
    ) throws Exception {
        byte[] inputBytes = readFileToByteArray(inputFile);

        // If no areas specified, default to 1 signature on the last page at BOTTOM_RIGHT
        if (areas == null || areas.isEmpty()) {
            areas = new ArrayList<>();
            PdfReader reader = new PdfReader(inputBytes);
            int totalPages = reader.getNumberOfPages();
            Rectangle rect = calculateRectangle(reader, totalPages, Position.BOTTOM_RIGHT, 150f, 50f);
            areas.add(new SignatureArea(totalPages, rect.getLeft(), rect.getBottom(), rect.getWidth(), rect.getHeight()));
            reader.close();
        }

        byte[] signedBytes = signPdfWithResolvedCert(context, inputBytes, certAlias, pin, reason, location, areas);

        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
            fos.write(signedBytes);
            fos.flush();
        }

        return outputFile;
    }

    public static File signPdfFile(
            Context context,
            File inputFile,
            File outputFile,
            String certAlias,
            String pin,
            String reason,
            String location
    ) throws Exception {
        return signPdfFile(context, inputFile, outputFile, certAlias, pin, reason, location, null);
    }

    public static byte[] signPdf(
            Context context,
            byte[] pdfBytes,
            String certAlias,
            String pin,
            String reason,
            String location
    ) throws Exception {
        List<SignatureArea> areas = new ArrayList<>();
        PdfReader reader = new PdfReader(pdfBytes);
        int totalPages = reader.getNumberOfPages();
        Rectangle rect = calculateRectangle(reader, totalPages, Position.BOTTOM_RIGHT, 150f, 50f);
        areas.add(new SignatureArea(totalPages, rect.getLeft(), rect.getBottom(), rect.getWidth(), rect.getHeight()));
        reader.close();

        return signPdfWithResolvedCert(context, pdfBytes, certAlias, pin, reason, location, areas);
    }

    private static byte[] signPdfWithResolvedCert(
            Context context,
            byte[] pdfBytes,
            String certAlias,
            String pin,
            String reason,
            String location,
            List<SignatureArea> areas
    ) throws Exception {
        boolean tokenConnected = UsbTokenManager.isHardwareTokenConnected(context);
        boolean isTokenAlias = certAlias != null && (
                certAlias.startsWith("USB_") || certAlias.startsWith("PKCS11") || certAlias.startsWith("CCID") || certAlias.contains("Token")
        );

        // 1. Try Hardware USB Token if attached or requested
        if (tokenConnected || isTokenAlias) {
            // 1a. Try PKCS#11 (Feitian / InnaIT)
            try {
                CcidTokenDriver.DetectedToken dt = CcidTokenDriver.scanForToken(context);
                int vid = (dt != null) ? dt.vendorId : 0;
                boolean initOk = P11Operation.p11initialize(context, vid);
                if (initOk) {
                    try {
                        if (0 == P11Operation.getSlotInfo()) {
                            P11Operation.openSession();
                        }
                    } catch (Throwable ignored) {}
                    if (pin != null && !pin.isEmpty()) {
                        try { P11Operation.loginUser(pin); } catch (Throwable ignored) {}
                    }
                    javax.security.cert.X509Certificate[] p11Certs = P11Operation.getAllX509Certificate();
                    if (p11Certs != null && p11Certs.length > 0) {
                        javax.security.cert.X509Certificate targetCert = p11Certs[0];
                        for (javax.security.cert.X509Certificate tc : p11Certs) {
                            if (CertificateManager.isClientCert(tc)) {
                                targetCert = tc;
                                break;
                            }
                        }
                        long[] keyHandle = P11Operation.getCertificateKeyHandle(targetCert);
                        if (keyHandle != null && keyHandle.length >= 2) {
                            X509Certificate stdCert = convertToX509Certificate(targetCert);
                            Certificate[] chain = new Certificate[]{stdCert};
                            ExternalSignature sig = new PKCS11ExternalSignature(keyHandle[1], DigestAlgorithms.SHA256);
                            Log.i(TAG, "Signing with Hardware PKCS#11 Token: " + stdCert.getSubjectDN().getName());
                            return signPdfWithAreas(pdfBytes, sig, chain, stdCert, areas, reason, location);
                        }
                    }
                }
            } catch (Throwable t) {
                Log.w(TAG, "PKCS11 token sign notice: " + t.getMessage());
            }

            // 1b. Try Direct CCID APDU signing (mToken / ProxKey / SafeNet / CCID)
            try {
                List<CcidTokenDriver.CcidCertInfo> ccidCerts = CcidTokenDriver.readCertificatesViaCcid(context, pin);
                if (ccidCerts != null && !ccidCerts.isEmpty()) {
                    CcidTokenDriver.CcidCertInfo ci = ccidCerts.get(0);
                    if (ci.x509Cert != null) {
                        Certificate[] chain = new Certificate[]{ci.x509Cert};
                        ExternalSignature sig = new CcidExternalSignature(context, pin, DigestAlgorithms.SHA256);
                        Log.i(TAG, "Signing with Hardware CCID Token: " + ci.x509Cert.getSubjectDN().getName());
                        return signPdfWithAreas(pdfBytes, sig, chain, ci.x509Cert, areas, reason, location);
                    }
                }
            } catch (Throwable t) {
                Log.w(TAG, "CCID token sign notice: " + t.getMessage());
            }
        }

        // 2. Software Certificate (.p12 / .pfx)
        CertificateManager.ensureDefaultCertificate(context);
        List<File> files = CertificateManager.getAllCertificateFiles(context);

        File targetP12 = null;
        if (files != null && !files.isEmpty()) {
            for (File f : files) {
                if (certAlias != null && (f.getName().equalsIgnoreCase(certAlias) || f.getAbsolutePath().equalsIgnoreCase(certAlias))) {
                    targetP12 = f;
                    break;
                }
            }
            if (targetP12 == null) {
                // Find first non-default user cert
                for (File f : files) {
                    if (!f.getName().equalsIgnoreCase("default_abinfo_dsc.p12")) {
                        targetP12 = f;
                        break;
                    }
                }
            }
            if (targetP12 == null) {
                targetP12 = files.get(0);
            }
        }

        if (targetP12 == null || !targetP12.exists()) {
            targetP12 = CertificateManager.getLastCertFile(context);
        }

        if (targetP12 != null && targetP12.exists()) {
            char[] passChars = (pin != null) ? pin.toCharArray() : new char[0];
            char[][] tryPasswords = new char[][]{
                    passChars,
                    new char[]{'1', '2', '3', '4'},
                    new char[]{'1', '2', '3', '4', '5', '6', '7', '8'},
                    new char[0]
            };

            for (char[] pwd : tryPasswords) {
                try {
                    KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
                    try (FileInputStream fis = new FileInputStream(targetP12)) {
                        ks.load(fis, pwd);
                    } catch (Throwable e) {
                        ks = KeyStore.getInstance("PKCS12");
                        try (FileInputStream fis = new FileInputStream(targetP12)) {
                            ks.load(fis, pwd);
                        }
                    }

                    Enumeration<String> aliases = ks.aliases();
                    while (aliases.hasMoreElements()) {
                        String a = aliases.nextElement();
                        if (ks.isKeyEntry(a)) {
                            PrivateKey pk = (PrivateKey) ks.getKey(a, pwd);
                            Certificate[] chain = ks.getCertificateChain(a);
                            if (pk != null && chain != null && chain.length > 0) {
                                X509Certificate x509Cert = (X509Certificate) chain[0];
                                ExternalSignature extSig = new CustomPrivateKeySignature(pk, DigestAlgorithms.SHA256, "BC");
                                Log.i(TAG, "Signing with P12 Certificate: " + x509Cert.getSubjectDN().getName());
                                return signPdfWithAreas(pdfBytes, extSig, chain, x509Cert, areas, reason, location);
                            }
                        }
                    }
                } catch (Throwable ignored) {}
            }
        }

        throw new Exception("No valid digital certificate found to sign the PDF document.");
    }

    private static X509Certificate convertToX509Certificate(javax.security.cert.X509Certificate javaxCert) throws Exception {
        byte[] encoded = javaxCert.getEncoded();
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(encoded));
    }

    private static byte[] readFileToByteArray(File file) throws Exception {
        try (FileInputStream fis = new FileInputStream(file);
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            byte[] buf = new byte[8192];
            int r;
            while ((r = fis.read(buf)) != -1) {
                baos.write(buf, 0, r);
            }
            return baos.toByteArray();
        }
    }
}
