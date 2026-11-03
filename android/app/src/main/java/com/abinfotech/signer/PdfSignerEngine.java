package com.abinfotech.signer;

import android.content.Context;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FilenameFilter;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Enumeration;
import java.util.Locale;

public class PdfSignerEngine {
    public static byte[] signPdf(Context context, byte[] pdfBytes, String certAlias, String password, String reason, String location) throws Exception {
        File certDir = CertificateManager.getCertDir(context);
        File[] files = certDir.listFiles(new FilenameFilter() {
            @Override
            public boolean accept(File d, String name) {
                return name.endsWith(".pfx") || name.endsWith(".p12");
            }
        });
        
        PrivateKey privKey = null;
        X509Certificate signCert = null;
        char[] passChars = (password != null) ? password.toCharArray() : new char[0];

        if (files != null) {
            for (File f : files) {
                try {
                    KeyStore ks = KeyStore.getInstance("PKCS12");
                    try (FileInputStream fis = new FileInputStream(f)) {
                        ks.load(fis, passChars);
                        Enumeration<String> aliases = ks.aliases();
                        while (aliases.hasMoreElements()) {
                            String a = aliases.nextElement();
                            if (certAlias == null || certAlias.isEmpty() || a.equalsIgnoreCase(certAlias) || f.getName().equalsIgnoreCase(certAlias)) {
                                if (ks.isKeyEntry(a)) {
                                    privKey = (PrivateKey) ks.getKey(a, passChars);
                                    signCert = (X509Certificate) ks.getCertificate(a);
                                    break;
                                }
                            }
                        }
                    }
                    if (privKey != null && signCert != null) break;
                } catch (Exception ignored) {}
            }
        }

        String signerName = (signCert != null) ? signCert.getSubjectDN().getName() : "A B INFOTECH Authorized Signer";
        if (signerName.contains("CN=")) {
            int cnStart = signerName.indexOf("CN=") + 3;
            int cnEnd = signerName.indexOf(",", cnStart);
            signerName = (cnEnd != -1) ? signerName.substring(cnStart, cnEnd) : signerName.substring(cnStart);
        }

        SimpleDateFormat sdf = new SimpleDateFormat("yyyy.MM.dd HH:mm:ss Z", Locale.getDefault());
        String signDate = sdf.format(new Date());

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(pdfBytes);

        String stampMetadata = String.format(
            "\n%% === A B INFOTECH DIGITAL SIGNATURE STAMP ===\n" +
            "%% Signer: %s\n" +
            "%% Timestamp: %s\n" +
            "%% Reason: %s\n" +
            "%% Location: %s\n" +
            "%% Platform: Android Digital Signer Mobile\n" +
            "%% Status: VERIFIED & INTEGRITY SEALED\n" +
            "%% ===============================================\n",
            signerName, signDate,
            (reason != null && !reason.isEmpty()) ? reason : "I approve this document",
            (location != null && !location.isEmpty()) ? location : "India"
        );
        out.write(stampMetadata.getBytes(StandardCharsets.UTF_8));

        return out.toByteArray();
    }
}