package com.abinfotech.signer;

import android.content.Context;
import android.os.Environment;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FilenameFilter;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class CertificateManager {

    private static final String LAST_CERT_FILE = "last_cert.p12";

    public static File getCertDir(Context context) {
        File dir = new File(context.getFilesDir(), "certificates");
        if (!dir.exists()) dir.mkdirs();
        return dir;
    }

    public static String importCertificate(Context context, InputStream inStream, String fileName) throws Exception {
        File dir = getCertDir(context);
        File destFile = new File(dir, fileName);
        try (FileOutputStream fos = new FileOutputStream(destFile)) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = inStream.read(buffer)) != -1) {
                fos.write(buffer, 0, read);
            }
            fos.flush();
        } finally {
            try { inStream.close(); } catch (Exception ignored) {}
        }

        // Also save as last active cert for immediate auto-use
        saveAsLastCert(context, destFile);

        return destFile.getAbsolutePath();
    }

    public static void saveAsLastCert(Context context, File srcFile) {
        try {
            File lastFile = new File(context.getFilesDir(), LAST_CERT_FILE);
            try (FileInputStream fis = new FileInputStream(srcFile);
                 FileOutputStream fos = new FileOutputStream(lastFile)) {
                byte[] buffer = new byte[8192];
                int len;
                while ((len = fis.read(buffer)) != -1) {
                    fos.write(buffer, 0, len);
                }
                fos.flush();
            }
        } catch (Exception ignored) {}
    }

    public static File getLastCertFile(Context context) {
        File lastFile = new File(context.getFilesDir(), LAST_CERT_FILE);
        return lastFile.exists() && lastFile.length() > 0 ? lastFile : null;
    }

    public static List<File> getAllCertificateFiles(Context context) {
        List<File> result = new ArrayList<>();
        Set<String> seenPaths = new HashSet<>();

        FilenameFilter pfxFilter = new FilenameFilter() {
            @Override
            public boolean accept(File d, String name) {
                String lower = name.toLowerCase();
                return lower.endsWith(".pfx") || lower.endsWith(".p12");
            }
        };

        // 1. Internal certificates directory
        File dir = getCertDir(context);
        File[] files = dir.listFiles(pfxFilter);
        if (files != null) {
            for (File f : files) {
                if (f.isFile() && seenPaths.add(f.getAbsolutePath())) {
                    result.add(f);
                }
            }
        }

        // 2. Internal app files root (e.g. last_cert.p12)
        File rootFilesDir = context.getFilesDir();
        if (rootFilesDir != null) {
            File[] rootFiles = rootFilesDir.listFiles(pfxFilter);
            if (rootFiles != null) {
                for (File f : rootFiles) {
                    if (f.isFile() && seenPaths.add(f.getAbsolutePath())) {
                        result.add(f);
                    }
                }
            }
        }

        // 3. Downloads directory
        try {
            File downloads = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
            if (downloads != null && downloads.exists()) {
                File[] downFiles = downloads.listFiles(pfxFilter);
                if (downFiles != null) {
                    for (File f : downFiles) {
                        if (f.isFile() && seenPaths.add(f.getAbsolutePath())) {
                            result.add(f);
                        }
                    }
                }
            }
        } catch (Throwable ignored) {}

        // 4. Documents directory
        try {
            File docs = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS);
            if (docs != null && docs.exists()) {
                File[] docFiles = docs.listFiles(pfxFilter);
                if (docFiles != null) {
                    for (File f : docFiles) {
                        if (f.isFile() && seenPaths.add(f.getAbsolutePath())) {
                            result.add(f);
                        }
                    }
                }
            }
        } catch (Throwable ignored) {}

        return result;
    }

    public static JSONArray listCertificatesJson(Context context, String password) {
        JSONArray arr = new JSONArray();
        char[] passChars = (password != null && !password.isEmpty()) ? password.toCharArray() : new char[0];

        // 1. Hardware USB Token Certificates (if connected)
        try {
            if (UsbTokenManager.isHardwareTokenConnected(context)) {
                try {
                    P11Operation.p11initialize(context.getApplicationContext());
                    if (0 == P11Operation.getSlotInfo()) {
                        P11Operation.openSession();
                        javax.security.cert.X509Certificate[] tokenCerts = P11Operation.getAllX509Certificate();
                        if (tokenCerts != null && tokenCerts.length > 0) {
                            for (int i = 0; i < tokenCerts.length; i++) {
                                javax.security.cert.X509Certificate tc = tokenCerts[i];
                                JSONObject obj = new JSONObject();
                                obj.put("alias", "USB_Token_Slot0_Cert_" + i);
                                obj.put("subject", tc.getSubjectDN().getName());
                                obj.put("issuer", tc.getIssuerDN().getName());
                                obj.put("source", "USB Token (PKCS#11 Hardware)");
                                obj.put("file_path", "PKCS11://token/cert/" + i);
                                obj.put("is_hardware_token", true);
                                arr.put(obj);
                            }
                        }
                    }
                } catch (Throwable t) {
                    // Token reading fallback
                }
            }
        } catch (Throwable ignored) {}

        // 2. Software Certificates (.pfx / .p12)
        List<File> certFiles = getAllCertificateFiles(context);
        for (File f : certFiles) {
            boolean loadedWithKey = false;
            try {
                KeyStore ks = KeyStore.getInstance("PKCS12");
                try (FileInputStream fis = new FileInputStream(f)) {
                    ks.load(fis, passChars);
                    Enumeration<String> aliases = ks.aliases();
                    while (aliases.hasMoreElements()) {
                        String alias = aliases.nextElement();
                        if (ks.isKeyEntry(alias)) {
                            X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
                            JSONObject obj = new JSONObject();
                            obj.put("alias", alias);
                            obj.put("subject", cert.getSubjectDN().getName());
                            obj.put("issuer", cert.getIssuerDN().getName());
                            obj.put("source", f.getName());
                            obj.put("file_path", f.getAbsolutePath());
                            obj.put("is_hardware_token", false);
                            arr.put(obj);
                            loadedWithKey = true;
                        }
                    }
                }
            } catch (Exception e) {
                // If wrong password or generic load, still register file entry so user sees it
            }

            if (!loadedWithKey) {
                try {
                    JSONObject fallback = new JSONObject();
                    fallback.put("alias", f.getName());
                    fallback.put("subject", "CN=" + f.getName());
                    fallback.put("issuer", "Local Software KeyStore");
                    fallback.put("source", f.getName());
                    fallback.put("file_path", f.getAbsolutePath());
                    fallback.put("is_hardware_token", false);
                    arr.put(fallback);
                } catch (Exception ignored) {}
            }
        }

        return arr;
    }

    public static int getCertCount(Context context) {
        int count = getAllCertificateFiles(context).size();
        if (UsbTokenManager.isHardwareTokenConnected(context)) {
            count += 1;
        }
        return count;
    }
}
