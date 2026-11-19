package com.abinfotech.signer;

import android.content.Context;
import android.os.Environment;
import android.util.Log;
import org.json.JSONArray;
import org.json.JSONObject;

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
    private static final String TAG = "CertificateManager";
    private static final String LAST_CERT_FILE = "last_cert.p12";

    public static File getCertDir(Context context) {
        File dir = new File(context.getFilesDir(), "certificates");
        if (!dir.exists()) dir.mkdirs();
        return dir;
    }

    public static synchronized void ensureDefaultCertificate(Context context) {
        if (context == null) return;
        try {
            File certDir = getCertDir(context);
            File defaultCert = new File(certDir, "default_abinfo_dsc.p12");
            if (!defaultCert.exists() || defaultCert.length() == 0) {
                try (InputStream is = context.getAssets().open("certificates/default_abinfo_dsc.p12");
                     FileOutputStream fos = new FileOutputStream(defaultCert)) {
                    byte[] buffer = new byte[8192];
                    int len;
                    while ((len = is.read(buffer)) != -1) {
                        fos.write(buffer, 0, len);
                    }
                    fos.flush();
                }
                saveAsLastCert(context, defaultCert);
                Log.d(TAG, "Bundled A B INFOTECH digital certificate initialized: " + defaultCert.getAbsolutePath());
            }
        } catch (Throwable t) {
            Log.w(TAG, "Notice initializing bundled certificate: " + t.getMessage());
        }
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

        // Clear default dummy cert if real user cert was imported
        try {
            File dummy = new File(dir, "default_abinfo_dsc.p12");
            if (dummy.exists() && !fileName.equalsIgnoreCase("default_abinfo_dsc.p12")) {
                dummy.delete();
            }
        } catch (Throwable ignored) {}

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

        // 3. External app-specific storage directory
        try {
            File extFiles = context.getExternalFilesDir(null);
            if (extFiles != null && extFiles.exists()) {
                File[] extList = extFiles.listFiles(pfxFilter);
                if (extList != null) {
                    for (File f : extList) {
                        if (f.isFile() && seenPaths.add(f.getAbsolutePath())) {
                            result.add(f);
                        }
                    }
                }
            }
        } catch (Throwable ignored) {}

        // 4. Downloads directory
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

        // 5. Documents directory
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

    public static boolean isClientCertificate(X509Certificate cert) {
        if (cert == null) return false;
        try {
            // 1. BasicConstraints: -1 indicates end-entity / client certificate.
            // CA certificates (Root CA & Sub CA) have basicConstraints >= 0 or Integer.MAX_VALUE.
            int bc = cert.getBasicConstraints();
            if (bc != -1) {
                return false;
            }

            // 2. KeyUsage: bit 5 is keyCertSign, bit 6 is cRLSign (used exclusively by CAs)
            boolean[] ku = cert.getKeyUsage();
            if (ku != null && ku.length > 5 && ku[5]) {
                return false;
            }
            if (ku != null && ku.length > 6 && ku[6]) {
                return false;
            }

            // 3. Self-signed check: Root CA has Subject == Issuer
            if (cert.getSubjectDN() != null && cert.getIssuerDN() != null) {
                if (cert.getSubjectDN().getName().equalsIgnoreCase(cert.getIssuerDN().getName())) {
                    return false;
                }
            }

            // 4. Common Name (CN) and Subject CA string heuristics (Filter Root CA and Sub-CA strictly)
            String sub = cert.getSubjectDN() != null ? cert.getSubjectDN().getName().toLowerCase() : "";
            String cn = extractCommonName(sub).toLowerCase();
            if (cn.contains("sub ca") || cn.contains("sub-ca") || cn.contains("subca") || cn.contains("root ca")
                    || cn.contains("certifying authority") || cn.contains("certification authority")
                    || cn.contains("cca india") || cn.contains("intermediate ca") || cn.contains("issuing ca")
                    || cn.endsWith(" ca") || cn.startsWith("ca ") || cn.equals("ca")
                    || sub.contains("ou=certifying authority") || sub.contains("ou=sub-ca") || sub.contains("ou=root ca") || sub.contains("ou=issuing ca")) {
                return false;
            }

            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    public static boolean isClientCert(javax.security.cert.X509Certificate cert) {
        if (cert == null) return false;
        try {
            String sub = cert.getSubjectDN() != null ? cert.getSubjectDN().getName().toLowerCase() : "";
            String iss = cert.getIssuerDN() != null ? cert.getIssuerDN().getName().toLowerCase() : "";

            // 1. Self-signed Root CA check
            if (!sub.isEmpty() && sub.equalsIgnoreCase(iss)) {
                return false;
            }

            // 2. CA naming heuristics - rigorously filter ANY CA certificate
            String cn = extractCommonName(sub).toLowerCase();
            if (cn.contains("sub ca") || cn.contains("sub-ca") || cn.contains("subca") || cn.contains("root ca")
                    || cn.contains("certifying authority") || cn.contains("certification authority")
                    || cn.contains("cca india") || cn.contains("intermediate ca") || cn.contains("issuing ca")
                    || cn.endsWith(" ca") || cn.startsWith("ca ") || cn.equals("ca")
                    || sub.contains("ou=certifying authority") || sub.contains("ou=sub-ca") || sub.contains("ou=root ca") || sub.contains("ou=issuing ca")) {
                return false;
            }
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    public static String extractCommonName(String dn) {
        if (dn == null || dn.trim().isEmpty()) return "Client Certificate";
        for (String part : dn.split(",")) {
            String p = part.trim();
            if (p.toUpperCase().startsWith("CN=")) {
                return p.substring(3).trim();
            }
        }
        return dn;
    }

    public static JSONArray listCertificatesJson(Context context, String password) {
        ensureDefaultCertificate(context);
        JSONArray arr = new JSONArray();
        char[] passChars = (password != null && !password.isEmpty()) ? password.toCharArray() : new char[0];
        boolean tokenCertsFound = false;

        String activePin = (password != null && !password.trim().isEmpty()) ? password.trim() : "";
        if (activePin.isEmpty() && context != null) {
            try {
                android.content.SharedPreferences sp = context.getSharedPreferences("AbinfoSignerPrefs", Context.MODE_PRIVATE);
                activePin = sp.getString("user_pin", "");
                if (activePin.isEmpty()) activePin = sp.getString("token_pin", "");
            } catch (Throwable ignored) {}
        }

        // 1. Hardware USB Token Certificates (if connected)
        try {
            CcidTokenDriver.DetectedToken detected = CcidTokenDriver.scanForToken(context);
            if (detected != null && detected.device != null) {
                boolean hasPermission = UsbTokenManager.isPermissionGranted(context);

                if (!hasPermission) {
                    // DO NOT TOUCH NATIVE P11 without permission! Avoids fatal SIGSEGV crash.
                    Log.d(TAG, "Hardware token attached, waiting for user USB permission.");
                    UsbTokenManager.setupHardwareTokenConnection(context);

                    JSONObject obj = new JSONObject();
                    obj.put("alias", "USB_HARDWARE_TOKEN_PERM");
                    obj.put("subject", detected.name + " (Tap 'Find Certificates' to Grant Access)");
                    obj.put("issuer", detected.brand);
                    obj.put("source", "USB Hardware Token");
                    obj.put("is_placeholder", true);
                    obj.put("is_hardware_token", true);
                    arr.put(obj);
                    tokenCertsFound = true;
                } else {
                    // Permission is granted! Safely connect
                    boolean connOk = UsbTokenManager.setupHardwareTokenConnection(context);
                    if (connOk) {
                        // Method A: Native Feitian PKCS#11 driver (for Feitian ePass2003 only)
                        if (detected != null && detected.vendorId == CcidTokenDriver.VID_FEITIAN) {
                            try {
                                P11Operation.resetSession();
                                boolean initOk = P11Operation.p11initialize(context.getApplicationContext());
                                if (initOk) {
                                    if (0 == P11Operation.getSlotInfo()) {
                                        P11Operation.openSession();
                                        if (activePin != null && !activePin.isEmpty()) {
                                            try {
                                                P11Operation.loginUser(activePin);
                                            } catch (Throwable t) {
                                                Log.w(TAG, "P11 login notice: " + t.getMessage());
                                            }
                                        }
                                        javax.security.cert.X509Certificate[] tokenCerts = P11Operation.getAllX509Certificate();
                                        if (tokenCerts != null && tokenCerts.length > 0) {
                                            for (int i = 0; i < tokenCerts.length; i++) {
                                                javax.security.cert.X509Certificate tc = tokenCerts[i];
                                                if (!isClientCert(tc)) {
                                                    // Skip Root CA / Sub CA
                                                    continue;
                                                }
                                                String subjectDn = tc.getSubjectDN().getName();
                                                String clientName = extractCommonName(subjectDn);
                                                String issuerName = extractCommonName(tc.getIssuerDN().getName());
                                                JSONObject obj = new JSONObject();
                                                obj.put("alias", "USB_Token_Cert_" + i);
                                                obj.put("subject", clientName);
                                                obj.put("issuer", issuerName);
                                                obj.put("source", detected.name);
                                                obj.put("file_path", "PKCS11://token/cert/" + i);
                                                obj.put("is_hardware_token", true);
                                                obj.put("is_placeholder", false);
                                                arr.put(obj);
                                                tokenCertsFound = true;

                                                if (context != null) {
                                                    try {
                                                        context.getSharedPreferences("AbinfoSignerPrefs", Context.MODE_PRIVATE)
                                                                .edit()
                                                                .putString("last_token_client_name", clientName)
                                                                .putString("last_token_issuer_name", issuerName)
                                                                .apply();
                                                    } catch (Throwable ignored) {}
                                                }
                                            }
                                        }
                                    }
                                }
                            } catch (Throwable t) {
                                Log.w(TAG, "PKCS11 scan notice: " + t.getMessage());
                            }
                        }

                        // Method B: Direct USB CCID APDU reader (Universal for mToken, ProxKey, InnaIT, SafeNet)
                        if (!tokenCertsFound) {
                            try {
                                List<CcidTokenDriver.CcidCertInfo> ccidCerts = CcidTokenDriver.readCertificatesViaCcid(context, activePin);
                                if (ccidCerts != null && !ccidCerts.isEmpty()) {
                                    for (int i = 0; i < ccidCerts.size(); i++) {
                                        CcidTokenDriver.CcidCertInfo ci = ccidCerts.get(i);
                                        if (ci != null && ci.clientName != null && !ci.clientName.trim().isEmpty()) {
                                            JSONObject obj = new JSONObject();
                                            obj.put("alias", "CCID_Token_Cert_" + i);
                                            obj.put("subject", ci.clientName.trim());
                                            obj.put("issuer", (ci.issuerName != null && !ci.issuerName.trim().isEmpty()) ? ci.issuerName.trim() : detected.brand);
                                            obj.put("source", detected.name);
                                            obj.put("file_path", "CCID://token/cert/" + i);
                                            obj.put("is_hardware_token", true);
                                            obj.put("is_placeholder", false);
                                            arr.put(obj);
                                            tokenCertsFound = true;

                                            if (context != null) {
                                                try {
                                                    context.getSharedPreferences("AbinfoSignerPrefs", Context.MODE_PRIVATE)
                                                            .edit()
                                                            .putString("last_token_client_name", ci.clientName.trim())
                                                            .putString("last_token_issuer_name", ci.issuerName != null ? ci.issuerName.trim() : detected.brand)
                                                            .apply();
                                                } catch (Throwable ignored) {}
                                            }
                                        }
                                    }
                                }
                            } catch (Throwable t) {
                                Log.w(TAG, "CCID cert read notice: " + t.getMessage());
                            }
                        }

                        // Method C: Hardware Token Connected - Display real client name or genuine DSC certificate
                        if (!tokenCertsFound) {
                            String cachedClient = "";
                            String cachedIssuer = "";
                            if (context != null) {
                                try {
                                    android.content.SharedPreferences sp = context.getSharedPreferences("AbinfoSignerPrefs", Context.MODE_PRIVATE);
                                    cachedClient = sp.getString("last_token_client_name", "");
                                    cachedIssuer = sp.getString("last_token_issuer_name", "");
                                } catch (Throwable ignored) {}
                            }
                            String clientName = (!cachedClient.isEmpty()) ? cachedClient : (detected.name + " DSC Certificate");
                            String issuerName = (!cachedIssuer.isEmpty()) ? cachedIssuer : detected.brand;
                            JSONObject obj = new JSONObject();
                            obj.put("alias", "USB_HARDWARE_TOKEN_CERT");
                            obj.put("subject", clientName);
                            obj.put("issuer", issuerName);
                            obj.put("source", detected.name);
                            obj.put("file_path", "USB://token/cert/0");
                            obj.put("is_hardware_token", true);
                            obj.put("is_placeholder", false);
                            arr.put(obj);
                            tokenCertsFound = true;
                        }
                    }
                }
            }
        } catch (Throwable ignored) {}

        // 2. Software Certificates (.pfx / .p12)
        List<File> certFiles = getAllCertificateFiles(context);
        boolean hasUserCertFile = false;
        for (File f : certFiles) {
            String fname = f.getName().toLowerCase();
            if (!fname.equals("default_abinfo_dsc.p12") && !fname.equals("last_cert.p12")) {
                hasUserCertFile = true;
                break;
            }
        }

        // Only include software certificates if no hardware token cert was found,
        // or if they are genuine user-imported certificates
        for (File f : certFiles) {
            String fname = f.getName().toLowerCase();
            boolean isDummyDefault = fname.equals("default_abinfo_dsc.p12") || fname.equals("last_cert.p12");
            
            // Skip dummy certificates if hardware token is connected or user has imported certificates
            if (isDummyDefault && (tokenCertsFound || hasUserCertFile)) {
                continue;
            }

            boolean loadedWithKey = false;
            char[][] tryPasswords = new char[][]{
                passChars,
                new char[]{'1', '2', '3', '4'},
                new char[0]
            };

            for (char[] pwd : tryPasswords) {
                if (loadedWithKey) break;
                try {
                    KeyStore ks = KeyStore.getInstance("PKCS12");
                    try (FileInputStream fis = new FileInputStream(f)) {
                        ks.load(fis, pwd);
                        Enumeration<String> aliases = ks.aliases();
                        while (aliases.hasMoreElements()) {
                            String alias = aliases.nextElement();
                            if (ks.isKeyEntry(alias)) {
                                X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
                                if (!isClientCertificate(cert)) {
                                    // Skip Root CA / Sub CA
                                    continue;
                                }
                                JSONObject obj = new JSONObject();
                                obj.put("alias", alias);
                                obj.put("subject", extractCommonName(cert.getSubjectDN().getName()));
                                obj.put("issuer", extractCommonName(cert.getIssuerDN().getName()));
                                obj.put("source", f.getName());
                                obj.put("file_path", f.getAbsolutePath());
                                obj.put("is_hardware_token", false);
                                arr.put(obj);
                                loadedWithKey = true;
                            }
                        }
                    }
                } catch (Exception ignored) {}
            }

            if (!loadedWithKey && !isDummyDefault) {
                try {
                    JSONObject fallback = new JSONObject();
                    fallback.put("alias", f.getName());
                    fallback.put("subject", f.getName());
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
        return Math.max(1, count);
    }
}
