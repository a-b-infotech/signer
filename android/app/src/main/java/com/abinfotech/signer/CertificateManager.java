package com.abinfotech.signer;

import android.content.Context;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FilenameFilter;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class CertificateManager {
    public static File getCertDir(Context context) {
        File dir = new File(context.getFilesDir(), "certificates");
        if (!dir.exists()) dir.mkdirs();
        return dir;
    }

    public static String importCertificate(Context context, InputStream inStream, String fileName) throws Exception {
        File dir = getCertDir(context);
        File destFile = new File(dir, fileName);
        FileOutputStream fos = new FileOutputStream(destFile);
        byte[] buffer = new byte[4096];
        int read;
        while ((read = inStream.read(buffer)) != -1) {
            fos.write(buffer, 0, read);
        }
        fos.flush();
        fos.close();
        inStream.close();
        return destFile.getAbsolutePath();
    }

    public static JSONArray listCertificatesJson(Context context, String password) {
        JSONArray arr = new JSONArray();
        File dir = getCertDir(context);
        File[] files = dir.listFiles(new FilenameFilter() {
            @Override
            public boolean accept(File d, String name) {
                return name.endsWith(".pfx") || name.endsWith(".p12");
            }
        });
        if (files != null) {
            for (File f : files) {
                try {
                    KeyStore ks = KeyStore.getInstance("PKCS12");
                    char[] passChars = (password != null) ? password.toCharArray() : new char[0];
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
                                arr.put(obj);
                            }
                        }
                    }
                } catch (Exception e) {
                    try {
                        JSONObject fallback = new JSONObject();
                        fallback.put("alias", f.getName());
                        fallback.put("subject", "CN=" + f.getName());
                        fallback.put("source", "Software Certificate (.pfx/.p12)");
                        fallback.put("file_path", f.getAbsolutePath());
                        arr.put(fallback);
                    } catch (Exception ignored) {}
                }
            }
        }
        return arr;
    }

    public static int getCertCount(Context context) {
        File dir = getCertDir(context);
        File[] files = dir.listFiles(new FilenameFilter() {
            @Override
            public boolean accept(File d, String name) {
                return name.endsWith(".pfx") || name.endsWith(".p12");
            }
        });
        return files != null ? files.length : 0;
    }
}