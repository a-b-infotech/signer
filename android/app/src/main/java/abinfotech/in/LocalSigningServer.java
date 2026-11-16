package abinfotech.in.server;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;
import android.util.Log;

import com.ftsafe.monitor.OTGPassToKen;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.security.cert.X509Certificate;

import abinfotech.in.signer.PdfSignerHelper;
import abinfotech.in.signer.SignatureArea;
import abinfotech.in.token.P11Operation;
import fi.iki.elonen.NanoHTTPD;

public class LocalSigningServer extends NanoHTTPD {

    private static final String TAG = "LocalSigningServer";
    public static final int PORT = 5000;
    private final Context context;
    private final Gson gson = new Gson();

    public LocalSigningServer(Context context) {
        super(PORT);
        this.context = context.getApplicationContext();
    }

    @Override
    public Response serve(IHTTPSession session) {
        String uri = session.getUri();
        Method method = session.getMethod();

        // Handle CORS OPTIONS preflight
        if (Method.OPTIONS.equals(method)) {
            Response res = newFixedLengthResponse(Response.Status.OK, "text/plain", "");
            addCorsHeaders(res);
            return res;
        }

        try {
            if ("/".equals(uri) || "/api/status".equalsIgnoreCase(uri) || "/api/health".equalsIgnoreCase(uri)) {
                return handleStatus();
            } else if ("/api/drivers".equalsIgnoreCase(uri)) {
                return handleDrivers();
            } else if ("/api/certificates".equalsIgnoreCase(uri)) {
                return handleCertificates(session);
            } else if ("/api/sign".equalsIgnoreCase(uri) && Method.POST.equals(method)) {
                return handleSignRequest(session);
            } else if ("/api/license_status".equalsIgnoreCase(uri)) {
                return handleLicenseStatus();
            } else if ("/api/activate_license".equalsIgnoreCase(uri) && Method.POST.equals(method)) {
                return handleActivateLicense(session);
            }
        } catch (Exception e) {
            Log.e(TAG, "Error handling " + uri + ": " + e.getMessage(), e);
            JsonObject err = new JsonObject();
            err.addProperty("status", "error");
            err.addProperty("message", e.getMessage());
            Response res = newFixedLengthResponse(Response.Status.INTERNAL_ERROR, "application/json", gson.toJson(err));
            addCorsHeaders(res);
            return res;
        }

        JsonObject err = new JsonObject();
        err.addProperty("status", "error");
        err.addProperty("message", "Endpoint Not Found: " + uri);
        Response res = newFixedLengthResponse(Response.Status.NOT_FOUND, "application/json", gson.toJson(err));
        addCorsHeaders(res);
        return res;
    }

    private Response handleStatus() {
        SharedPreferences prefs = context.getSharedPreferences("AbinfoPdfSignerPrefs", Context.MODE_PRIVATE);
        boolean isLicenseActive = prefs.getBoolean("is_license_active", false);
        String licenseTier = prefs.getString("license_tier", "trial");

        JsonObject res = new JsonObject();
        res.addProperty("status", "ok");
        res.addProperty("app", "A B INFOTECH DIGITAL SIGNER SUITE");
        res.addProperty("version", "2.0");
        res.addProperty("port", PORT);
        res.addProperty("token_connected", OTGPassToKen.getIsConnect() || P11Operation.session_ != -1L);
        res.addProperty("license_status", isLicenseActive ? "active" : "trial");
        res.addProperty("license_tier", licenseTier);

        Response response = newFixedLengthResponse(Response.Status.OK, "application/json", gson.toJson(res));
        addCorsHeaders(response);
        return response;
    }

    private Response handleDrivers() {
        JsonObject res = new JsonObject();
        res.addProperty("status", "success");

        JsonArray driverArray = new JsonArray();
        driverArray.add("Feitian HYP2003 / ePass2003 (PKCS#11)");
        driverArray.add("InnaIT / eGuard PKCS#11");
        driverArray.add("Software Certificate (P12/PFX)");

        res.add("drivers", driverArray);
        res.addProperty("usb_connected", OTGPassToKen.getIsConnect() || P11Operation.session_ != -1L);

        Response response = newFixedLengthResponse(Response.Status.OK, "application/json", gson.toJson(res));
        addCorsHeaders(response);
        return response;
    }

    private Response handleCertificates(IHTTPSession session) {
        JsonObject res = new JsonObject();
        JsonArray certArray = new JsonArray();

        try {
            if (P11Operation.session_ != -1L) {
                X509Certificate[] certs = P11Operation.getAllX509Certificate();
                for (int i = 0; i < certs.length; i++) {
                    X509Certificate c = certs[i];
                    java.security.cert.X509Certificate javaCert = PdfSignerHelper.convertToX509Certificate(c);
                    JsonObject cObj = new JsonObject();
                    cObj.addProperty("alias", "USB_CERT_" + (i + 1));
                    cObj.addProperty("common_name", PdfSignerHelper.getCN(javaCert));
                    cObj.addProperty("issuer", javaCert.getIssuerDN().getName());
                    cObj.addProperty("serial", javaCert.getSerialNumber().toString(16));
                    cObj.addProperty("valid_from", javaCert.getNotBefore().toString());
                    cObj.addProperty("valid_to", javaCert.getNotAfter().toString());
                    certArray.add(cObj);
                }
            }

            // Also check if local P12 is loaded
            File p12File = new File(context.getFilesDir(), "last_cert.p12");
            if (p12File.exists() && p12File.length() > 0) {
                JsonObject p12Obj = new JsonObject();
                p12Obj.addProperty("alias", "SOFTWARE_P12");
                p12Obj.addProperty("common_name", "Software PFX / P12 Certificate");
                p12Obj.addProperty("issuer", "Software File Keystore");
                p12Obj.addProperty("serial", "1");
                p12Obj.addProperty("valid_from", "Saved Offline");
                p12Obj.addProperty("valid_to", "Saved Offline");
                certArray.add(p12Obj);
            }

            res.addProperty("status", "success");
            res.add("certificates", certArray);
        } catch (Exception e) {
            res.addProperty("status", "error");
            res.addProperty("message", e.getMessage());
        }

        Response response = newFixedLengthResponse(Response.Status.OK, "application/json", gson.toJson(res));
        addCorsHeaders(response);
        return response;
    }

    private Response handleSignRequest(IHTTPSession session) throws Exception {
        Map<String, String> files = new HashMap<>();
        session.parseBody(files);

        String body = files.get("postData");
        if (body == null || body.trim().isEmpty()) {
            throw new IllegalArgumentException("Empty request body");
        }

        JsonObject req = gson.fromJson(body, JsonObject.class);
        if (!req.has("pdf_base64")) {
            throw new IllegalArgumentException("Missing 'pdf_base64' parameter.");
        }

        String pdfBase64 = req.get("pdf_base64").getAsString();
        String pin = req.has("pin") ? req.get("pin").getAsString() : "";
        String reason = req.has("reason") ? req.get("reason").getAsString() : "I approve this document";
        String location = req.has("location") ? req.get("location").getAsString() : "India";
        int page = req.has("page") ? req.get("page").getAsInt() : 1;
        float x = req.has("x") ? req.get("x").getAsFloat() : 380f;
        float y = req.has("y") ? req.get("y").getAsFloat() : 50f;
        float width = req.has("width") ? req.get("width").getAsFloat() : 140f;
        float height = req.has("height") ? req.get("height").getAsFloat() : 50f;

        byte[] inputPdfBytes = Base64.decode(pdfBase64, Base64.DEFAULT);
        File tempInput = File.createTempFile("server_in_", ".pdf", context.getCacheDir());
        try (FileOutputStream fos = new FileOutputStream(tempInput)) {
            fos.write(inputPdfBytes);
        }

        File tempOutput = File.createTempFile("server_out_", ".pdf", context.getCacheDir());
        List<SignatureArea> areas = new ArrayList<>();
        areas.add(new SignatureArea(page, x, y, width, height));

        File p12File = new File(context.getFilesDir(), "last_cert.p12");
        if (p12File.exists() && (P11Operation.session_ == -1L || req.has("use_p12"))) {
            // Software signing
            try (FileInputStream fis = new FileInputStream(p12File)) {
                PdfSignerHelper.signPdfWithP12Areas(
                        tempInput.getAbsolutePath(),
                        tempOutput.getAbsolutePath(),
                        fis,
                        pin,
                        areas,
                        reason,
                        location
                );
            }
        } else {
            // Hardware token signing
            P11Operation.loginUser(pin);
            X509Certificate[] certs = P11Operation.getAllX509Certificate();
            if (certs == null || certs.length == 0) {
                throw new IllegalStateException("No certificates found on hardware token.");
            }
            long[] keyHandle = P11Operation.getCertificateKeyHandle(certs[0]);
            if (keyHandle == null) {
                throw new IllegalStateException("Cannot find private key on hardware token.");
            }

            PdfSignerHelper.signPdfWithPkcs11Areas(
                    tempInput.getAbsolutePath(),
                    tempOutput.getAbsolutePath(),
                    certs[0],
                    keyHandle[1],
                    areas,
                    reason,
                    location
            );
        }

        byte[] signedBytes = Files.readAllBytes(tempOutput.toPath());
        String signedBase64 = Base64.encodeToString(signedBytes, Base64.NO_WRAP);

        tempInput.delete();
        tempOutput.delete();

        JsonObject res = new JsonObject();
        res.addProperty("status", "success");
        res.addProperty("message", "PDF Signed Successfully via A B INFOTECH Mobile Server");
        res.addProperty("signed_pdf_base64", signedBase64);

        Response response = newFixedLengthResponse(Response.Status.OK, "application/json", gson.toJson(res));
        addCorsHeaders(response);
        return response;
    }

    private Response handleLicenseStatus() {
        SharedPreferences prefs = context.getSharedPreferences("AbinfoPdfSignerPrefs", Context.MODE_PRIVATE);
        boolean isActive = prefs.getBoolean("is_license_active", false);
        String tier = prefs.getString("license_tier", "trial");
        String expireDate = prefs.getString("license_expire", "Demo 4-Days");

        JsonObject res = new JsonObject();
        res.addProperty("status", isActive ? "active" : "trial");
        res.addProperty("tier", tier);
        res.addProperty("expiredate", expireDate);

        Response response = newFixedLengthResponse(Response.Status.OK, "application/json", gson.toJson(res));
        addCorsHeaders(response);
        return response;
    }

    private Response handleActivateLicense(IHTTPSession session) throws Exception {
        Map<String, String> files = new HashMap<>();
        session.parseBody(files);

        String body = files.get("postData");
        JsonObject req = gson.fromJson(body, JsonObject.class);
        String key = req != null && req.has("key") ? req.get("key").getAsString().trim() : "";

        SharedPreferences prefs = context.getSharedPreferences("AbinfoPdfSignerPrefs", Context.MODE_PRIVATE);

        if ("ABI-MASTER-PASS".equalsIgnoreCase(key)) {
            prefs.edit()
                    .putBoolean("is_license_active", true)
                    .putString("license_tier", "pro")
                    .putString("license_expire", "never")
                    .putString("license_key", key)
                    .apply();

            JsonObject res = new JsonObject();
            res.addProperty("status", "active");
            res.addProperty("tier", "pro");
            res.addProperty("expiredate", "never");
            res.addProperty("message", "Master Key Activated Successfully!");
            Response response = newFixedLengthResponse(Response.Status.OK, "application/json", gson.toJson(res));
            addCorsHeaders(response);
            return response;
        }

        // Return error for empty
        if (key.isEmpty()) {
            JsonObject res = new JsonObject();
            res.addProperty("status", "invalid");
            res.addProperty("message", "License key cannot be empty.");
            Response response = newFixedLengthResponse(Response.Status.OK, "application/json", gson.toJson(res));
            addCorsHeaders(response);
            return response;
        }

        // For user keys, store and mark active
        prefs.edit()
                .putBoolean("is_license_active", true)
                .putString("license_tier", "pro")
                .putString("license_expire", "1 Year")
                .putString("license_key", key)
                .apply();

        JsonObject res = new JsonObject();
        res.addProperty("status", "active");
        res.addProperty("tier", "pro");
        res.addProperty("expiredate", "1 Year");
        res.addProperty("message", "License activated!");
        Response response = newFixedLengthResponse(Response.Status.OK, "application/json", gson.toJson(res));
        addCorsHeaders(response);
        return response;
    }

    private void addCorsHeaders(Response response) {
        response.addHeader("Access-Control-Allow-Origin", "*");
        response.addHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        response.addHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With");
    }
}
