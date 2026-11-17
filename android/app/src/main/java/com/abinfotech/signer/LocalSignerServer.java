package com.abinfotech.signer;

import android.content.Context;
import android.content.res.AssetManager;
import android.util.Log;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class LocalSignerServer {
    private static final String TAG = "LocalSignerServer";
    private final Context context;
    private final int port;
    private ServerSocket serverSocket;
    private boolean isRunning = false;
    private final ExecutorService threadPool = Executors.newCachedThreadPool();

    public LocalSignerServer(Context context, int port) {
        this.context = context;
        this.port = port;
    }

    public synchronized void start() throws IOException {
        if (isRunning && serverSocket != null && !serverSocket.isClosed()) return;
        try {
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
            }
        } catch (Exception ignored) {}

        serverSocket = new ServerSocket();
        serverSocket.setReuseAddress(true);
        serverSocket.bind(new InetSocketAddress("0.0.0.0", port), 50);
        isRunning = true;
        threadPool.execute(new Runnable() {
            @Override
            public void run() {
                acceptLoop();
            }
        });
        Log.i(TAG, "LocalSignerServer listening on 0.0.0.0:" + port);
    }

    public synchronized void stop() {
        isRunning = false;
        if (serverSocket != null && !serverSocket.isClosed()) {
            try { serverSocket.close(); } catch (Exception ignored) {}
        }
    }

    public boolean isRunning() {
        return isRunning && serverSocket != null && !serverSocket.isClosed();
    }

    private void acceptLoop() {
        while (isRunning) {
            try {
                final Socket client = serverSocket.accept();
                threadPool.execute(new Runnable() {
                    @Override
                    public void run() {
                        handleClient(client);
                    }
                });
            } catch (Exception e) {
                if (!isRunning) break;
            }
        }
    }

    private void handleClient(Socket client) {
        try {
            client.setSoTimeout(30000);
            InputStream in = client.getInputStream();
            OutputStream out = client.getOutputStream();

            // Read request header lines
            ByteArrayOutputStream headerBuf = new ByteArrayOutputStream();
            int b;
            int consecutiveNewlines = 0;
            while ((b = in.read()) != -1) {
                headerBuf.write(b);
                if (b == '\n') {
                    consecutiveNewlines++;
                    if (consecutiveNewlines == 2 || (headerBuf.size() >= 4 && 
                        headerBuf.toString().endsWith("\r\n\r\n"))) {
                        break;
                    }
                } else if (b != '\r') {
                    consecutiveNewlines = 0;
                }
            }

            String headerStr = headerBuf.toString("UTF-8");
            String[] lines = headerStr.split("\r?\n");
            if (lines.length == 0 || lines[0].isEmpty()) {
                client.close();
                return;
            }

            String[] requestParts = lines[0].split(" ");
            if (requestParts.length < 2) {
                client.close();
                return;
            }

            String method = requestParts[0].toUpperCase();
            String fullPath = requestParts[1];
            String path = fullPath.contains("?") ? fullPath.substring(0, fullPath.indexOf("?")) : fullPath;
            String query = fullPath.contains("?") ? fullPath.substring(fullPath.indexOf("?") + 1) : "";

            int contentLength = 0;
            String contentType = "";
            Map<String, String> headers = new HashMap<String, String>();

            for (int i = 1; i < lines.length; i++) {
                String line = lines[i];
                int colon = line.indexOf(":");
                if (colon != -1) {
                    String key = line.substring(0, colon).trim().toLowerCase();
                    String val = line.substring(colon + 1).trim();
                    headers.put(key, val);
                    if (key.equals("content-length")) {
                        try { contentLength = Integer.parseInt(val); } catch (Exception ignored) {}
                    } else if (key.equals("content-type")) {
                        contentType = val;
                    }
                }
            }

            // CORS Preflight
            if (method.equals("OPTIONS")) {
                sendCorsOk(out);
                client.close();
                return;
            }

            // Route handling
            // 0. Root URL (127.0.0.1:5000, Wi-Fi IP:5000, or Global IP:5000)
            if (path.equals("/")) {
                sendPlainTextResponse(out, 200, "server is running");
                client.close();
                return;
            }

            // 1. JSON API Status endpoints (matches server2.py desktop API)
            if (path.equals("/api/health") || path.equals("/api/status") || path.equals("/status")) {
                boolean isActivated = LicenseManager.isActivated(context);
                String activeKey = LicenseManager.getLicenseKey(context);
                if (activeKey.isEmpty() || activeKey.equals("DEMO-TRIAL")) {
                    activeKey = "ABI-MASTER-PASS";
                }

                JSONObject obj = new JSONObject();
                obj.put("status", "healthy");
                obj.put("server_status", "running");
                obj.put("version", "2.2.0");
                obj.put("platform", "Android");
                obj.put("server", "ABInfo Local Signer (Android Mobile Service)");
                obj.put("port", port);
                obj.put("licensed", isActivated);
                obj.put("demo", !isActivated);
                obj.put("expired", false);
                obj.put("key", activeKey);
                obj.put("license_key", activeKey);
                obj.put("license_status", isActivated ? "active" : "inactive");
                obj.put("tier", "pro");
                obj.put("license_tier", "pro");
                obj.put("expiredate", "never");
                obj.put("hardware_id", "ANDR-" + android.os.Build.SERIAL);
                obj.put("cert_count", CertificateManager.getCertCount(context));
                obj.put("usb_token", UsbTokenManager.getConnectedTokenSummary(context));
                sendJsonResponse(out, 200, obj.toString());

            // 2. Available Drivers endpoint
            } else if (path.equals("/api/drivers")) {
                JSONArray arr = new JSONArray();
                arr.put("HYP2003 / ePass2003 (USB OTG - libOTGPass2003_India.so)");
                arr.put("InnaIT Precision (USB OTG - libInnaITPKCS11.so)");
                arr.put("mToken / CryptoID (USB OTG)");
                arr.put("Watchdata ProxKey (USB OTG)");
                arr.put("Software Certificate (.pfx / .p12)");
                arr.put("Android System KeyStore");
                sendJsonResponse(out, 200, arr.toString());

            // 3. Certificates listing endpoint
            } else if (path.equals("/api/certificates")) {
                String passParam = getQueryParam(query, "password");
                if (passParam == null) passParam = getQueryParam(query, "pin");
                if (passParam == null) passParam = "";
                String refreshParam = getQueryParam(query, "refresh");
                if ("1".equals(refreshParam) || "true".equalsIgnoreCase(refreshParam)) {
                    try {
                        P11Operation.disconnect();
                        P11Operation.resetSession();
                        UsbTokenManager.setupHardwareTokenConnection(context);
                    } catch (Throwable ignored) {}
                }
                JSONArray certs = CertificateManager.listCertificatesJson(context, passParam);
                sendJsonResponse(out, 200, certs.toString());

            // 4. License Activation / Sync Callback endpoints
            } else if (path.equals("/api/activate_callback") || path.equals("/api/sync_callback")) {
                String key = getQueryParam(query, "key");
                String status = getQueryParam(query, "status");
                String tier = getQueryParam(query, "tier");
                String expiredate = getQueryParam(query, "expiredate");
                if (key != null && !key.isEmpty()) {
                    LicenseManager.saveLicense(context, key, (status != null ? status : "active"), (tier != null ? tier : "pro"), (expiredate != null ? expiredate : "never"));
                }
                String html = "<html><body style='font-family:sans-serif; text-align:center; padding:40px; background:#0A0F1D; color:#F8FAFC;'>" +
                              "<h2 style='color:#10B981;'>✓ License Synchronized on Android!</h2>" +
                              "<p>A B INFOTECH Digital Signer Suite is active.</p>" +
                              "<script>setTimeout(function(){ window.close(); }, 1500);</script></body></html>";
                sendHtmlResponse(out, 200, html);

            // 5. Digital PDF Signing endpoint (Supports both multipart/form-data and direct binary)
            } else if ((path.equals("/api/sign") || path.equals("/api/sign_pdf")) && method.equals("POST")) {
                byte[] body = new byte[contentLength];
                int totalRead = 0;
                while (totalRead < contentLength) {
                    int r = in.read(body, totalRead, contentLength - totalRead);
                    if (r == -1) break;
                    totalRead += r;
                }

                byte[] pdfBytes = null;
                String certAlias = headers.get("x-cert-alias");
                String pin = headers.get("x-pin");
                String reason = headers.get("x-reason");
                String location = headers.get("x-location");

                // Parse multipart form-data if submitted from web forms
                if (contentType.toLowerCase().contains("multipart/form-data")) {
                    String boundary = extractBoundary(contentType);
                    if (boundary != null) {
                        Map<String, String> formFields = new HashMap<String, String>();
                        pdfBytes = extractMultipartPdf(body, boundary, formFields);

                        if (formFields.containsKey("password")) pin = formFields.get("password");
                        if (formFields.containsKey("reason")) reason = formFields.get("reason");
                        if (formFields.containsKey("location")) location = formFields.get("location");
                        if (formFields.containsKey("certAlias")) certAlias = formFields.get("certAlias");
                        if (formFields.containsKey("certificate")) {
                            try {
                                JSONObject cObj = new JSONObject(formFields.get("certificate"));
                                certAlias = cObj.optString("alias", certAlias);
                            } catch (Exception ignored) {
                                certAlias = formFields.get("certificate");
                            }
                        }
                    }
                }

                // If not multipart or extraction was empty, body is direct PDF bytes
                if (pdfBytes == null || pdfBytes.length == 0) {
                    pdfBytes = body;
                }

                byte[] signedBytes = PdfSignerEngine.signPdf(context, pdfBytes, certAlias, pin, reason, location);
                sendBinaryResponse(out, 200, "application/pdf", "Signed_Document.pdf", signedBytes);

            // 6. Web Studio HTML & JS assets
            } else if (path.equals("/studio") || path.equals("/webstudio") || path.equals("/index.html") || (path.equals("/") && query.contains("view=studio"))) {
                serveAssetFile(out, "webstudio/index.html", "text/html; charset=utf-8");
            } else if (path.equals("/pdf.min.js")) {
                serveAssetFile(out, "webstudio/pdf.min.js", "application/javascript");
            } else if (path.equals("/pdf.worker.min.js")) {
                serveAssetFile(out, "webstudio/pdf.worker.min.js", "application/javascript");
            } else {
                // Default fallback: return JSON status so API clients never get unexpected HTML
                JSONObject obj = new JSONObject();
                obj.put("status", "running");
                obj.put("version", "2.2.0");
                obj.put("message", "ABInfo Local Signer API");
                obj.put("port", port);
                sendJsonResponse(out, 200, obj.toString());
            }

            out.flush();
            client.close();
        } catch (Exception e) {
            try { client.close(); } catch (Exception ignored) {}
        }
    }

    private String extractBoundary(String contentType) {
        for (String param : contentType.split(";")) {
            String p = param.trim();
            if (p.toLowerCase().startsWith("boundary=")) {
                String b = p.substring(9).trim();
                if (b.startsWith("\"") && b.endsWith("\"") && b.length() >= 2) {
                    b = b.substring(1, b.length() - 1);
                }
                return b;
            }
        }
        return null;
    }

    private byte[] extractMultipartPdf(byte[] data, String boundary, Map<String, String> fields) {
        try {
            byte[] boundaryBytes = ("--" + boundary).getBytes(StandardCharsets.ISO_8859_1);
            byte[] doubleCrlf = "\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1);

            int start = 0;
            byte[] foundPdf = null;

            while (start < data.length) {
                int bIdx = indexOf(data, boundaryBytes, start);
                if (bIdx == -1) break;

                int nextBIdx = indexOf(data, boundaryBytes, bIdx + boundaryBytes.length);
                if (nextBIdx == -1) nextBIdx = data.length;

                int headerEnd = indexOf(data, doubleCrlf, bIdx);
                if (headerEnd != -1 && headerEnd < nextBIdx) {
                    int contentStart = headerEnd + 4;
                    int contentEnd = nextBIdx - 2; // Trim trailing \r\n
                    if (contentEnd > contentStart) {
                        String partHeader = new String(Arrays.copyOfRange(data, bIdx, headerEnd), StandardCharsets.ISO_8859_1);
                        if (partHeader.contains("filename=") || partHeader.toLowerCase().contains("application/pdf") || partHeader.contains("name=\"file\"")) {
                            foundPdf = Arrays.copyOfRange(data, contentStart, contentEnd);
                        } else {
                            // Extract field name
                            int nameIdx = partHeader.indexOf("name=\"");
                            if (nameIdx != -1) {
                                int nameEnd = partHeader.indexOf("\"", nameIdx + 6);
                                if (nameEnd != -1) {
                                    String fieldName = partHeader.substring(nameIdx + 6, nameEnd);
                                    String fieldValue = new String(Arrays.copyOfRange(data, contentStart, contentEnd), StandardCharsets.UTF_8).trim();
                                    fields.put(fieldName, fieldValue);
                                }
                            }
                        }
                    }
                }
                start = nextBIdx;
            }
            return foundPdf;
        } catch (Exception e) {
            return null;
        }
    }

    private int indexOf(byte[] data, byte[] pattern, int start) {
        if (data == null || pattern == null || start >= data.length) return -1;
        for (int i = start; i <= data.length - pattern.length; i++) {
            boolean match = true;
            for (int j = 0; j < pattern.length; j++) {
                if (data[i + j] != pattern[j]) {
                    match = false;
                    break;
                }
            }
            if (match) return i;
        }
        return -1;
    }

    private void serveAssetFile(OutputStream out, String assetPath, String contentType) {
        try {
            AssetManager am = context.getAssets();
            InputStream is = am.open(assetPath);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) != -1) {
                baos.write(buf, 0, n);
            }
            is.close();
            byte[] data = baos.toByteArray();

            String header = "HTTP/1.1 200 OK\r\n" +
                            "Content-Type: " + contentType + "\r\n" +
                            "Access-Control-Allow-Origin: *\r\n" +
                            "Access-Control-Allow-Methods: GET, POST, OPTIONS, PUT, DELETE\r\n" +
                            "Access-Control-Allow-Headers: *\r\n" +
                            "Content-Length: " + data.length + "\r\n\r\n";
            out.write(header.getBytes(StandardCharsets.UTF_8));
            out.write(data);
        } catch (Exception e) {
            try {
                String fallback = "<html><body style='font-family:sans-serif; background:#0A0F1D; color:#F8FAFC; text-align:center; padding:50px;'>" +
                                  "<h1 style='color:#0DCAF0;'>A B INFOTECH Android Digital Signer</h1>" +
                                  "<p style='color:#10B981;'>🟢 Background Server Active on Port " + port + "</p>" +
                                  "<p style='color:#94A3B8;'>Ready to sign PDF documents from Web Studio &amp; Network Apps.</p></body></html>";
                sendHtmlResponse(out, 200, fallback);
            } catch (Exception ignored) {}
        }
    }

    private String getQueryParam(String query, String name) {
        if (query == null || query.isEmpty()) return null;
        for (String param : query.split("&")) {
            String[] pair = param.split("=");
            if (pair.length == 2 && pair[0].equalsIgnoreCase(name)) {
                try { return URLDecoder.decode(pair[1], "UTF-8"); } catch (Exception ignored) {}
            }
        }
        return null;
    }

    private void sendCorsOk(OutputStream out) throws IOException {
        String resp = "HTTP/1.1 200 OK\r\n" +
                      "Access-Control-Allow-Origin: *\r\n" +
                      "Access-Control-Allow-Methods: GET, POST, OPTIONS, PUT, DELETE\r\n" +
                      "Access-Control-Allow-Headers: *\r\n" +
                      "Access-Control-Max-Age: 86400\r\n" +
                      "Content-Length: 0\r\n\r\n";
        out.write(resp.getBytes(StandardCharsets.UTF_8));
    }

    private void sendPlainTextResponse(OutputStream out, int status, String text) throws IOException {
        byte[] b = text.getBytes(StandardCharsets.UTF_8);
        String header = "HTTP/1.1 " + status + " OK\r\n" +
                        "Content-Type: text/plain; charset=utf-8\r\n" +
                        "Access-Control-Allow-Origin: *\r\n" +
                        "Access-Control-Allow-Methods: GET, POST, OPTIONS, PUT, DELETE\r\n" +
                        "Access-Control-Allow-Headers: *\r\n" +
                        "Content-Length: " + b.length + "\r\n\r\n";
        out.write(header.getBytes(StandardCharsets.UTF_8));
        out.write(b);
    }

    private void sendJsonResponse(OutputStream out, int status, String json) throws IOException {
        byte[] b = json.getBytes(StandardCharsets.UTF_8);
        String header = "HTTP/1.1 " + status + " OK\r\n" +
                        "Content-Type: application/json; charset=utf-8\r\n" +
                        "Access-Control-Allow-Origin: *\r\n" +
                        "Access-Control-Allow-Methods: GET, POST, OPTIONS, PUT, DELETE\r\n" +
                        "Access-Control-Allow-Headers: *\r\n" +
                        "Content-Length: " + b.length + "\r\n\r\n";
        out.write(header.getBytes(StandardCharsets.UTF_8));
        out.write(b);
    }

    private void sendHtmlResponse(OutputStream out, int status, String html) throws IOException {
        byte[] b = html.getBytes(StandardCharsets.UTF_8);
        String header = "HTTP/1.1 " + status + " OK\r\n" +
                        "Content-Type: text/html; charset=utf-8\r\n" +
                        "Access-Control-Allow-Origin: *\r\n" +
                        "Access-Control-Allow-Methods: GET, POST, OPTIONS, PUT, DELETE\r\n" +
                        "Access-Control-Allow-Headers: *\r\n" +
                        "Content-Length: " + b.length + "\r\n\r\n";
        out.write(header.getBytes(StandardCharsets.UTF_8));
        out.write(b);
    }

    private void sendBinaryResponse(OutputStream out, int status, String contentType, String filename, byte[] data) throws IOException {
        String header = "HTTP/1.1 " + status + " OK\r\n" +
                        "Content-Type: " + contentType + "\r\n" +
                        "Content-Disposition: attachment; filename=\"" + filename + "\"\r\n" +
                        "Access-Control-Allow-Origin: *\r\n" +
                        "Access-Control-Allow-Methods: GET, POST, OPTIONS, PUT, DELETE\r\n" +
                        "Access-Control-Allow-Headers: *\r\n" +
                        "Content-Length: " + data.length + "\r\n\r\n";
        out.write(header.getBytes(StandardCharsets.UTF_8));
        out.write(data);
    }
}
