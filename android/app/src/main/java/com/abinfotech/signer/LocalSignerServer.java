package com.abinfotech.signer;

import android.content.Context;
import android.content.res.AssetManager;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class LocalSignerServer {
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
            client.setSoTimeout(15000);
            InputStream in = client.getInputStream();
            OutputStream out = client.getOutputStream();

            BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            String line = reader.readLine();
            if (line == null) { client.close(); return; }

            String[] parts = line.split(" ");
            if (parts.length < 2) { client.close(); return; }

            String method = parts[0].toUpperCase();
            String fullPath = parts[1];
            String path = fullPath.contains("?") ? fullPath.substring(0, fullPath.indexOf("?")) : fullPath;
            String query = fullPath.contains("?") ? fullPath.substring(fullPath.indexOf("?") + 1) : "";

            int contentLength = 0;
            String contentType = "";
            Map<String, String> headers = new HashMap<String, String>();

            while ((line = reader.readLine()) != null && !line.isEmpty()) {
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
            if (path.equals("/api/status") || path.equals("/status")) {
                JSONObject obj = new JSONObject();
                obj.put("status", "running");
                obj.put("version", "2.2.0");
                obj.put("platform", "Android");
                obj.put("server", "ABInfo Local Signer (Android Service)");
                obj.put("port", port);
                obj.put("licensed", LicenseManager.isActivated(context));
                obj.put("license_tier", "pro");
                obj.put("cert_count", CertificateManager.getCertCount(context));
                obj.put("usb_token", UsbTokenManager.getConnectedTokenSummary(context));
                sendJsonResponse(out, 200, obj.toString());
            } else if (path.equals("/api/drivers")) {
                JSONArray arr = new JSONArray();
                arr.put("HYP2003 / ePass2003 (USB OTG - libOTGPass2003_India.so)");
                arr.put("InnaIT Precision (USB OTG - libInnaITPKCS11.so)");
                arr.put("mToken / CryptoID (USB OTG)");
                arr.put("Watchdata ProxKey (USB OTG)");
                arr.put("Software Certificate (.pfx / .p12)");
                arr.put("Android System KeyStore");
                sendJsonResponse(out, 200, arr.toString());
            } else if (path.equals("/api/certificates")) {
                JSONArray certs = CertificateManager.listCertificatesJson(context, "");
                sendJsonResponse(out, 200, certs.toString());
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
            } else if ((path.equals("/api/sign") || path.equals("/api/sign_pdf")) && method.equals("POST")) {
                byte[] body = new byte[contentLength];
                int totalRead = 0;
                while (totalRead < contentLength) {
                    int r = in.read(body, totalRead, contentLength - totalRead);
                    if (r == -1) break;
                    totalRead += r;
                }

                String certAlias = headers.get("x-cert-alias");
                String pin = headers.get("x-pin");
                String reason = headers.get("x-reason");
                String location = headers.get("x-location");

                byte[] signedBytes = PdfSignerEngine.signPdf(context, body, certAlias, pin, reason, location);
                sendBinaryResponse(out, 200, "application/pdf", "Signed_Document.pdf", signedBytes);
            } else if (path.equals("/") || path.equals("/studio") || path.equals("/index.html")) {
                serveAssetFile(out, "webstudio/index.html", "text/html; charset=utf-8");
            } else if (path.equals("/pdf.min.js")) {
                serveAssetFile(out, "webstudio/pdf.min.js", "application/javascript");
            } else if (path.equals("/pdf.worker.min.js")) {
                serveAssetFile(out, "webstudio/pdf.worker.min.js", "application/javascript");
            } else {
                serveAssetFile(out, "webstudio/index.html", "text/html; charset=utf-8");
            }

            out.flush();
            client.close();
        } catch (Exception ignored) {}
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
                      "Content-Length: 0\r\n\r\n";
        out.write(resp.getBytes(StandardCharsets.UTF_8));
    }

    private void sendJsonResponse(OutputStream out, int status, String json) throws IOException {
        byte[] b = json.getBytes(StandardCharsets.UTF_8);
        String header = "HTTP/1.1 " + status + " OK\r\n" +
                        "Content-Type: application/json; charset=utf-8\r\n" +
                        "Access-Control-Allow-Origin: *\r\n" +
                        "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n" +
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
                        "Content-Length: " + b.length + "\r\n\r\n";
        out.write(header.getBytes(StandardCharsets.UTF_8));
        out.write(b);
    }

    private void sendBinaryResponse(OutputStream out, int status, String contentType, String filename, byte[] data) throws IOException {
        String header = "HTTP/1.1 " + status + " OK\r\n" +
                        "Content-Type: " + contentType + "\r\n" +
                        "Content-Disposition: attachment; filename=\"" + filename + "\"\r\n" +
                        "Access-Control-Allow-Origin: *\r\n" +
                        "Content-Length: " + data.length + "\r\n\r\n";
        out.write(header.getBytes(StandardCharsets.UTF_8));
        out.write(data);
    }
}
