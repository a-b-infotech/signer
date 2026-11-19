package com.abinfotech.signer;

import android.app.Activity;
import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.Bundle;
import android.view.View;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.ProgressBar;
import android.widget.Toast;

public class WebStudioActivity extends Activity {
    public static final String URL_CLOUD = "https://sign.a-b-infotech.in/Token.php";
    public static final String URL_LOCAL = "http://127.0.0.1:5000/studio";
    public static final String URL_INBUILT_ASSET = "file:///android_asset/webstudio/index.html";

    private WebView webView;
    private ProgressBar progressBar;
    private int currentUrlTier = 0; // 0: Cloud, 1: Local, 2: Inbuilt

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_web_studio);

        progressBar = (ProgressBar) findViewById(R.id.pbWebLoading);
        webView = (WebView) findViewById(R.id.wvStudio);

        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setAllowFileAccess(true);
        settings.setAllowContentAccess(true);
        settings.setLoadWithOverviewMode(true);
        settings.setUseWideViewPort(true);
        settings.setBuiltInZoomControls(true);
        settings.setDisplayZoomControls(false);

        webView.setWebViewClient(new WebViewClient() {
            @Override
            public void onPageFinished(WebView view, String url) {
                if (progressBar != null) progressBar.setVisibility(View.GONE);
            }

            @Override
            public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
                if (request != null && request.isForMainFrame()) {
                    fallbackToNextTier(view);
                }
            }
        });

        webView.setWebChromeClient(new WebChromeClient() {
            @Override
            public void onProgressChanged(WebView view, int newProgress) {
                if (progressBar != null) {
                    if (newProgress < 100) {
                        progressBar.setVisibility(View.VISIBLE);
                        progressBar.setProgress(newProgress);
                    } else {
                        progressBar.setVisibility(View.GONE);
                    }
                }
            }
        });

        loadDualInbuiltUrl();
    }

    private void loadDualInbuiltUrl() {
        if (isNetworkAvailable()) {
            currentUrlTier = 0;
            webView.loadUrl(URL_CLOUD);
        } else if (SignerServerService.serverInstance != null && SignerServerService.serverInstance.isRunning()) {
            currentUrlTier = 1;
            webView.loadUrl(URL_LOCAL);
        } else {
            currentUrlTier = 2;
            webView.loadUrl(URL_INBUILT_ASSET);
        }
    }

    private void fallbackToNextTier(WebView view) {
        if (currentUrlTier == 0) {
            // Cloud failed, fallback to local server (Tier 1)
            currentUrlTier = 1;
            if (SignerServerService.serverInstance != null && SignerServerService.serverInstance.isRunning()) {
                view.loadUrl(URL_LOCAL);
            } else {
                currentUrlTier = 2;
                view.loadUrl(URL_INBUILT_ASSET);
            }
        } else if (currentUrlTier == 1) {
            // Local failed, fallback to inbuilt asset (Tier 2)
            currentUrlTier = 2;
            view.loadUrl(URL_INBUILT_ASSET);
        }
    }

    private boolean isNetworkAvailable() {
        try {
            ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm != null) {
                NetworkInfo netInfo = cm.getActiveNetworkInfo();
                return netInfo != null && netInfo.isConnected();
            }
        } catch (Throwable ignored) {}
        return false;
    }

    @Override
    public void onBackPressed() {
        if (webView != null && webView.canGoBack()) {
            webView.goBack();
        } else {
            super.onBackPressed();
        }
    }
}
