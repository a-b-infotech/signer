package com.abinfotech.signer;

import android.content.Context;
import java.util.ArrayList;
import java.util.List;

public class UsbTokenManager {

    public static class TokenInfo {
        public String name;
        public String brand;
        public boolean isConnected;

        public TokenInfo(String name, String brand, boolean isConnected) {
            this.name = name;
            this.brand = brand;
            this.isConnected = isConnected;
        }
    }

    public static List<TokenInfo> getAvailableDrivers(Context context) {
        List<TokenInfo> list = new ArrayList<TokenInfo>();
        CcidTokenDriver.DetectedToken detected = CcidTokenDriver.scanForToken(context);

        list.add(new TokenInfo("HYP2003 / ePass2003 (USB OTG)", "HyperPKI Feitian", detected != null && detected.name.contains("HYP2003")));
        list.add(new TokenInfo("mToken / CryptoID (USB OTG)", "Longmai PKI", detected != null && detected.name.contains("mToken")));
        list.add(new TokenInfo("Watchdata ProxKey (USB OTG)", "Watchdata WDS", detected != null && detected.name.contains("Watchdata")));
        list.add(new TokenInfo("InnaIT Precision (USB OTG)", "Precision / eMudhra", detected != null && detected.name.contains("InnaIT")));
        list.add(new TokenInfo("Software Certificate (.pfx / .p12)", "Local / Storage", true));
        list.add(new TokenInfo("Android System KeyStore", "Hardware KeyStore", true));
        return list;
    }

    public static boolean isHardwareTokenConnected(Context context) {
        return CcidTokenDriver.scanForToken(context) != null;
    }

    public static String getConnectedTokenSummary(Context context) {
        CcidTokenDriver.DetectedToken token = CcidTokenDriver.scanForToken(context);
        if (token != null) {
            return "🟢 Connected: " + token.name + " (" + token.brand + ")";
        }
        return "No USB Token Connected (Plug OTG Cable)";
    }
}
