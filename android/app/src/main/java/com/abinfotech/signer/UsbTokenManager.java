package com.abinfotech.signer;

import android.content.Context;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbManager;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class UsbTokenManager {

    public static class TokenInfo {
        public String name;
        public String driverSo;
        public int vendorId;
        public int productId;
        public boolean isConnected;

        public TokenInfo(String name, String driverSo, int vendorId, int productId, boolean isConnected) {
            this.name = name;
            this.driverSo = driverSo;
            this.vendorId = vendorId;
            this.productId = productId;
            this.isConnected = isConnected;
        }
    }

    // Supported USB Token VID/PID Signatures
    // 1. HYP2003 (Feitian / HyperPKI / ePass2003)
    private static final int VID_HYP2003 = 0x096e; // Feitian / EnterSafe
    // 2. mToken (Longmai CryptoID)
    private static final int VID_MTOKEN = 0x096e; // Longmai often shares or uses 0x0801 / 0x0806
    // 3. Watchdata ProxKey
    private static final int VID_PROXKEY_1 = 0x04b4;
    private static final int VID_PROXKEY_2 = 0x163c;
    // 4. InnaIT Precision
    private static final int VID_INNAIT_1 = 0x2007;
    private static final int VID_INNAIT_2 = 0x2ce3;

    public static List<TokenInfo> getAvailableDrivers(Context context) {
        List<TokenInfo> list = new ArrayList<TokenInfo>();
        list.add(new TokenInfo("HYP2003 / ePass2003 Token", "libcastle.so", VID_HYP2003, 0x0405, false));
        list.add(new TokenInfo("mToken / CryptoID Token", "libcryptoid_pkcs11.so", VID_MTOKEN, 0x0801, false));
        list.add(new TokenInfo("Watchdata ProxKey Token", "libWatchdataPKCS11.so", VID_PROXKEY_1, 0x0002, false));
        list.add(new TokenInfo("InnaIT Precision Token", "libinnait_pkcs11.so", VID_INNAIT_1, 0x1001, false));
        list.add(new TokenInfo("Smartcard CCID Driver", "libpcsclite.so", 0, 0, false));
        list.add(new TokenInfo("OpenSC PKCS#11 Core", "libopensc.so", 0, 0, false));

        UsbManager usbManager = (UsbManager) context.getSystemService(Context.USB_SERVICE);
        if (usbManager != null) {
            HashMap<String, UsbDevice> deviceList = usbManager.getDeviceList();
            for (UsbDevice device : deviceList.values()) {
                int vid = device.getVendorId();
                int pid = device.getProductId();

                for (TokenInfo t : list) {
                    if (t.vendorId != 0 && t.vendorId == vid) {
                        t.isConnected = true;
                    }
                }
            }
        }
        return list;
    }

    public static boolean isHardwareTokenConnected(Context context) {
        UsbManager usbManager = (UsbManager) context.getSystemService(Context.USB_SERVICE);
        if (usbManager == null) return false;
        HashMap<String, UsbDevice> deviceList = usbManager.getDeviceList();
        for (UsbDevice device : deviceList.values()) {
            int vid = device.getVendorId();
            if (vid == VID_HYP2003 || vid == VID_PROXKEY_1 || vid == VID_PROXKEY_2 ||
                vid == VID_INNAIT_1 || vid == VID_INNAIT_2) {
                return true;
            }
        }
        return false;
    }

    public static String getConnectedTokenSummary(Context context) {
        UsbManager usbManager = (UsbManager) context.getSystemService(Context.USB_SERVICE);
        if (usbManager == null) return "No USB Token Connected (Use OTG Cable)";
        HashMap<String, UsbDevice> deviceList = usbManager.getDeviceList();
        if (deviceList == null || deviceList.isEmpty()) {
            return "No USB Token Connected (Use OTG Cable)";
        }
        for (UsbDevice device : deviceList.values()) {
            int vid = device.getVendorId();
            int pid = device.getProductId();
            if (vid == VID_HYP2003) {
                return "🟢 Connected: HYP2003 / ePass2003 (VID: 0x" + Integer.toHexString(vid) + ")";
            }
            if (vid == VID_PROXKEY_1 || vid == VID_PROXKEY_2) {
                return "🟢 Connected: Watchdata ProxKey (VID: 0x" + Integer.toHexString(vid) + ")";
            }
            if (vid == VID_INNAIT_1 || vid == VID_INNAIT_2) {
                return "🟢 Connected: InnaIT Precision (VID: 0x" + Integer.toHexString(vid) + ")";
            }
            return "🟢 USB Device Detected: " + device.getDeviceName();
        }
        return "No USB Token Connected (Use OTG Cable)";
    }

    public static void tryLoadNativeLibraries() {
        String[] libs = new String[] {
            "castle", "cryptoid_pkcs11", "WatchdataPKCS11", "innait_pkcs11", "pcsclite", "opensc"
        };
        for (String lib : libs) {
            try {
                System.loadLibrary(lib);
            } catch (Throwable ignored) {}
        }
    }
}
