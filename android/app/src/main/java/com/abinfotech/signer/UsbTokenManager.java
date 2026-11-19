package com.abinfotech.signer;

import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.hardware.usb.UsbConstants;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbEndpoint;
import android.hardware.usb.UsbInterface;
import android.hardware.usb.UsbManager;
import android.os.Build;
import android.util.Log;

import java.util.ArrayList;
import java.util.List;

public class UsbTokenManager {
    private static final String TAG = "UsbTokenManager";
    public static final String ACTION_USB_PERMISSION = "com.abinfotech.signer.USB_PERMISSION";

    private static UsbDevice sConnectedDevice = null;
    private static UsbDeviceConnection sActiveConnection = null;
    private static UsbInterface sActiveInterface = null;
    private static UsbEndpoint sBulkInEndpoint = null;
    private static UsbEndpoint sBulkOutEndpoint = null;

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
        List<TokenInfo> list = new ArrayList<>();
        CcidTokenDriver.DetectedToken detected = CcidTokenDriver.scanForToken(context);

        list.add(new TokenInfo("HYP2003 / ePass2003 (USB OTG)", "HyperPKI Feitian", detected != null && detected.name.contains("HYP2003")));
        list.add(new TokenInfo("mToken / CryptoID (USB OTG)", "Longmai PKI", detected != null && detected.name.contains("mToken")));
        list.add(new TokenInfo("Watchdata ProxKey (USB OTG)", "Watchdata WDS", detected != null && detected.name.contains("Watchdata")));
        list.add(new TokenInfo("InnaIT Precision (USB OTG)", "Precision / eMudhra", detected != null && detected.name.contains("InnaIT")));
        list.add(new TokenInfo("SafeNet eToken (USB OTG)", "Gemalto / Thales", detected != null && detected.name.contains("SafeNet")));
        list.add(new TokenInfo("Software Certificate (.pfx / .p12)", "Local / Storage", true));
        list.add(new TokenInfo("Android System KeyStore", "Hardware KeyStore", true));
        return list;
    }

    public static boolean isHardwareTokenConnected(Context context) {
        return CcidTokenDriver.scanForToken(context) != null;
    }

    public static boolean isPermissionGranted(Context context) {
        if (context == null) return false;
        UsbManager manager = (UsbManager) context.getSystemService(Context.USB_SERVICE);
        if (manager == null) return false;
        CcidTokenDriver.DetectedToken detected = CcidTokenDriver.scanForToken(context);
        return detected != null && detected.device != null && manager.hasPermission(detected.device);
    }

    public static synchronized UsbDeviceConnection getActiveConnection() {
        return sActiveConnection;
    }

    public static synchronized UsbEndpoint getBulkInEndpoint() {
        return sBulkInEndpoint;
    }

    public static synchronized UsbEndpoint getBulkOutEndpoint() {
        return sBulkOutEndpoint;
    }

    public static synchronized UsbInterface getActiveInterface() {
        return sActiveInterface;
    }

    public static synchronized UsbDevice getConnectedDevice() {
        return sConnectedDevice;
    }

    public static String getConnectedTokenSummary(Context context) {
        CcidTokenDriver.DetectedToken token = CcidTokenDriver.scanForToken(context);
        if (token != null) {
            UsbManager manager = (UsbManager) context.getSystemService(Context.USB_SERVICE);
            boolean hasPerm = manager != null && manager.hasPermission(token.device);
            return "🟢 " + token.name + " (" + token.brand + ")" + (hasPerm ? " [Ready]" : " [Permission Needed]");
        }
        return "No USB Token Connected (Plug OTG Cable)";
    }

    /**
     * Inspects attached USB devices, prompts for permission if needed, and wires the
     * open UsbDeviceConnection and Bulk IN/OUT endpoints into MyApplication and JniCallBack
     * so that libOTGPass2003_India.so and CCID smartcard commands function correctly.
     */
    public static synchronized boolean setupHardwareTokenConnection(Context context) {
        if (context == null) return false;
        UsbManager manager = (UsbManager) context.getSystemService(Context.USB_SERVICE);
        if (manager == null) return false;

        CcidTokenDriver.DetectedToken detected = CcidTokenDriver.scanForToken(context);
        if (detected == null || detected.device == null) {
            disconnectToken();
            return false;
        }

        UsbDevice device = detected.device;
        if (sConnectedDevice != null && (!sConnectedDevice.getDeviceName().equals(device.getDeviceName()) || sConnectedDevice.getDeviceId() != device.getDeviceId())) {
            Log.d(TAG, "Different USB Token detected! Resetting previous token connection.");
            disconnectToken(context);
            P11Operation.disconnect();
        }
        sConnectedDevice = device;

        if (!manager.hasPermission(device)) {
            Log.d(TAG, "Requesting USB permission for token: VID=0x" + Integer.toHexString(device.getVendorId()) + " PID=0x" + Integer.toHexString(device.getProductId()));
            try {
                int flags = 0;
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    flags = PendingIntent.FLAG_MUTABLE;
                }
                Intent intent = new Intent(ACTION_USB_PERMISSION);
                intent.setPackage(context.getPackageName());
                PendingIntent pi = PendingIntent.getBroadcast(context, 0, intent, flags);
                manager.requestPermission(device, pi);
            } catch (Throwable t) {
                Log.e(TAG, "Error requesting USB permission: " + t.getMessage(), t);
            }
            return false;
        }

        // If connection is already open and valid for the same device, reuse it!
        if (sActiveConnection != null && sConnectedDevice != null && sConnectedDevice.getDeviceId() == device.getDeviceId()
                && sBulkInEndpoint != null && sBulkOutEndpoint != null) {
            return true;
        }

        // Permission already granted: open connection and claim interface
        try {
            if (sActiveConnection != null) {
                try { sActiveConnection.close(); } catch (Throwable ignored) {}
                sActiveConnection = null;
            }
            UsbDeviceConnection conn = manager.openDevice(device);
            if (conn == null) {
                Log.e(TAG, "Could not open UsbDeviceConnection for device");
                return false;
            }
            sActiveConnection = conn;

            UsbInterface targetIntf = null;
            UsbEndpoint bulkIn = null;
            UsbEndpoint bulkOut = null;

            int intfCount = device.getInterfaceCount();

            // Pass 0: Strictly find CCID Smartcard interface (Class 11 / 0x0B) or Smartcard Vendor (Class 255)
            // Pass 1: Fallback to any non-MassStorage interface
            for (int pass = 0; pass < 2; pass++) {
                for (int i = 0; i < intfCount; i++) {
                    UsbInterface intf = device.getInterface(i);
                    int intfClass = intf.getInterfaceClass();

                    // CRITICAL: NEVER claim Mass Storage (Class 8 / Virtual CD-ROM installer)
                    if (intfClass == UsbConstants.USB_CLASS_MASS_STORAGE || intfClass == 8) {
                        continue;
                    }

                    if (pass == 0) {
                        // Must be CCID (11 / USB_CLASS_CSCID) or Vendor-specific smartcard (255)
                        if (intfClass != 11 && intfClass != UsbConstants.USB_CLASS_CSCID && intfClass != 255) {
                            continue;
                        }
                    }

                    UsbEndpoint tempIn = null;
                    UsbEndpoint tempOut = null;
                    for (int j = 0; j < intf.getEndpointCount(); j++) {
                        UsbEndpoint ep = intf.getEndpoint(j);
                        if (ep.getType() == UsbConstants.USB_ENDPOINT_XFER_BULK) {
                            if (ep.getDirection() == UsbConstants.USB_DIR_IN) {
                                tempIn = ep;
                            } else if (ep.getDirection() == UsbConstants.USB_DIR_OUT) {
                                tempOut = ep;
                            }
                        }
                    }
                    if (tempIn != null && tempOut != null) {
                        targetIntf = intf;
                        bulkIn = tempIn;
                        bulkOut = tempOut;
                        break;
                    }
                }
                if (targetIntf != null) break;
            }

            if (targetIntf != null) {
                boolean claimed = conn.claimInterface(targetIntf, true);
                Log.d(TAG, "Claimed USB Interface " + targetIntf.getId() + " (Class " + targetIntf.getInterfaceClass() + "): " + claimed);
                sActiveInterface = targetIntf;
                sBulkInEndpoint = bulkIn;
                sBulkOutEndpoint = bulkOut;

                // Wire endpoints into PKCS#11 SDK (libOTGPass2003_India.so) for all connected USB tokens
                try {
                    com.ftsafe.monitor.MyApplication myApp = com.ftsafe.monitor.MyApplication.getInstance();
                    if (myApp != null) {
                        myApp.setUsbDeviceConnection(conn);
                        myApp.setInUsbEndpoint(bulkIn);
                        myApp.setOutUsbEndpoint(bulkOut);
                        Log.d(TAG, "MyApplication endpoints successfully wired for token: VID=0x" + Integer.toHexString(device.getVendorId()));
                    }
                    com.ftsafe.monitor.JniCallBack cb = com.ftsafe.monitor.JniCallBack.getInstance();
                    if (cb != null) {
                        cb.setidVendor(device.getVendorId());
                        cb.setidProduct(device.getProductId());
                        Log.d(TAG, "JniCallBack VID/PID set: " + device.getVendorId() + " / " + device.getProductId());
                    }
                } catch (Throwable t) {
                    Log.w(TAG, "JniCallBack setup notice: " + t.getMessage());
                }

                return true;
            }
        } catch (Throwable t) {
            Log.e(TAG, "Failed to connect hardware token: " + t.getMessage(), t);
        }

        return false;
    }

    public static synchronized void disconnectToken(Context context) {
        disconnectToken();
        if (context != null) {
            try {
                context.getSharedPreferences("AbinfoSignerPrefs", Context.MODE_PRIVATE)
                        .edit()
                        .remove("last_token_client_name")
                        .remove("last_token_issuer_name")
                        .remove("last_token_device_id")
                        .remove("selected_cert_name")
                        .apply();
                context.getSharedPreferences("AbinfoPdfSignerPrefs", Context.MODE_PRIVATE)
                        .edit()
                        .remove("selected_cert_name")
                        .remove("last_token_client_name")
                        .remove("last_token_issuer_name")
                        .apply();
            } catch (Throwable ignored) {}
        }
    }

    public static synchronized void disconnectToken() {
        if (sActiveConnection != null) {
            if (sActiveInterface != null) {
                try {
                    sActiveConnection.releaseInterface(sActiveInterface);
                } catch (Throwable ignored) {}
                sActiveInterface = null;
            }
            try {
                sActiveConnection.close();
            } catch (Throwable ignored) {}
            sActiveConnection = null;
        }
        sBulkInEndpoint = null;
        sBulkOutEndpoint = null;
        sConnectedDevice = null;
        try {
            com.ftsafe.monitor.MyApplication myApp = com.ftsafe.monitor.MyApplication.getInstance();
            if (myApp != null) {
                myApp.setUsbDeviceConnection(null);
                myApp.setInUsbEndpoint(null);
                myApp.setOutUsbEndpoint(null);
            }
        } catch (Throwable ignored) {}
        try {
            P11Operation.disconnect();
        } catch (Throwable ignored) {}
    }
}
