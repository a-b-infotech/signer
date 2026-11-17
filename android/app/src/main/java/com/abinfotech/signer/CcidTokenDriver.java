package com.abinfotech.signer;

import android.content.Context;
import android.hardware.usb.UsbConstants;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbEndpoint;
import android.hardware.usb.UsbInterface;
import android.hardware.usb.UsbManager;
import java.util.HashMap;

/**
 * Pure Java CCID (Chip Card Interface Device) USB OTG Driver
 * Directly communicates with USB Cryptographic Tokens (HYP2003, mToken, ProxKey, InnaIT)
 * across any Android device without requiring incompatible native C/C++ libraries.
 */
public class CcidTokenDriver {

    public static class DetectedToken {
        public String name;
        public String brand;
        public int vendorId;
        public int productId;
        public UsbDevice device;
        public boolean hasCcidInterface;

        public DetectedToken(String name, String brand, int vendorId, int productId, UsbDevice device, boolean hasCcid) {
            this.name = name;
            this.brand = brand;
            this.vendorId = vendorId;
            this.productId = productId;
            this.device = device;
            this.hasCcidInterface = hasCcid;
        }
    }

    // Supported USB Token Hardware Signatures (India & Global PKI)
    // 1. HYP2003 / ePass2003 (Feitian / EnterSafe / HyperPKI)
    public static final int VID_FEITIAN = 0x096e;
    public static final int PID_EPASS2003 = 0x0405;
    public static final int PID_HYP2003_1 = 0x0807;
    public static final int PID_HYP2003_2 = 0x2003;

    // 2. mToken / CryptoID (Century Longmai PKI)
    // 0x055c is Beijing Century Longmai Technology Co., Ltd.
    public static final int VID_LONGMAI_1 = 0x055c;
    public static final int VID_LONGMAI_2 = 0x338c;
    public static final int VID_LONGMAI_3 = 0x4c4d; // 'LM'
    public static final int VID_LONGMAI_4 = 0x0925; // Lakeview / Longmai

    // 3. Watchdata ProxKey (Watchdata WDS)
    public static final int VID_WATCHDATA_1 = 0x163c;
    public static final int VID_WATCHDATA_2 = 0x04b5;
    public static final int VID_WATCHDATA_3 = 0x1059;
    public static final int VID_WATCHDATA_4 = 0x04b4;

    // 4. InnaIT Precision (Precision / eMudhra)
    public static final int VID_INNAIT_1 = 0x2ccf;
    public static final int VID_INNAIT_2 = 0x2007;
    public static final int VID_INNAIT_3 = 0x2ce3;

    // 5. SafeNet eToken (Gemalto / Thales)
    public static final int VID_SAFENET_1 = 0x0529;
    public static final int VID_SAFENET_2 = 0x08e6;

    public static DetectedToken scanForToken(Context context) {
        UsbManager manager = (UsbManager) context.getSystemService(Context.USB_SERVICE);
        if (manager == null) return null;

        HashMap<String, UsbDevice> devices = manager.getDeviceList();
        if (devices == null || devices.isEmpty()) return null;

        for (UsbDevice dev : devices.values()) {
            int vid = dev.getVendorId();
            int pid = dev.getProductId();

            boolean hasCcid = false;
            for (int i = 0; i < dev.getInterfaceCount(); i++) {
                UsbInterface intf = dev.getInterface(i);
                // CCID class is 0x0B (11) or vendor specific 0xFF (255)
                if (intf.getInterfaceClass() == 11 || intf.getInterfaceClass() == UsbConstants.USB_CLASS_CSCID) {
                    hasCcid = true;
                    break;
                }
            }

            // Inspect USB product & manufacturer descriptor strings if accessible
            String prodName = "";
            String mfgName = "";
            try {
                if (dev.getProductName() != null) prodName = dev.getProductName().toLowerCase();
            } catch (Throwable ignored) {}
            try {
                if (dev.getManufacturerName() != null) mfgName = dev.getManufacturerName().toLowerCase();
            } catch (Throwable ignored) {}
            String combined = (prodName + " " + mfgName).trim();

            // Match by product string descriptor heuristics first
            if (combined.contains("mtoken") || combined.contains("longmai") || combined.contains("cryptoid")) {
                return new DetectedToken("mToken / CryptoID", "Century Longmai PKI", vid, pid, dev, hasCcid);
            }
            if (combined.contains("epass") || combined.contains("hyp2003") || combined.contains("feitian")
                    || combined.contains("entersafe") || combined.contains("hyperpki")) {
                return new DetectedToken("HYP2003 / ePass2003", "HyperPKI Feitian", vid, pid, dev, hasCcid);
            }
            if (combined.contains("proxkey") || combined.contains("watchdata")) {
                return new DetectedToken("Watchdata ProxKey", "Watchdata WDS", vid, pid, dev, hasCcid);
            }
            if (combined.contains("innait") || combined.contains("precision") || combined.contains("emudhra")) {
                return new DetectedToken("InnaIT Precision", "Precision / eMudhra", vid, pid, dev, hasCcid);
            }
            if (combined.contains("safenet") || combined.contains("etoken") || combined.contains("gemalto") || combined.contains("thales")) {
                return new DetectedToken("SafeNet eToken", "Gemalto / Thales", vid, pid, dev, hasCcid);
            }

            // Match by USB Vendor IDs
            // 1. mToken / CryptoID (Century Longmai - 0x055C, 0x338C, 0x4C4D, 0x0925)
            if (vid == VID_LONGMAI_1 || vid == VID_LONGMAI_2 || vid == VID_LONGMAI_3 || vid == VID_LONGMAI_4) {
                return new DetectedToken("mToken / CryptoID", "Century Longmai PKI", vid, pid, dev, hasCcid);
            }
            // 2. HYP2003 / ePass2003 (Feitian / EnterSafe - 0x096E)
            if (vid == VID_FEITIAN) {
                return new DetectedToken("HYP2003 / ePass2003", "HyperPKI Feitian", vid, pid, dev, hasCcid);
            }
            // 3. Watchdata ProxKey (0x163C, 0x04B5, 0x1059, 0x04B4)
            if (vid == VID_WATCHDATA_1 || vid == VID_WATCHDATA_2 || vid == VID_WATCHDATA_3 || vid == VID_WATCHDATA_4) {
                return new DetectedToken("Watchdata ProxKey", "Watchdata WDS", vid, pid, dev, hasCcid);
            }
            // 4. InnaIT Precision (0x2CCF, 0x2007, 0x2CE3)
            if (vid == VID_INNAIT_1 || vid == VID_INNAIT_2 || vid == VID_INNAIT_3) {
                return new DetectedToken("InnaIT Precision", "Precision / eMudhra", vid, pid, dev, hasCcid);
            }
            // 5. SafeNet eToken (0x0529, 0x08E6)
            if (vid == VID_SAFENET_1 || vid == VID_SAFENET_2) {
                return new DetectedToken("SafeNet eToken", "Gemalto / Thales", vid, pid, dev, hasCcid);
            }
            // Generic Smartcard / CCID
            if (hasCcid) {
                return new DetectedToken("Smartcard Token (CCID)", "USB PKI Token", vid, pid, dev, true);
            }
        }
        return null;
    }

    public static byte[] sendApduCommand(Context context, DetectedToken token, byte[] apdu) {
        if (token == null || token.device == null) return null;
        UsbManager manager = (UsbManager) context.getSystemService(Context.USB_SERVICE);
        if (manager == null || !manager.hasPermission(token.device)) return null;

        UsbDeviceConnection conn = manager.openDevice(token.device);
        if (conn == null) return null;

        try {
            UsbInterface ccidInterface = null;
            UsbEndpoint outEndpoint = null;
            UsbEndpoint inEndpoint = null;

            for (int i = 0; i < token.device.getInterfaceCount(); i++) {
                UsbInterface intf = token.device.getInterface(i);
                for (int j = 0; j < intf.getEndpointCount(); j++) {
                    UsbEndpoint ep = intf.getEndpoint(j);
                    if (ep.getType() == UsbConstants.USB_ENDPOINT_XFER_BULK) {
                        if (ep.getDirection() == UsbConstants.USB_DIR_OUT) outEndpoint = ep;
                        if (ep.getDirection() == UsbConstants.USB_DIR_IN) inEndpoint = ep;
                    }
                }
                if (outEndpoint != null && inEndpoint != null) {
                    ccidInterface = intf;
                    break;
                }
            }

            if (ccidInterface != null) {
                conn.claimInterface(ccidInterface, true);

                // Build CCID PC_to_RDR_XfrBlock (0x6F) message
                byte[] ccidMsg = new byte[10 + apdu.length];
                ccidMsg[0] = 0x6F; // Message Type
                int len = apdu.length;
                ccidMsg[1] = (byte) (len & 0xFF);
                ccidMsg[2] = (byte) ((len >> 8) & 0xFF);
                ccidMsg[3] = (byte) ((len >> 16) & 0xFF);
                ccidMsg[4] = (byte) ((len >> 24) & 0xFF);
                ccidMsg[5] = 0x00; // Slot number
                ccidMsg[6] = 0x01; // Sequence number
                System.arraycopy(apdu, 0, ccidMsg, 10, apdu.length);

                conn.bulkTransfer(outEndpoint, ccidMsg, ccidMsg.length, 3000);

                byte[] respBuf = new byte[1024];
                int read = conn.bulkTransfer(inEndpoint, respBuf, respBuf.length, 3000);
                if (read > 10) {
                    byte[] apduResp = new byte[read - 10];
                    System.arraycopy(respBuf, 10, apduResp, 0, read - 10);
                    return apduResp;
                }
            }
        } catch (Exception ignored) {
        } finally {
            conn.close();
        }
        return null;
    }
}

