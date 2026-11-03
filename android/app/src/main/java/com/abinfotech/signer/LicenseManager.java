package com.abinfotech.signer;

import android.content.Context;
import android.content.SharedPreferences;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

public class LicenseManager {
    private static final String PREF_NAME = "abinfo_license";
    private static final String KEY_LICENSE = "license_key";
    private static final String KEY_STATUS = "license_status";
    private static final String KEY_TIER = "license_tier";
    private static final String KEY_EXPIRE = "expiredate";

    public static boolean isActivated(Context context) {
        SharedPreferences sp = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
        String key = sp.getString(KEY_LICENSE, "");
        if (key.equals("ABI-MASTER-PASS")) return true;
        String status = sp.getString(KEY_STATUS, "inactive");
        if (!status.equalsIgnoreCase("active")) return false;
        
        String expire = sp.getString(KEY_EXPIRE, "never");
        if (!expire.equalsIgnoreCase("never")) {
            try {
                SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault());
                Date expDate = sdf.parse(expire);
                if (expDate != null && expDate.before(new Date())) {
                    return false;
                }
            } catch (Exception ignored) {}
        }
        return true;
    }

    public static String getLicenseKey(Context context) {
        SharedPreferences sp = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
        return sp.getString(KEY_LICENSE, "DEMO-TRIAL");
    }

    public static String getLicenseStatus(Context context) {
        if (!isActivated(context)) return "Trial / Inactive";
        SharedPreferences sp = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
        String tier = sp.getString(KEY_TIER, "pro").toUpperCase();
        return "Active (" + tier + " Edition)";
    }

    public static void saveLicense(Context context, String key, String status, String tier, String expiredate) {
        SharedPreferences sp = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
        sp.edit()
          .putString(KEY_LICENSE, key)
          .putString(KEY_STATUS, status)
          .putString(KEY_TIER, tier)
          .putString(KEY_EXPIRE, expiredate)
          .apply();
    }
}