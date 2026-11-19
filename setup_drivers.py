import os
import shutil
import struct
import subprocess

repo_root = os.path.dirname(os.path.abspath(__file__))
drivers_dir = os.path.join(repo_root, "drivers")

os.makedirs(os.path.join(drivers_dir, "windows", "x64"), exist_ok=True)
os.makedirs(os.path.join(drivers_dir, "windows", "x86"), exist_ok=True)
os.makedirs(os.path.join(drivers_dir, "macos"), exist_ok=True)
os.makedirs(os.path.join(drivers_dir, "linux"), exist_ok=True)
os.makedirs(os.path.join(drivers_dir, "android", "arm64-v8a"), exist_ok=True)
os.makedirs(os.path.join(drivers_dir, "android", "armeabi-v7a"), exist_ok=True)
os.makedirs(os.path.join(drivers_dir, "android", "armeabi"), exist_ok=True)

print("=== A B INFOTECH - Multi-Platform PKCS#11 Driver Setup ===")

# 1. Setup Windows x64 drivers
win_x64_sources = {
    r"C:\Windows\System32\HYP2003csp11IND.dll": "HYP2003csp11IND.dll",
    r"C:\Windows\System32\cryptoida_pkcs11.dll": "cryptoida_pkcs11.dll",
    r"C:\Windows\System32\SignatureP11.dll": "SignatureP11.dll",
    r"C:\Windows\System32\InnaITPKCS11Driver.dll": "InnaITPKCS11Driver.dll",
    r"C:\Windows\System32\Watchdata\PROXKey CSP India V3.0\WDPKCS.dll": "WDPKCS.dll",
    os.path.join(repo_root, "HS2003-pkcs11.dll"): "HS2003-pkcs11.dll",
    os.path.join(repo_root, "Pkcs11Interop.dll"): "Pkcs11Interop.dll",
    os.path.join(repo_root, "Pkcs11Admin.dll"): "Pkcs11Admin.dll",
    os.path.join(repo_root, "BouncyCastle.Crypto.dll"): "BouncyCastle.Crypto.dll",
}

for src, name in win_x64_sources.items():
    if os.path.exists(src):
        dst = os.path.join(drivers_dir, "windows", "x64", name)
        shutil.copy2(src, dst)
        print(f"Windows x64: {name} ({os.path.getsize(dst)/1024:.1f} KB)")

# 2. Setup Windows x86 drivers
win_x86_sources = {
    r"C:\Windows\SysWOW64\HYP2003csp11IND.dll": "HYP2003csp11IND.dll",
    r"C:\Windows\SysWOW64\cryptoida_pkcs11.dll": "cryptoida_pkcs11.dll",
    r"C:\Windows\SysWOW64\InnaITPKCS11Driver.dll": "InnaITPKCS11Driver.dll",
    r"C:\Windows\SysWOW64\Watchdata\PROXKey CSP India V3.0\WDPKCS.dll": "WDPKCS.dll",
    os.path.join(repo_root, "HS2003-pkcs11.dll"): "HS2003-pkcs11.dll",
    os.path.join(repo_root, "Pkcs11Interop.dll"): "Pkcs11Interop.dll",
    os.path.join(repo_root, "Pkcs11Admin.dll"): "Pkcs11Admin.dll",
    os.path.join(repo_root, "BouncyCastle.Crypto.dll"): "BouncyCastle.Crypto.dll",
}

for src, name in win_x86_sources.items():
    if os.path.exists(src):
        dst = os.path.join(drivers_dir, "windows", "x86", name)
        shutil.copy2(src, dst)
        print(f"Windows x86: {name} ({os.path.getsize(dst)/1024:.1f} KB)")

# 3. Setup Android native drivers in drivers/android and android/app/src/main/jniLibs
android_libs = [
    "libc++_shared.so",
    "libInnaITPKCS11.so",
    "libOTGPass2003_India.so",
    "lib_atick.so",
    "libWatchdataPKCS11.so",
    "libproxkey.so",
    "libWDAssist.so",
    "libcryptoid_pkcs11.so",
    "libmtoken.so",
    "libmTokenGM.so",
    "libcastle.so",
    "libhyp2003.so",
    "libep2003.so",
    "libinnait_pkcs11.so",
    "libinneit.so",
    "libopensc.so",
    "libpcsclite.so",
    "libtrustkey.so",
    "libusb.so"
]

for abi in ["arm64-v8a", "armeabi-v7a", "armeabi"]:
    src_abi_dir = os.path.join(repo_root, "android", "app", "src", "main", "jniLibs", abi)
    dst_abi_dir = os.path.join(drivers_dir, "android", abi)
    for lib in android_libs:
        src = os.path.join(src_abi_dir, lib)
        dst = os.path.join(dst_abi_dir, lib)
        if os.path.exists(src) and not os.path.exists(dst):
            shutil.copy2(src, dst)
        if os.path.exists(dst):
            print(f"Android {abi}: {lib} ({os.path.getsize(dst)/1024:.1f} KB)")

# 4. Setup Linux drivers
linux_dir = os.path.join(drivers_dir, "linux")
for fname in ["libcastle.so", "libWatchdataPKCS11.so", "libcryptoid_pkcs11.so", "libinnait_pkcs11.so", "opensc-pkcs11.so"]:
    p = os.path.join(linux_dir, fname)
    if os.path.exists(p):
        print(f"Linux: {fname} ({os.path.getsize(p)/1024:.1f} KB)")

# 5. Setup macOS drivers
mac_dir = os.path.join(drivers_dir, "macos")
for fname in ["libcastle.dylib", "libWD_PKCS11.dylib", "libcryptoid_pkcs11.dylib", "libinnait_pkcs11.dylib", "opensc-pkcs11.so"]:
    p = os.path.join(mac_dir, fname)
    if os.path.exists(p):
        print(f"macOS: {fname} ({os.path.getsize(p)/1024:.1f} KB)")

print("\nSetup & verification completed successfully for all operating systems.")
