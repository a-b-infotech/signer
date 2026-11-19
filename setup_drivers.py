import os
import shutil

repo_root = r"C:\xampp\htdocs\abinfo_signer"
drivers_dir = os.path.join(repo_root, "drivers")

os.makedirs(os.path.join(drivers_dir, "windows", "x64"), exist_ok=True)
os.makedirs(os.path.join(drivers_dir, "windows", "x86"), exist_ok=True)
os.makedirs(os.path.join(drivers_dir, "macos"), exist_ok=True)
os.makedirs(os.path.join(drivers_dir, "linux"), exist_ok=True)
os.makedirs(os.path.join(drivers_dir, "android", "arm64-v8a"), exist_ok=True)
os.makedirs(os.path.join(drivers_dir, "android", "armeabi-v7a"), exist_ok=True)
os.makedirs(os.path.join(drivers_dir, "android", "armeabi"), exist_ok=True)

# 1. Copy Windows x64 drivers
win_x64_sources = {
    r"C:\Windows\System32\HYP2003csp11IND.dll": "HYP2003csp11IND.dll",
    r"C:\Windows\System32\cryptoida_pkcs11.dll": "cryptoida_pkcs11.dll",
    r"C:\Windows\System32\SignatureP11.dll": "SignatureP11.dll",
    r"C:\Windows\System32\InnaITPKCS11Driver.dll": "InnaITPKCS11Driver.dll",
    r"C:\Windows\System32\Watchdata\PROXKey CSP India V3.0\WDPKCS.dll": "WDPKCS.dll",
    os.path.join(repo_root, "HS2003-pkcs11.dll"): "HS2003-pkcs11.dll",
}

for src, name in win_x64_sources.items():
    if os.path.exists(src):
        dst = os.path.join(drivers_dir, "windows", "x64", name)
        shutil.copy2(src, dst)
        print(f"Copied Windows x64: {name} ({os.path.getsize(dst)/1024:.1f} KB)")

# 2. Copy Windows x86 drivers
win_x86_sources = {
    r"C:\Windows\SysWOW64\HYP2003csp11IND.dll": "HYP2003csp11IND.dll",
    r"C:\Windows\SysWOW64\cryptoida_pkcs11.dll": "cryptoida_pkcs11.dll",
    r"C:\Windows\SysWOW64\InnaITPKCS11Driver.dll": "InnaITPKCS11Driver.dll",
    r"C:\Windows\SysWOW64\Watchdata\PROXKey CSP India V3.0\WDPKCS.dll": "WDPKCS.dll",
}

for src, name in win_x86_sources.items():
    if os.path.exists(src):
        dst = os.path.join(drivers_dir, "windows", "x86", name)
        shutil.copy2(src, dst)
        print(f"Copied Windows x86: {name} ({os.path.getsize(dst)/1024:.1f} KB)")

# 3. Copy Android native libraries from temp_reference_files
android_sources = {
    os.path.join(repo_root, "temp_reference_files", "unused_so_files", "arm64-v8a", "libOTGPass2003_India.so"): os.path.join(drivers_dir, "android", "arm64-v8a", "libOTGPass2003_India.so"),
    os.path.join(repo_root, "temp_reference_files", "unused_so_files", "arm64-v8a", "libInnaITPKCS11.so"): os.path.join(drivers_dir, "android", "arm64-v8a", "libInnaITPKCS11.so"),
    os.path.join(repo_root, "temp_reference_files", "unused_so_files", "armeabi-v7a", "libOTGPass2003_India.so"): os.path.join(drivers_dir, "android", "armeabi-v7a", "libOTGPass2003_India.so"),
    os.path.join(repo_root, "temp_reference_files", "unused_so_files", "armeabi", "libOTGPass2003_India.so"): os.path.join(drivers_dir, "android", "armeabi", "libOTGPass2003_India.so"),
}

for src, dst in android_sources.items():
    if os.path.exists(src):
        shutil.copy2(src, dst)
        print(f"Copied Android library: {os.path.basename(dst)} ({os.path.getsize(dst)/1024:.1f} KB)")

# Also copy libInnaITPKCS11.so into android/app/src/main/jniLibs/arm64-v8a/
in_src = os.path.join(repo_root, "temp_reference_files", "unused_so_files", "arm64-v8a", "libInnaITPKCS11.so")
in_dst = os.path.join(repo_root, "android", "app", "src", "main", "jniLibs", "arm64-v8a", "libInnaITPKCS11.so")
if os.path.exists(in_src):
    shutil.copy2(in_src, in_dst)
    print("Injected libInnaITPKCS11.so into android jniLibs/arm64-v8a")

print("Setup completed successfully.")
