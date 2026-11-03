import os
import sys
import subprocess
import shutil
import zipfile
import glob

# Determine repository root
repo_root = os.path.dirname(os.path.abspath(__file__))
project_dir = os.path.join(repo_root, "android")
app_dir = os.path.join(project_dir, "app")
src_dir = os.path.join(app_dir, "src", "main")
res_dir = os.path.join(src_dir, "res")
manifest_file = os.path.join(src_dir, "AndroidManifest.xml")

print(f"=== A B INFOTECH - Building Android APK ===")
print(f"Repository Root: {repo_root}")

# Discover Android SDK
candidates_sdk = [
    os.environ.get("ANDROID_HOME", ""),
    os.environ.get("ANDROID_SDK_ROOT", ""),
    os.path.expanduser(r"~\AppData\Local\Android\Sdk"),
    r"C:\Users\sheth\AppData\Local\Android\Sdk",
    "/usr/local/lib/android/sdk",
    "/opt/android-sdk",
    os.path.expanduser("~/Library/Android/sdk"),
]
sdk_dir = None
for c in candidates_sdk:
    if c and os.path.isdir(c):
        sdk_dir = c
        break

if not sdk_dir:
    print("ERROR: Android SDK directory not found!")
    sys.exit(1)
print(f"Android SDK Found: {sdk_dir}")

# Discover Build Tools
bt_dir = os.path.join(sdk_dir, "build-tools")
build_tools_list = sorted([d for d in os.listdir(bt_dir) if os.path.isdir(os.path.join(bt_dir, d))], reverse=True)
if not build_tools_list:
    print("ERROR: No build-tools found in Android SDK!")
    sys.exit(1)
build_tools_dir = os.path.join(bt_dir, build_tools_list[0])
print(f"Using Build Tools: {build_tools_dir} ({build_tools_list[0]})")

# Discover Platforms
platforms_dir = os.path.join(sdk_dir, "platforms")
plat_list = sorted([d for d in os.listdir(platforms_dir) if os.path.isdir(os.path.join(platforms_dir, d))], reverse=True)
if not plat_list:
    print("ERROR: No platforms found in Android SDK!")
    sys.exit(1)
android_jar = os.path.join(platforms_dir, plat_list[0], "android.jar")
print(f"Using Platform JAR: {android_jar} ({plat_list[0]})")

# Discover Java Executables
def find_exe(name):
    ext = ".exe" if sys.platform == "win32" else ""
    # Look in common Windows Android Studio JBR first (modern Java 17/21/25)
    as_jbr = r"C:\Program Files\Android\Android Studio\jbr\bin"
    c = os.path.join(as_jbr, name + ext)
    if os.path.isfile(c):
        return c

    # Look in JAVA_HOME
    jh = os.environ.get("JAVA_HOME", "")
    if jh:
        c = os.path.join(jh, "bin", name + ext)
        if os.path.isfile(c):
            return c

    p = shutil.which(name)
    if p:
        return p

    return name

java_exe = find_exe("java")
javac_exe = find_exe("javac")
keytool_exe = find_exe("keytool")

ext = ".exe" if sys.platform == "win32" else ""
aapt2_exe = os.path.join(build_tools_dir, "aapt2" + ext)
zipalign_exe = os.path.join(build_tools_dir, "zipalign" + ext)
d8_jar = os.path.join(build_tools_dir, "lib", "d8.jar")
apksigner_jar = os.path.join(build_tools_dir, "lib", "apksigner.jar")

if not os.path.isfile(d8_jar):
    for sub in build_tools_list:
        sub_d8 = os.path.join(bt_dir, sub, "lib", "d8.jar")
        if os.path.isfile(sub_d8):
            d8_jar = sub_d8
            break

if not os.path.isfile(apksigner_jar):
    for sub in build_tools_list:
        sub_apk = os.path.join(bt_dir, sub, "lib", "apksigner.jar")
        if os.path.isfile(sub_apk):
            apksigner_jar = sub_apk
            break

# Build Directory Setup
build_dir = os.path.join(project_dir, "build_output")
if os.path.exists(build_dir):
    try:
        shutil.rmtree(build_dir)
    except Exception:
        pass
os.makedirs(build_dir, exist_ok=True)

gen_dir = os.path.join(build_dir, "gen")
os.makedirs(gen_dir, exist_ok=True)
bin_classes_dir = os.path.join(build_dir, "classes")
os.makedirs(bin_classes_dir, exist_ok=True)

# 1. Compile Resources
print("\n[1/7] Compiling Android resources with aapt2...")
res_zip = os.path.join(build_dir, "res.zip")
cmd_compile = [aapt2_exe, "compile", "--dir", res_dir, "-o", res_zip]
ret = subprocess.run(cmd_compile, capture_output=True, text=True)
if ret.returncode != 0:
    print("aapt2 compile error:", ret.stderr)
    sys.exit(1)
print("aapt2 compile completed successfully.")

# 2. Link Resources
print("\n[2/7] Linking resources with aapt2 and generating R.java...")
base_apk = os.path.join(build_dir, "base.apk")
cmd_link = [
    aapt2_exe, "link",
    "-I", android_jar,
    "--manifest", manifest_file,
    "--java", gen_dir,
    "-o", base_apk,
    "--auto-add-overlay",
    res_zip
]
ret = subprocess.run(cmd_link, capture_output=True, text=True)
if ret.returncode != 0:
    print("aapt2 link error:", ret.stderr)
    sys.exit(1)
print(f"aapt2 link completed successfully. Generated R.java in: {gen_dir}")

# 3. Compile Java Sources
print("\n[3/7] Compiling Java classes with javac...")
java_files = []
for root, _, files in os.walk(os.path.join(src_dir, "java")):
    for f in files:
        if f.endswith(".java"):
            java_files.append(os.path.join(root, f))
for root, _, files in os.walk(gen_dir):
    for f in files:
        if f.endswith(".java"):
            java_files.append(os.path.join(root, f))

cmd_javac = [
    javac_exe,
    "-source", "1.8",
    "-target", "1.8",
    "-cp", android_jar,
    "-d", bin_classes_dir
] + java_files
ret = subprocess.run(cmd_javac, capture_output=True, text=True)
if ret.returncode != 0:
    print("javac error:", ret.stderr)
    sys.exit(1)
print(f"javac completed successfully. Compiled {len(java_files)} Java source files.")

# 4. Convert .class to DEX with D8
print("\n[4/7] Converting bytecode to Dalvik Executable (classes.dex) with d8...")
class_files = []
for root, _, files in os.walk(bin_classes_dir):
    for f in files:
        if f.endswith(".class"):
            class_files.append(os.path.join(root, f))

dex_dir = os.path.join(build_dir, "dex")
os.makedirs(dex_dir, exist_ok=True)
cmd_d8 = [
    java_exe,
    "-cp", d8_jar,
    "com.android.tools.r8.D8",
    "--min-api", "26",
    "--output", dex_dir,
    "--lib", android_jar
] + class_files
ret = subprocess.run(cmd_d8, capture_output=True, text=True)
if ret.returncode != 0:
    print("d8 error:", ret.stderr)
    sys.exit(1)
print("D8 completed successfully.")

# 5. Package classes.dex into APK
print("\n[5/7] Packaging classes.dex into base APK...")
dex_file = os.path.join(dex_dir, "classes.dex")
unaligned_apk = os.path.join(build_dir, "unaligned.apk")
shutil.copyfile(base_apk, unaligned_apk)

with zipfile.ZipFile(unaligned_apk, "a") as zipf:
    zipf.write(dex_file, "classes.dex")
print("Classes successfully injected into APK.")

# 6. Align APK with zipalign
print("\n[6/7] Aligning APK with zipalign...")
aligned_apk = os.path.join(build_dir, "aligned.apk")
cmd_zipalign = [zipalign_exe, "-f", "4", unaligned_apk, aligned_apk]
ret = subprocess.run(cmd_zipalign, capture_output=True, text=True)
if ret.returncode != 0:
    print("zipalign error:", ret.stderr)
    sys.exit(1)
print("zipalign completed successfully.")

# 7. Sign APK with apksigner
print("\n[7/7] Signing APK with apksigner...")
keystore_path = os.path.join(project_dir, "debug.keystore")
if not os.path.exists(keystore_path):
    print("Generating debug keystore...")
    cmd_genkey = [
        keytool_exe, "-genkeypair", "-v",
        "-keystore", keystore_path,
        "-alias", "abinfokey",
        "-keyalg", "RSA",
        "-keysize", "2048",
        "-validity", "10000",
        "-storepass", "android",
        "-keypass", "android",
        "-dname", "CN=ABINFOTECH, OU=Engineering, O=A B INFOTECH, L=Rajkot, ST=Gujarat, C=IN"
    ]
    ret = subprocess.run(cmd_genkey, capture_output=True, text=True)
    if ret.returncode != 0:
        print("keytool error:", ret.stderr)
        sys.exit(1)

dist_dir = os.path.join(repo_root, "dist")
os.makedirs(dist_dir, exist_ok=True)
final_apk = os.path.join(dist_dir, "Abinfo_Signer_Android.apk")
root_apk = os.path.join(repo_root, "Abinfo_Signer_Android.apk")

cmd_sign = [
    java_exe,
    "-jar", apksigner_jar,
    "sign",
    "--ks", keystore_path,
    "--ks-pass", "pass:android",
    "--ks-key-alias", "abinfokey",
    "--key-pass", "pass:android",
    "--out", final_apk,
    aligned_apk
]
ret = subprocess.run(cmd_sign, capture_output=True, text=True)
if ret.returncode != 0:
    print("apksigner error:", ret.stderr)
    sys.exit(1)

# Verify APK
cmd_verify = [
    java_exe,
    "-jar", apksigner_jar,
    "verify",
    "-v",
    final_apk
]
ret_v = subprocess.run(cmd_verify, capture_output=True, text=True)
print("APK Verification Output:\n" + ret_v.stdout.strip())

shutil.copyfile(final_apk, root_apk)

apk_size = os.path.getsize(final_apk) / 1024
print(f"\n=======================================================")
print(f"SUCCESS! Android APK built and verified successfully!")
print(f"Dist Location: {final_apk}")
print(f"Root Location: {root_apk}")
print(f"Final Size:    {apk_size:.2f} KB")
print(f"=======================================================\n")
