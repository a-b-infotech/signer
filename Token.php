<?php
session_start();

// Set Timezone to India to ensure EXACT time matching for expiration
date_default_timezone_set('Asia/Kolkata');

// ==========================================
// 1. DATABASE CONFIGURATION FOR LICENSE CHECK
// ==========================================
$db_host = 'sql302.ezyro.com';
$db_user = 'ezyro_37092101';            // DB username
$db_pass = 'abhi@123';                // DB password
$db_name = 'ezyro_37092101_fj';       // DB name
$table_name = 'license_keys';         // Table name

function getDbConnection($db_host, $db_user, $db_pass, $db_name) {
    try {
        $conn = mysqli_init();
        if (!$conn) return null;
        $conn->options(MYSQLI_OPT_CONNECT_TIMEOUT, 3);
        if (@$conn->real_connect($db_host, $db_user, $db_pass, $db_name)) {
            return $conn;
        }
    } catch (Exception $e) {}
    return null;
}

// AJAX Endpoint to verify license from the database
if (isset($_GET['action']) && $_GET['action'] === 'verify_license') {
    header('Content-Type: application/json');
    $key = $_POST['key'] ?? ($_GET['key'] ?? '');

    // Developer Bypass
    if ($key === 'ABI-MASTER-PASS') {
        echo json_encode(['status' => 'active', 'tier' => 'pro']);
        exit;
    }

    $conn = getDbConnection($db_host, $db_user, $db_pass, $db_name);
    if (!$conn || $conn->connect_error) {
        echo json_encode(['status' => 'error', 'message' => 'DB Connection failed']);
        exit;
    }

    $stmt = $conn->prepare("SELECT status, expiredate, license_tier FROM $table_name WHERE license_key = ? LIMIT 1");
    if ($stmt) {
        $stmt->bind_param("s", $key);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($row = $result->fetch_assoc()) {
            if ($row['status'] !== 'active') {
                echo json_encode(['status' => 'inactive']);
            } 
            // Checks Date AND EXACT Time (Hours:Minutes:Seconds) against current IST time
            elseif (!empty($row['expiredate']) && $row['expiredate'] !== 'never' && strtotime($row['expiredate']) < time()) {
                echo json_encode(['status' => 'expired']);
            } else {
                $tier = (!empty($row['license_tier']) && strtolower($row['license_tier']) === 'basic') ? 'basic' : 'pro';
                echo json_encode(['status' => 'active', 'tier' => $tier]);
            }
        } else {
            echo json_encode(['status' => 'invalid']);
        }
        $stmt->close();
    } else {
        echo json_encode(['status' => 'error', 'message' => 'Query error']);
    }
    
    $conn->close();
    exit;
}

// Desktop App Browser Sync Endpoint
if (isset($_GET['action']) && $_GET['action'] === 'browser_sync') {
    $license_key = isset($_REQUEST['key']) ? trim($_REQUEST['key']) : '';
    
    if (empty($license_key)) {
        header("Location: http://127.0.0.1:5000/api/sync_callback?status=invalid");
        exit;
    }

    if ($license_key === 'ABI-MASTER-PASS') {
        header("Location: http://127.0.0.1:5000/api/sync_callback?status=active&id=1&key=ABI-MASTER-PASS&status_val=active&tier=pro&client_email=" . urlencode("sales@a-b-infotech.in") . "&activated_at=" . urlencode(date('Y-m-d H:i:s')) . "&expiredate=never");
        exit;
    }

    $conn = getDbConnection($db_host, $db_user, $db_pass, $db_name);
    if ($conn) {
        $stmt = $conn->prepare("SELECT id, license_key, status, expiredate, license_tier, client_email, activated_at FROM $table_name WHERE license_key = ? LIMIT 1");
        if ($stmt) {
            $stmt->bind_param("s", $license_key);
            $stmt->execute();
            $result = $stmt->get_result();

            if ($row = $result->fetch_assoc()) {
                $tier = (!empty($row['license_tier']) && strtolower($row['license_tier']) === 'basic') ? 'basic' : 'pro';
                
                if (strtolower($row['status']) === 'inactive') {
                    if (empty($row['expiredate']) || $row['expiredate'] === '0000-00-00 00:00:00') {
                        $upd = $conn->prepare("UPDATE $table_name SET status = 'active', activated_at = NOW(), expiredate = DATE_ADD(NOW(), INTERVAL 1 YEAR) WHERE id = ?");
                        if ($upd) {
                            $upd->bind_param("i", $row['id']);
                            $upd->execute();
                            $upd->close();
                        }
                        $row['expiredate'] = date('Y-m-d H:i:s', strtotime('+1 year'));
                    } else {
                        $upd = $conn->prepare("UPDATE $table_name SET status = 'active', activated_at = NOW() WHERE id = ?");
                        if ($upd) {
                            $upd->bind_param("i", $row['id']);
                            $upd->execute();
                            $upd->close();
                        }
                    }
                    $row['status'] = 'active';
                    $row['activated_at'] = date('Y-m-d H:i:s');
                }

                $client_email = $row['client_email'] ?? '';
                $activated_at = $row['activated_at'] ?? '';
                $expiredate = !empty($row['expiredate']) ? $row['expiredate'] : 'never';
                $id = $row['id'];

                if ($row['status'] !== 'active') {
                    header("Location: http://127.0.0.1:5000/api/sync_callback?status=" . urlencode($row['status']) . "&id=" . urlencode($id) . "&key=" . urlencode($license_key) . "&tier=" . urlencode($tier) . "&client_email=" . urlencode($client_email) . "&activated_at=" . urlencode($activated_at) . "&expiredate=" . urlencode($expiredate));
                } elseif (!empty($row['expiredate']) && $row['expiredate'] !== 'never' && strtotime($row['expiredate']) < time()) {
                    header("Location: http://127.0.0.1:5000/api/sync_callback?status=expired&id=" . urlencode($id) . "&key=" . urlencode($license_key) . "&tier=" . urlencode($tier) . "&client_email=" . urlencode($client_email) . "&activated_at=" . urlencode($activated_at) . "&expiredate=" . urlencode($expiredate));
                } else {
                    header("Location: http://127.0.0.1:5000/api/sync_callback?status=active&id=" . urlencode($id) . "&key=" . urlencode($license_key) . "&status_val=" . urlencode($row['status']) . "&tier=" . urlencode($tier) . "&client_email=" . urlencode($client_email) . "&activated_at=" . urlencode($activated_at) . "&expiredate=" . urlencode($expiredate));
                }
                $stmt->close();
                $conn->close();
                exit;
            }
            $stmt->close();
        }
        $conn->close();
    }

    header("Location: http://127.0.0.1:5000/api/sync_callback?status=active&id=1&key=" . urlencode($license_key) . "&status_val=active&tier=pro&client_email=" . urlencode("sales@a-b-infotech.in") . "&activated_at=" . urlencode(date('Y-m-d H:i:s')) . "&expiredate=never");
    exit;
}
// ==========================================

$config = [
    'uploadDir' => 'uploads/',
    'allowedTypes' => ['pdf'],
    'maxFileSize' => 50 * 1024 * 1024,
];

if (!is_dir($config['uploadDir'])) {
    mkdir($config['uploadDir'], 0755, true);
}

function sanitizeInput($input) {
    return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
}

if (isset($_GET['action']) && $_GET['action'] === 'reset') {
    if (isset($_SESSION['pdfPath']) && file_exists($_SESSION['pdfPath'])) {
        @unlink($_SESSION['pdfPath']);
    }
    unset($_SESSION['pdfPath'], $_SESSION['fileName']);
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

$uploadError = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['pdfFile'])) {
    $fileName = basename($_FILES['pdfFile']['name']);
    $fileExtension = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));

    if ($fileExtension !== 'pdf') {
        $uploadError = "Only PDF files are allowed.";
    } else {
        $uniqueFileName = uniqid('pdf_', true) . '.pdf';
        $filePath = $config['uploadDir'] . $uniqueFileName;

        if (move_uploaded_file($_FILES['pdfFile']['tmp_name'], $filePath)) {
            $_SESSION['pdfPath'] = $filePath;
            $_SESSION['fileName'] = $fileName;
            header("Location: " . $_SERVER['PHP_SELF']);
            exit;
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>A B INFOTECH - PDF Signer</title>

<script src="https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js"></script>

<!-- Google Tag Manager & Microsoft Clarity Scripts -->
<script>
    (function(w, d, s, l, i) {
        w[l] = w[l] || [];
        w[l].push({ 'gtm.start': new Date().getTime(), event: 'gtm.js' });
        var f = d.getElementsByTagName(s)[0],
            j = d.createElement(s),
            dl = l != 'dataLayer' ? '&l=' + l : '';
        j.async = true;
        j.src = 'https://www.googletagmanager.com/gtm.js?id=' + i + dl;
        f.parentNode.insertBefore(j, f);
    })(window, document, 'script', 'dataLayer', 'GTM-PRJ7VHLR');
</script>
<script type="text/javascript">
    (function(c,l,a,r,i,t,y){
        c[a]=c[a]||function(){(c[a].q=c[a].q||[]).push(arguments)};
        t=l.createElement(r);t.async=1;t.src="https://www.clarity.ms/tag/"+i;
        y=l.getElementsByTagName(r)[0];y.parentNode.insertBefore(t,y);
    })(window, document, "clarity", "script", "ujg2qgx1l3");
</script>

<style>
body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: #0f2027;
    color: #fff;
    margin: 0;
    min-height: 100vh;
    overflow-x: hidden;
}
    
#bg-img {
    position: fixed;
    top: 0; left: 0; width: 100%; height: 100%;
    object-fit: cover; z-index: -1; opacity: 0.8;
}

.glass-card {
    background: rgba(25, 30, 40, 0.75);
    backdrop-filter: blur(12px);
    border-radius: 15px;
    border: 1px solid rgba(255, 255, 255, 0.1);
    box-shadow: 0 15px 35px rgba(0, 0, 0, 0.5);
}

.btn-abi {
    border: none; border-radius: 8px; padding: 12px 20px;
    cursor: pointer; font-weight: 700; transition: 0.3s;
    font-size: 14px;
}

.btn-cyan { background: #0dcaf0; color: #000; }
.btn-cyan:hover { background: #0baccc; }
.btn-success { background: #2ecc71; color: white; }
.btn-success:hover { background: #27ae60; }
.btn-danger { background: #e74c3c; color: white; }
.btn-danger:hover { background: #c0392b; }
.btn-warning { background: #f39c12; color: #fff; }
.btn-warning:hover { background: #e67e22; }

.glass-input {
    width: 100%; padding: 10px; border-radius: 6px;
    border: 1px solid rgba(13, 202, 240, 0.4);
    background: rgba(0, 0, 0, 0.3); color: white;
    margin-bottom: 15px; box-sizing: border-box;
}

.custom-file-upload {
    display: block; padding: 30px;
    border: 2px dashed rgba(13, 202, 240, 0.5);
    border-radius: 12px; text-align: center;
    cursor: pointer; margin-bottom: 20px;
    transition: 0.2s;
}
.custom-file-upload:hover {
    border-color: #0dcaf0;
    background: rgba(13, 202, 240, 0.05);
}

#pdfFile { display: none; }

.workspace-container {
    display: flex; gap: 20px; width: 95%; max-width: 1400px;
    margin: 20px auto; height: 90vh; overflow: hidden;
}

.pdf-sidebar {
    flex: 0 0 320px; padding: 20px; overflow-y: auto;
    background: rgba(25, 30, 40, 0.9); border-radius: 12px; box-sizing: border-box;
}

.pdf-panel {
    flex: 1; min-width: 0; display: flex; flex-direction: column;
    background: rgba(0, 0, 0, 0.3); border-radius: 12px; overflow: hidden;
}

.pdf-toolbar {
    padding: 15px; background: rgba(25, 30, 40, 0.95);
    display: flex; justify-content: space-between; align-items: center;
    flex-wrap: wrap; gap: 10px;
}

.pdf-container {
    flex: 1; overflow: auto; padding: 15px; display: flex;
    justify-content: center; align-items: flex-start;
}

.pdf-wrapper {
    position: relative; display: inline-block; background: white;
    box-shadow: 0 5px 15px rgba(0, 0, 0, 0.3);
}

.interaction-layer {
    position: absolute; top: 0; left: 0; right: 0; bottom: 0;
}

.active-layer { cursor: crosshair; background: rgba(13, 202, 240, 0.08); }
.selection-box { position: absolute; border: 2px dashed #0dcaf0; background: rgba(13, 202, 240, 0.2); }
.signature-area {
    position: absolute; border: 2px solid #2ecc71; background: rgba(46, 204, 113, 0.2);
    color: #27ae60; font-size: 13px; display: flex; justify-content: center; align-items: center;
    font-weight: bold; text-align: center;
}

.area-item {
    background: rgba(0, 0, 0, 0.3); padding: 10px; border-radius: 8px;
    margin-bottom: 10px; display: flex; justify-content: space-between;
}

.logo {
    display: block; height: 80px; width: auto; background: white;
    border-radius: 8px; padding: 10px; margin-bottom: 20px;
}
.logo img { height: 100%; width: 100%; object-fit: contain; transition: transform 0.3s ease; }
.logo:hover img { transform: scale(1.05); }

@media(max-width: 992px) {
    .workspace-container { flex-direction: column; height: auto; min-height: 100vh; overflow: visible; }
    .pdf-sidebar { flex: none; width: 100%; order: 2; }
    .pdf-panel { flex: none; height: 65vh; order: 1; }
    .pdf-toolbar { flex-direction: column; align-items: stretch; }
    .pdf-toolbar > div { display: flex; justify-content: space-between; margin-bottom: 10px; }
}
</style>
</head>
<body>

<!-- Dynamic Ads Container (Hidden by default, shown in demo mode or license expired) -->
<div class="ad-container" style="display:none; text-align:center; margin: 10px auto; max-width: 95%;">
    <!-- Google AdSense Block -->
    <ins class="adsbygoogle"
         style="display:block"
         data-ad-client="ca-pub-4544316411176795"
         data-ad-slot="YOUR_AD_SLOT_ID"
         data-ad-format="auto"
         data-full-width-responsive="true"></ins>
</div>

<!-- Overlays -->
<div id="offline-overlay" style="display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(15,32,39,0.95); z-index:9999; justify-content:center; align-items:center; flex-direction:column;">
    <div class="glass-card" style="padding:40px; text-align:center; max-width:420px; width:90%;">
        <h2 style="color:#e74c3c; margin-top:0;">⚠️ Software Required</h2>
        <p style="margin-bottom:25px; line-height:1.6;">You need to install and run the background A B INFOTECH software to connect your USB hardware token.</p>
        
        <a href="https://github.com/a-b-infotech/signer/releases/latest/download/Abinfo_Signer_Windows_Setup.exe" class="btn-abi btn-cyan" style="text-decoration:none; display:block; margin-bottom:10px; box-sizing:border-box;">📥 Download Latest Windows Setup</a>
        <a href="https://github.com/a-b-infotech/my-software/releases/download/1.0/Abinfo_Signer_Offline.exe" class="btn-abi btn-success" style="text-decoration:none; display:block; margin-bottom:15px; box-sizing:border-box;">🔐 Download Standalone Offline Edition</a>
        
        <button onclick="checkBackgroundServer()" class="btn-abi btn-cyan" style="width:100%;">↻ Retry Connection</button>
    </div>
</div>
   
<div id="update-overlay" style="display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(15,32,39,0.95); z-index:9998; justify-content:center; align-items:center; flex-direction:column;">
    <div class="glass-card" style="padding:40px; text-align:center; max-width:420px; width:90%;">
        <h2 style="color:#f39c12; margin-top:0;">🔄 Update Required</h2>
        <p style="margin-bottom:25px; line-height:1.6;">A new version of the Digital Signer is required to continue using the software.</p>
        
        <a href="https://github.com/a-b-infotech/signer/releases/latest/download/Abinfo_Signer_Windows_Setup.exe" class="btn-abi btn-cyan" style="text-decoration:none; display:block; margin-bottom:10px; box-sizing:border-box;">📥 Download Latest Windows Setup</a>
        <a href="https://github.com/a-b-infotech/my-software/releases/download/1.0/Abinfo_Signer_Offline.exe" class="btn-abi btn-success" style="text-decoration:none; display:block; box-sizing:border-box;">🔐 Download Offline Version</a>
    </div>
</div>

<div id="expired-overlay" style="display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(15,32,39,0.95); z-index:9997; justify-content:center; align-items:center; flex-direction:column;">
    <div class="glass-card" style="padding:40px; text-align:center; max-width:420px; width:90%;">
        <h2 style="color:#e74c3c; margin-top:0;">⏳ License Expired</h2>
        <p style="margin-bottom:25px; line-height:1.6;">Your software license has expired. Please renew your license to continue using the Digital Signer.</p>
        
        <a href="https://pay.a-b-infotech.in/license.php" target="_blank" class="btn-abi btn-warning" style="text-decoration:none; display:block; margin-bottom:15px; box-sizing:border-box; font-size: 16px;">💳 Renew / Purchase License Online</a>
        
        <div style="background:rgba(0,0,0,0.3); padding:15px; border-radius:8px; margin-bottom:20px;">
            <p style="margin:5px 0; color:#aaa;">Manual Contact:</p>
            <p style="margin:5px 0; font-size:18px; font-weight:bold; color:#2ecc71;">📞 <a href="tel:7016797720" style="color:#2ecc71; text-decoration:none;">7016797720</a></p>
            <p style="margin:5px 0; font-size:16px; font-weight:bold; color:#0dcaf0;">✉️ <a href="mailto:sales@a-b-infotech.in" style="color:#0dcaf0; text-decoration:none;">sales@a-b-infotech.in</a></p>
        </div>
        <a href="https://api.whatsapp.com/send?phone=917016797720&text=I%20want%20to%20renew%20my%20PDF%20Signer%20License" target="_blank" class="btn-abi btn-success" style="text-decoration:none; display:block; box-sizing:border-box;">💬 Contact on WhatsApp</a>
    </div>
</div>

<!-- Core System Checks & Ad Loading -->
<script>
window.isDemoMode = false;
window.adsLoaded = false;

function loadAds() {
    if (!window.adsLoaded) {
        const script = document.createElement('script');
        script.async = true;
        script.src = "https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-4544316411176795";
        script.crossOrigin = "anonymous";
        document.head.appendChild(script);
        window.adsLoaded = true;
        
        setTimeout(() => {
            try { (adsbygoogle = window.adsbygoogle || []).push({}); } catch (e) {}
        }, 500);
    }
    document.querySelectorAll('.ad-container').forEach(el => el.style.display = 'block');
}

function removeAds() {
    document.querySelectorAll('.ad-container').forEach(el => el.style.display = 'none');
}

function parseSemver(v) {
    if (!v) return [0, 0, 0];
    return String(v).replace(/^v/i, '').split('.').map(n => parseInt(n) || 0);
}

function isOlderThan(vClient, vMin) {
    const c = parseSemver(vClient);
    const m = parseSemver(vMin);
    for (let i = 0; i < 3; i++) {
        const cv = c[i] || 0;
        const mv = m[i] || 0;
        if (cv < mv) return true;
        if (cv > mv) return false;
    }
    return false;
}

async function checkBackgroundServer() {
    try {
        const res = await fetch('http://127.0.0.1:5000/api/health', { mode: 'cors' });
        if (res.ok) {
            document.getElementById('offline-overlay').style.display = 'none';
            const data = await res.json();
            
            if (data.version) {
                document.querySelectorAll('.app-version-display').forEach(el => {
                    el.textContent = 'v' + data.version;
                });
            }
            
            if (data.demo === true) {
                // Not activated
                window.isDemoMode = true;
                const demoMsg = document.getElementById('demoWarningMsg');
                if (demoMsg) demoMsg.style.display = 'block';
                document.getElementById('update-overlay').style.display = 'none';
                document.getElementById('expired-overlay').style.display = 'none';
                loadAds(); // Trigger Ads for Demo Mode
            } else {
                // Activated, verify expiration with database
                const formData = new FormData();
                formData.append('key', data.key || '');

                let verifyData = { status: 'active' };
                try {
                    const verifyRes = await fetch('?action=verify_license', { method: 'POST', body: formData });
                    verifyData = await verifyRes.json();
                } catch (ve) {
                    verifyData = { status: 'active' }; // Fallback to active if offline
                }

                if (verifyData.status === 'expired') {
                    document.getElementById('expired-overlay').style.display = 'flex';
                    document.getElementById('update-overlay').style.display = 'none';
                    loadAds(); // Trigger Ads for Expired License
                    return; 
                } else if (verifyData.status === 'active') {
                    document.getElementById('expired-overlay').style.display = 'none';
                    window.isDemoMode = false;
                    const demoMsg = document.getElementById('demoWarningMsg');
                    if (demoMsg) demoMsg.style.display = 'none';
                    removeAds(); // Hide Ads for Valid Users
                    
                    // Check if client version is older than required 2.0.0
                    if (data.version && isOlderThan(data.version, '2.0.0')) {
                        document.getElementById('update-overlay').style.display = 'flex';
                    } else {
                        document.getElementById('update-overlay').style.display = 'none';
                    }
                } else {
                    window.isDemoMode = true;
                    const demoMsg = document.getElementById('demoWarningMsg');
                    if (demoMsg) demoMsg.style.display = 'block';
                    document.getElementById('expired-overlay').style.display = 'none';
                    loadAds();
                }
            }
        } else {
            throw new Error('Server not OK');
        }
    } catch (e) {
        document.getElementById('offline-overlay').style.display = 'flex';
        document.getElementById('update-overlay').style.display = 'none';
        document.getElementById('expired-overlay').style.display = 'none';
    }
}
window.addEventListener('load', checkBackgroundServer);
setInterval(checkBackgroundServer, 2000); 
</script>

<img src="bg-anim.gif" id="bg-img" onerror="this.style.display='none';">

<?php if (!isset($_SESSION['pdfPath'])): ?>

<!-- UPLOAD SCREEN -->
<div style="max-width:600px;margin:10vh auto; padding: 0 15px;">
    <div class="glass-card" style="padding:40px;">
        <a href="Token.php" class="logo-section" style="text-align:center;color:#0dcaf0;text-decoration:none; display:block;">
            <span class="logo">
                <img src="abinfo.png" alt="A B INFOTECH" onerror="this.src='app_icon.png';">
            </span>
        </a>
        <h2 style="text-align:center;color:#0dcaf0; margin-top: 10px;">
            A B INFOTECH - Digital Signer <span class="app-version-display" style="font-size: 14px; color: #aaa; margin-left: 5px;"></span>
        </h2>

        <?php if ($uploadError): ?>
            <div style="color:#ff6b6b;margin-bottom:15px; text-align:center;"><?= $uploadError ?></div>
        <?php endif; ?>

        <form method="POST" enctype="multipart/form-data">
            <label for="pdfFile" class="custom-file-upload">
                <span id="file-chosen">📁 Click here to Select PDF Document</span>
            </label>
            <input type="file" id="pdfFile" name="pdfFile" accept=".pdf" required>
            <button type="submit" class="btn-abi btn-cyan" style="width:100%; font-size:16px;">Upload & Open PDF</button>
        </form>
    </div>
</div>

<script>
document.getElementById('pdfFile').addEventListener('change', function(){
    if (this.files && this.files[0]) {
        document.getElementById('file-chosen').textContent = "Selected: " + this.files[0].name;
    }
});
</script>

<?php else: ?>

<!-- SIGNING WORKSPACE -->
<div class="workspace-container">
    <div class="pdf-sidebar">
        <h3 style="color:#0dcaf0; margin-top:0;">Signature Settings <span class="app-version-display" style="font-size: 12px; color: #aaa; margin-left: 5px;"></span></h3>
        <p style="word-break: break-all; font-size: 13px; color: #cbd5e1;"><?= sanitizeInput($_SESSION['fileName']) ?></p>

        <form id="signForm">
            <label style="font-size: 13px; color: #94a3b8; font-weight: 600;">USB Token Driver</label>
            <select class="glass-input" id="driverDropdownWorkspace"></select>

            <label style="font-size: 13px; color: #94a3b8; font-weight: 600;">Digital Certificate</label>
            <select class="glass-input" name="certAlias" required>
                <option value="">-- Choose Certificate --</option>
            </select>

            <label style="font-size: 13px; color: #94a3b8; font-weight: 600;">USB Hardware Token PIN</label>
            <input type="password" class="glass-input" name="tokenPassword" placeholder="Enter Token PIN / Password" required>
            <input type="hidden" id="signatureAreasInput">

            <div id="signatureList" style="min-height:100px; margin-bottom:20px; font-size:13px;">
                No signatures drawn yet.
            </div>

            <div id="demoWarningMsg" style="display:none; color: #e74c3c; font-size: 13px; margin-bottom: 15px; font-weight: bold; text-align: center; border: 1px solid #e74c3c; padding: 10px; border-radius: 5px; background: rgba(231, 76, 60, 0.1);">
                <span style="font-size: 14px; text-decoration: underline;">DEMO Version Active</span><br><br>
                <a href="https://pay.a-b-infotech.in/license.php" target="_blank" style="display:inline-block; margin-bottom:8px; padding:6px 12px; background:#f39c12; color:#fff; text-decoration:none; border-radius:4px;">💳 Buy / Renew License Online</a><br>
                Or Contact: 7016797720 / <a href="https://api.whatsapp.com/send?phone=917016797720&text=Licence%20PDF%20Key" target='_blank' style="color:#2ecc71;">WhatsApp</a>
            </div>

            <button type="submit" class="btn-abi btn-success" id="finalSignBtn" disabled style="width: 100%; margin-bottom: 10px; font-size: 15px;">
                ✍️ Sign Document
            </button>

            <a href="?action=reset" class="btn-abi btn-danger" style="display:block; text-align:center; text-decoration:none;">Cancel / Close PDF</a>
        </form>
    </div>

    <div class="pdf-panel">
        <div class="pdf-toolbar">
            <div>
                <button id="prevPageBtn" class="btn-abi btn-cyan" style="padding: 8px 14px;">◀ Prev</button>
                <span style="margin:0 15px; font-weight: 600;">Page <span id="currentPageNum">1</span> / <span id="totalPages">0</span></span>
                <button id="nextPageBtn" class="btn-abi btn-cyan" style="padding: 8px 14px;">Next ▶</button>
            </div>
            <div>
                <button id="clearAreasBtn" class="btn-abi btn-danger" style="margin-right: 10px; padding: 8px 14px;">🗑️ Clear Areas</button>
                <button id="selectAreaBtn" class="btn-abi btn-cyan" style="padding: 8px 14px;">✏️ Draw Signature Box</button>
            </div>
        </div>

        <div class="pdf-container">
            <div class="pdf-wrapper" id="pdfWrapper">
                <canvas id="pdfCanvas"></canvas>
                <div class="interaction-layer" id="interactionLayer"></div>
            </div>
        </div>
    </div>
</div>

<!-- Demo Notice Modal -->
<div id="licenseModal" style="display:none; position:fixed; top:50%; left:50%; transform:translate(-50%,-50%); background:rgba(15,32,39,0.95); padding:20px; border:1px solid #0dcaf0; border-radius:12px; z-index:9999; text-align:center; box-shadow: 0 20px 50px rgba(0,0,0,0.8);">
    <div class="glass-card" style="padding:30px; text-align:center; max-width:400px; width:90%; margin:auto;">
        <h3 style="color:#f39c12; margin-top:0;">DEMO Version Notice</h3>
        <p style="color:#e2e8f0; line-height:1.5;">Only <b>one signature area</b> is allowed in Demo Mode.</p>
        <p style="color:#94a3b8; font-size:13px;">Please purchase or activate a Pro License to unlock unlimited signature boxes and batch signing.</p>
        <a href="https://pay.a-b-infotech.in/license.php" target="_blank" style="display:inline-block; padding:10px 20px; background:#f39c12; color:#fff; text-decoration:none; border-radius:5px; margin-bottom:10px; width: 100%; box-sizing: border-box; font-weight:bold;">💳 Get License / Renew Now</a>
        <a href="https://api.whatsapp.com/send?phone=917016797720&text=Licence%20PDF%20Key" target="_blank" style="display:inline-block; padding:10px 20px; background:#25D366; color:#fff; text-decoration:none; border-radius:5px; width: 100%; box-sizing: border-box; font-weight:bold;">💬 Contact on WhatsApp</a>
        <br><br>
        <button onclick="document.getElementById('licenseModal').style.display='none';" class="btn-abi btn-cyan" style="width: 100%;">Close</button>
    </div>
</div>

<script>
document.addEventListener('DOMContentLoaded', function(){
    const LOCAL_SERVER = 'http://127.0.0.1:5000';
    const pdfjsLib = window['pdfjs-dist/build/pdf'];
    const canvas = document.getElementById('pdfCanvas');
    const ctx = canvas.getContext('2d');
    const interactionLayer = document.getElementById('interactionLayer');
    const pdfWrapper = document.getElementById('pdfWrapper');

    let pdfDoc = null;
    let pageNum = 1;
    let currentPdfHeight = 0;
    let pageRendering = false;
    let signatureAreas = [];
    let isSelecting = false;
    let currentArea = null;
    let tempBox = null;
    const scale = 1.3;

    async function loadDrivers(){
        try{
            const response = await fetch(`${LOCAL_SERVER}/api/drivers`);
            const drivers = await response.json();
            const select = document.getElementById('driverDropdownWorkspace');
            if(!select) return;
            select.innerHTML = '';
            drivers.forEach(driver => {
                const opt = document.createElement('option');
                opt.value = driver;
                opt.textContent = driver;
                select.appendChild(opt);
            });
            select.addEventListener('change', fetchCertificates);
            fetchCertificates();
        }catch(e){}
    }

    async function fetchCertificates(){
        const driver = document.getElementById('driverDropdownWorkspace');
        if(!driver) return;
        try{
            const response = await fetch(`${LOCAL_SERVER}/api/certificates?driver_name=${encodeURIComponent(driver.value)}`);
            const certs = await response.json();
            const certSelect = document.querySelector('select[name="certAlias"]');
            
            certSelect.innerHTML = '<option value="">-- Choose Certificate --</option>';
            certs.forEach(cert => {
                const opt = document.createElement('option');
                opt.value = cert.alias;
                let displayName = cert.subject;
                const match = cert.subject.match(/CN=([^,]+)/);
                if(match) displayName = match[1];
                opt.textContent = `${displayName} (${cert.source})`;
                certSelect.appendChild(opt);
            });
        }catch(e){}
    }

    pdfjsLib.getDocument('<?= str_replace("\\", "/", $_SESSION["pdfPath"]) ?>').promise.then(pdf => {
        pdfDoc = pdf;
        document.getElementById('totalPages').textContent = pdf.numPages;
        renderPage(pageNum);
    });

    function renderPage(num){
        pageRendering = true;
        pdfDoc.getPage(num).then(page => {
            const viewport = page.getViewport({ scale });
            currentPdfHeight = viewport.height;
            canvas.height = viewport.height;
            canvas.width = viewport.width;
            pdfWrapper.style.width = viewport.width + 'px';
            pdfWrapper.style.height = viewport.height + 'px';

            page.render({ canvasContext: ctx, viewport: viewport }).promise.then(() => {
                pageRendering = false;
                drawSavedAreas();
            });
        });
        document.getElementById('currentPageNum').textContent = num;
    }

    document.getElementById('prevPageBtn').addEventListener('click', () => {
        if(pageNum <= 1) return;
        pageNum--; renderPage(pageNum);
    });

    document.getElementById('nextPageBtn').addEventListener('click', () => {
        if(pageNum >= pdfDoc.numPages) return;
        pageNum++; renderPage(pageNum);
    });

    document.getElementById('clearAreasBtn').addEventListener('click', function() {
        signatureAreas = [];
        updateSignatureList();
        drawSavedAreas();
        if (tempBox) { tempBox.remove(); tempBox = null; }
        currentArea = null; isSelecting = false;
        interactionLayer.classList.remove('active-layer');
        const selectBtn = document.getElementById('selectAreaBtn');
        selectBtn.style.background = '#0dcaf0'; selectBtn.textContent = '✏️ Draw Signature Box';
    });

    document.getElementById('selectAreaBtn').addEventListener('click', function(){
        if (window.isDemoMode && signatureAreas.length >= 1) {
            document.getElementById('licenseModal').style.display = 'block';
            return;
        }
        isSelecting = !isSelecting;
        if (isSelecting) {
            this.style.background = '#0baccc'; this.textContent = '✏️ Selecting Area...';
        } else {
            this.style.background = '#0dcaf0'; this.textContent = '✏️ Draw Signature Box';
        }
        interactionLayer.classList.toggle('active-layer');
    });

    let startX, startY;

    interactionLayer.addEventListener('mousedown', e => {
        if(!isSelecting) return;
        const rect = interactionLayer.getBoundingClientRect();
        startX = e.clientX - rect.left; startY = e.clientY - rect.top;
        currentArea = { x:startX, y:startY, width:0, height:0 };
        tempBox = document.createElement('div');
        tempBox.className = 'selection-box';
        interactionLayer.appendChild(tempBox);
    });

    interactionLayer.addEventListener('mousemove', e => {
        if(!isSelecting || !currentArea) return;
        const rect = interactionLayer.getBoundingClientRect();
        currentArea.width = (e.clientX - rect.left) - startX;
        currentArea.height = (e.clientY - rect.top) - startY;
        tempBox.style.left = (currentArea.width < 0 ? startX + currentArea.width : startX) + 'px';
        tempBox.style.top = (currentArea.height < 0 ? startY + currentArea.height : startY) + 'px';
        tempBox.style.width = Math.abs(currentArea.width) + 'px';
        tempBox.style.height = Math.abs(currentArea.height) + 'px';
    });

    interactionLayer.addEventListener('mouseup', () => {
        if(!currentArea) return;

        if (window.isDemoMode && signatureAreas.length >= 1) {
            currentArea = null;
            if (tempBox) tempBox.remove();
            tempBox = null;
            isSelecting = false;
            interactionLayer.classList.remove('active-layer');
            document.getElementById('selectAreaBtn').style.background = '#0dcaf0';
            document.getElementById('selectAreaBtn').textContent = '✏️ Draw Signature Box';
            document.getElementById('licenseModal').style.display = 'block';
            return;
        }

        const x = currentArea.width < 0 ? startX + currentArea.width : startX;
        const y = currentArea.height < 0 ? startY + currentArea.height : startY;
        const w = Math.abs(currentArea.width);
        const h = Math.abs(currentArea.height);

        if (w > 10 && h > 10) {
            signatureAreas.push({
                page: pageNum,
                x: x / scale,
                y: (currentPdfHeight - y - h) / scale,
                width: w / scale,
                height: h / scale
            });
        }

        updateSignatureList();
        currentArea = null;
        if (tempBox) tempBox.remove();
        tempBox = null;
        isSelecting = false;
        interactionLayer.classList.remove('active-layer');
        const selectBtn = document.getElementById('selectAreaBtn');
        selectBtn.style.background = '#0dcaf0'; selectBtn.textContent = '✏️ Draw Signature Box';
        drawSavedAreas();
    });

    function drawSavedAreas(){
        interactionLayer.querySelectorAll('.signature-area, .selection-box').forEach(el => el.remove());
        signatureAreas.forEach((area, idx) => {
            if(area.page !== pageNum) return;
            const div = document.createElement('div');
            div.className = 'signature-area';
            div.style.left = (area.x * scale) + 'px';
            div.style.top = (currentPdfHeight - (area.y + area.height) * scale) + 'px';
            div.style.width = (area.width * scale) + 'px';
            div.style.height = (area.height * scale) + 'px';
            div.innerHTML = `✓ Digital Signature #${idx + 1}<br><span style="font-size:11px; opacity:0.85;">(Page ${area.page})</span>`;
            interactionLayer.appendChild(div);
        });
    }

    function updateSignatureList(){
        const list = document.getElementById('signatureList');
        list.innerHTML = '';
        if (signatureAreas.length === 0) {
            list.innerHTML = 'No signatures drawn yet.';
        } else {
            signatureAreas.forEach((a, i) => {
                list.innerHTML += `<div class="area-item"><span>Page ${a.page}</span><span>Box #${i+1} (${Math.round(a.width)}x${Math.round(a.height)} pt)</span></div>`;
            });
        }
        document.getElementById('signatureAreasInput').value = JSON.stringify(signatureAreas);
        document.getElementById('finalSignBtn').disabled = signatureAreas.length === 0;
    }

    document.getElementById('signForm').addEventListener('submit', async function(e){
        e.preventDefault();
        const certVal = document.querySelector('[name="certAlias"]').value;
        const passVal = document.querySelector('[name="tokenPassword"]').value;
        const driverVal = document.getElementById('driverDropdownWorkspace').value;

        if (!certVal) {
            alert("Please choose a Digital Certificate from the dropdown.");
            return;
        }
        if (!passVal) {
            alert("Please enter your USB Hardware Token PIN / Password.");
            return;
        }

        const signBtn = document.getElementById('finalSignBtn');
        const oldText = signBtn.innerHTML;
        signBtn.innerHTML = "⏳ Signing with Hardware Token...";
        signBtn.disabled = true;

        try{
            const formData = new FormData();
            const fileBlob = await fetch('<?= str_replace("\\", "/", $_SESSION["pdfPath"]) ?>').then(r => r.blob());

            formData.append('file', fileBlob, '<?= sanitizeInput($_SESSION["fileName"]) ?>');
            formData.append('certificate', JSON.stringify({ alias: certVal }));
            formData.append('areas', JSON.stringify(signatureAreas));
            formData.append('password', passVal);
            formData.append('driver_name', driverVal);

            const response = await fetch(`${LOCAL_SERVER}/api/sign`, { method:'POST', body:formData });

            if(!response.ok){
                const err = await response.json().catch(() => ({}));
                throw new Error(err.error || `Signing failed (HTTP ${response.status})`);
            }

            const blob = await response.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'Signed_' + Date.now() + '.pdf';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            alert("✓ Success! The PDF has been digitally signed with your USB Token and downloaded.");
        }catch(e){
            alert("Digital Signature Error:\n" + e.message);
        } finally {
            signBtn.innerHTML = oldText;
            signBtn.disabled = signatureAreas.length === 0;
        }
    });

    loadDrivers();
});
</script>
<?php endif; ?>
</body>
</html>
