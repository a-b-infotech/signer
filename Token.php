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

// ====================================================================
// 2. AJAX ENDPOINT: FETCH LATEST VERSION METADATA FROM GITHUB
// Source: https://github.com/a-b-infotech/signer/blob/main/version.json
// ====================================================================
if (isset($_GET['action']) && $_GET['action'] === 'get_latest_version') {
    header('Content-Type: application/json');
    $version_urls = [
        'https://raw.githubusercontent.com/a-b-infotech/signer/main/version.json',
        'https://github.com/a-b-infotech/signer/raw/main/version.json',
        'https://github.com/a-b-infotech/signer/blob/main/version.json?raw=true'
    ];
    $data = null;
    foreach ($version_urls as $vurl) {
        $ctx = stream_context_create([
            'http' => [
                'timeout' => 5,
                'header' => "User-Agent: ABInfoSigner-Web/2.2.0\r\nAccept: application/json\r\n"
            ]
        ]);
        $content = @file_get_contents($vurl, false, $ctx);
        if ($content) {
            $parsed = @json_decode($content, true);
            if ($parsed && isset($parsed['version'])) {
                $data = $parsed;
                break;
            }
        }
    }
    if ($data) {
        echo json_encode($data);
    } else {
        echo json_encode([
            'version' => '2.2.0',
            'release_date' => date('Y-m-d'),
            'download_url' => 'https://github.com/a-b-infotech/signer/releases/latest/download/Abinfo_Signer_Windows_Setup.exe'
        ]);
    }
    exit;
}

// ====================================================================
// 3. AJAX ENDPOINT: VERIFY LICENSE FROM DATABASE
// ====================================================================
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

// ====================================================================
// 4. DESKTOP APP BROWSER SYNC ENDPOINT
// ====================================================================
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

// ====================================================================
// 5. UPLOAD & RESET HANDLERS
// ====================================================================
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
        $uploadError = "Only valid PDF documents are allowed.";
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
<title>A B INFOTECH - Digital Signer & Web Signing Suite</title>

<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700;800&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
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
:root {
    --bg-dark: #080d1a;
    --card-bg: rgba(22, 30, 49, 0.85);
    --border-light: rgba(255, 255, 255, 0.12);
    --primary-cyan: #0dcaf0;
    --primary-hover: #0baccc;
    --win-color: #0078d4;
    --mac-color: #9333ea;
    --linux-color: #ea580c;
    --accent-emerald: #10b981;
}

* {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
}

body {
    background: radial-gradient(circle at 50% 0%, #1e293b 0%, #0b0f19 80%);
    color: #f8fafc;
    min-height: 100vh;
    overflow-x: hidden;
    position: relative;
}

#bg-img {
    position: fixed;
    top: 0; left: 0; width: 100%; height: 100%;
    object-fit: cover; z-index: -2; opacity: 0.35; pointer-events: none;
}

/* 3D Glassmorphism Cards */
.glass-3d {
    background: var(--card-bg);
    backdrop-filter: blur(16px);
    -webkit-backdrop-filter: blur(16px);
    border: 1px solid var(--border-light);
    border-radius: 20px;
    box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.7), inset 0 1px 1px rgba(255, 255, 255, 0.15);
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
}

/* Top Navigation Bar */
.top-nav {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 14px 28px;
    background: rgba(15, 23, 42, 0.85);
    backdrop-filter: blur(12px);
    border-bottom: 1px solid rgba(255, 255, 255, 0.08);
    position: sticky;
    top: 0;
    z-index: 100;
}

.brand-section {
    display: flex;
    align-items: center;
    gap: 14px;
    text-decoration: none;
    color: #ffffff;
}

.logo-badge {
    height: 44px;
    padding: 4px 10px;
    background: #ffffff;
    border-radius: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
}

.logo-badge img {
    height: 36px;
    width: auto;
    object-fit: contain;
}

.brand-title {
    font-family: 'Outfit', sans-serif;
    font-size: 1.25rem;
    font-weight: 800;
    letter-spacing: -0.3px;
    background: linear-gradient(135deg, #ffffff 0%, #cbd5e1 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}

.brand-subtitle {
    font-size: 0.75rem;
    color: #0dcaf0;
    font-weight: 600;
    letter-spacing: 0.4px;
}

.nav-actions {
    display: flex;
    align-items: center;
    gap: 12px;
}

.status-pill {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 6px 14px;
    border-radius: 9999px;
    font-size: 0.8rem;
    font-weight: 700;
    background: rgba(16, 185, 129, 0.15);
    color: #34d399;
    border: 1px solid rgba(16, 185, 129, 0.3);
    box-shadow: 0 2px 8px rgba(16, 185, 129, 0.2);
}

.status-pill.offline {
    background: rgba(239, 68, 68, 0.15);
    color: #f87171;
    border-color: rgba(239, 68, 68, 0.3);
    box-shadow: 0 2px 8px rgba(239, 68, 68, 0.2);
}

.status-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: currentColor;
    box-shadow: 0 0 8px currentColor;
}

/* 3D Modern Interactive Buttons */
.btn-3d {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    padding: 12px 22px;
    border-radius: 12px;
    font-weight: 700;
    font-size: 0.92rem;
    cursor: pointer;
    text-decoration: none;
    border: none;
    transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
    box-shadow: 0 4px 14px rgba(0, 0, 0, 0.4), inset 0 1px 0 rgba(255, 255, 255, 0.25);
}

.btn-3d:active {
    transform: translateY(2px);
    box-shadow: 0 2px 6px rgba(0, 0, 0, 0.4);
}

.btn-cyan {
    background: linear-gradient(135deg, #0dcaf0 0%, #0284c7 100%);
    color: #04101e;
}
.btn-cyan:hover {
    background: linear-gradient(135deg, #38bdf8 0%, #0369a1 100%);
    box-shadow: 0 6px 20px rgba(13, 202, 240, 0.45);
    color: #000000;
}

.btn-green {
    background: linear-gradient(135deg, #10b981 0%, #059669 100%);
    color: #ffffff;
}
.btn-green:hover {
    background: linear-gradient(135deg, #34d399 0%, #047857 100%);
    box-shadow: 0 6px 20px rgba(16, 185, 129, 0.45);
}

.btn-red {
    background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
    color: #ffffff;
}
.btn-red:hover {
    background: linear-gradient(135deg, #f87171 0%, #b91c1c 100%);
    box-shadow: 0 6px 20px rgba(239, 68, 68, 0.45);
}

.btn-amber {
    background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
    color: #ffffff;
}
.btn-amber:hover {
    background: linear-gradient(135deg, #fbbf24 0%, #b45309 100%);
    box-shadow: 0 6px 20px rgba(245, 158, 11, 0.45);
}

.btn-tool {
    background: rgba(255, 255, 255, 0.08);
    color: #e2e8f0;
    border: 1px solid rgba(255, 255, 255, 0.15);
    padding: 8px 16px;
    font-size: 0.85rem;
}
.btn-tool:hover {
    background: rgba(255, 255, 255, 0.16);
    color: #ffffff;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
}

/* 3D Glass Form Inputs */
.glass-input {
    width: 100%;
    padding: 12px 14px;
    border-radius: 10px;
    border: 1px solid rgba(13, 202, 240, 0.3);
    background: rgba(10, 15, 28, 0.6);
    color: #ffffff;
    font-size: 0.9rem;
    margin-bottom: 14px;
    outline: none;
    box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.4);
    transition: all 0.2s ease;
}

.glass-input:focus {
    border-color: #0dcaf0;
    background: rgba(10, 15, 28, 0.85);
    box-shadow: 0 0 14px rgba(13, 202, 240, 0.4), inset 0 2px 4px rgba(0, 0, 0, 0.4);
}

.glass-input option {
    background: #0f172a;
    color: #ffffff;
}

/* 3D Drag & Drop Upload Zone */
.upload-card-wrapper {
    max-width: 640px;
    margin: 6vh auto;
    padding: 40px;
    text-align: center;
}

.upload-dropzone {
    border: 2px dashed rgba(13, 202, 240, 0.5);
    border-radius: 18px;
    padding: 45px 30px;
    background: rgba(13, 202, 240, 0.03);
    cursor: pointer;
    transition: all 0.3s ease;
    margin-bottom: 25px;
    box-shadow: inset 0 2px 10px rgba(0, 0, 0, 0.2);
}

.upload-dropzone:hover {
    border-color: #0dcaf0;
    background: rgba(13, 202, 240, 0.08);
    transform: translateY(-2px);
    box-shadow: 0 10px 25px rgba(13, 202, 240, 0.2);
}

.upload-icon-pulse {
    font-size: 3.5rem;
    margin-bottom: 14px;
    display: inline-block;
    filter: drop-shadow(0 4px 10px rgba(13, 202, 240, 0.5));
    animation: floatIcon 3s ease-in-out infinite;
}

@keyframes floatIcon {
    0%, 100% { transform: translateY(0); }
    50% { transform: translateY(-8px); }
}

#pdfFile { display: none; }

/* 3D Workspace Layout */
.workspace-container {
    display: flex;
    gap: 20px;
    width: 96%;
    max-width: 1540px;
    margin: 20px auto;
    height: calc(100vh - 100px);
}

.sidebar-panel {
    flex: 0 0 360px;
    padding: 22px;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
}

.editor-stage {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    overflow: hidden;
}

.stage-toolbar {
    padding: 12px 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid rgba(255, 255, 255, 0.08);
    flex-wrap: wrap;
    gap: 12px;
}

.canvas-viewport {
    flex: 1;
    overflow: auto;
    padding: 25px;
    display: flex;
    justify-content: center;
    align-items: flex-start;
    background: rgba(10, 15, 28, 0.4);
}

.pdf-bezel {
    position: relative;
    display: inline-block;
    background: #ffffff;
    border-radius: 4px;
    box-shadow: 0 25px 60px -15px rgba(0, 0, 0, 0.9), 0 0 0 1px rgba(255, 255, 255, 0.1);
}

.interaction-layer {
    position: absolute;
    top: 0; left: 0; right: 0; bottom: 0;
}

.active-selection {
    cursor: crosshair;
    background: rgba(13, 202, 240, 0.08);
}

.selection-ghost {
    position: absolute;
    border: 2px dashed #0dcaf0;
    background: rgba(13, 202, 240, 0.25);
    box-shadow: 0 0 15px rgba(13, 202, 240, 0.4);
}

.signature-stamp-box {
    position: absolute;
    border: 2px solid #10b981;
    background: rgba(16, 185, 129, 0.2);
    color: #065f46;
    font-weight: 700;
    font-size: 12px;
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    text-align: center;
    border-radius: 4px;
    backdrop-filter: blur(2px);
    box-shadow: 0 4px 12px rgba(16, 185, 129, 0.3);
}

/* ====================================================================
   3D MULTI-OS DOWNLOAD CARDS GRID (Windows, macOS, Linux)
   Exact match to official installer specification
   ==================================================================== */
.cards-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    gap: 20px;
    margin: 20px 0;
    width: 100%;
    text-align: center;
}

.os-card {
    background: rgba(15, 23, 42, 0.85);
    border: 1px solid rgba(255, 255, 255, 0.1);
    border-radius: 20px;
    padding: 26px 20px;
    display: flex;
    flex-direction: column;
    align-items: center;
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    position: relative;
    overflow: hidden;
    box-shadow: 0 10px 25px rgba(0, 0, 0, 0.5);
}

.os-card:hover {
    transform: translateY(-8px);
    border-color: rgba(255, 255, 255, 0.25);
    box-shadow: 0 20px 40px rgba(0, 0, 0, 0.7);
}

.os-icon {
    font-size: 2.8rem;
    margin-bottom: 12px;
}

.os-title {
    font-family: 'Outfit', sans-serif;
    font-size: 1.25rem;
    font-weight: 800;
    margin-bottom: 6px;
    color: #ffffff;
}

.os-desc {
    font-size: 0.82rem;
    color: #94a3b8;
    margin-bottom: 20px;
    line-height: 1.45;
}

.btn-download {
    width: 100%;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    padding: 12px 18px;
    border-radius: 12px;
    text-decoration: none;
    color: #ffffff;
    font-weight: 700;
    font-size: 0.9rem;
    transition: all 0.25s ease;
    box-shadow: 0 4px 14px rgba(0, 0, 0, 0.3);
    margin-top: auto;
}

.btn-win {
    background: linear-gradient(135deg, #0078d4 0%, #005a9e 100%);
    border: 1px solid #2b88d8;
}
.btn-win:hover {
    background: linear-gradient(135deg, #1084d8 0%, #0066b3 100%);
    box-shadow: 0 6px 20px rgba(0, 120, 212, 0.55);
    transform: translateY(-2px);
}

.btn-mac {
    background: linear-gradient(135deg, #9333ea 0%, #6b21a8 100%);
    border: 1px solid #a855f7;
}
.btn-mac:hover {
    background: linear-gradient(135deg, #a855f7 0%, #7e22ce 100%);
    box-shadow: 0 6px 20px rgba(168, 85, 247, 0.55);
    transform: translateY(-2px);
}

.btn-linux {
    background: linear-gradient(135deg, #ea580c 0%, #c2410c 100%);
    border: 1px solid #f97316;
}
.btn-linux:hover {
    background: linear-gradient(135deg, #f97316 0%, #d946ef 100%);
    box-shadow: 0 6px 20px rgba(234, 88, 12, 0.55);
    transform: translateY(-2px);
}

.file-info {
    display: block;
    font-size: 0.72rem;
    color: #64748b;
    margin-top: 8px;
    font-family: monospace;
}

/* Modals & Fullscreen Overlays */
.overlay-backdrop {
    display: none;
    position: fixed;
    top: 0; left: 0; width: 100%; height: 100%;
    background: rgba(8, 13, 26, 0.92);
    backdrop-filter: blur(14px);
    -webkit-backdrop-filter: blur(14px);
    z-index: 9999;
    justify-content: center;
    align-items: center;
    padding: 20px;
}

.modal-3d {
    max-width: 920px;
    width: 100%;
    padding: 35px 30px;
    text-align: center;
    max-height: 90vh;
    overflow-y: auto;
}

.modal-badge {
    display: inline-block;
    padding: 5px 14px;
    border-radius: 9999px;
    font-size: 0.8rem;
    font-weight: 700;
    margin-bottom: 12px;
    text-transform: uppercase;
}

@media(max-width: 992px) {
    .workspace-container {
        flex-direction: column;
        height: auto;
        min-height: 100vh;
    }
    .sidebar-panel { flex: none; width: 100%; order: 2; }
    .editor-stage { flex: none; height: 70vh; order: 1; }
    .top-nav { flex-direction: column; gap: 10px; align-items: stretch; }
    .nav-actions { justify-content: space-between; }
}
</style>
</head>
<body>

<!-- Google AdSense Container -->
<div class="ad-container" style="display:none; text-align:center; margin: 10px auto; max-width: 95%;">
    <ins class="adsbygoogle"
         style="display:block"
         data-ad-client="ca-pub-4544316411176795"
         data-ad-slot="YOUR_AD_SLOT_ID"
         data-ad-format="auto"
         data-full-width-responsive="true"></ins>
</div>

<!-- ====================================================================
     TOP NAVIGATION & LIVE SERVER STATUS
     ==================================================================== -->
<header class="top-nav">
    <a href="Token.php" class="brand-section">
        <div class="logo-badge">
            <img src="abinfo.png" alt="A B INFOTECH" onerror="this.src='app_icon.png';">
        </div>
        <div>
            <div class="brand-title">A B INFOTECH</div>
            <div class="brand-subtitle">Digital Signer & Web Signing Suite</div>
        </div>
    </a>
    <div class="nav-actions">
        <div id="serverStatusPill" class="status-pill offline" title="Background Local API Server status">
            <span class="status-dot"></span>
            <span id="serverStatusText">Local Server: Connecting...</span>
        </div>
        <div id="licensePill" class="status-pill" style="display:none; background: rgba(59,130,246,0.15); color:#60a5fa; border-color: rgba(59,130,246,0.3);">
            <span id="licenseTierText">PRO SUITE</span>
        </div>
        <a href="https://api.whatsapp.com/send?phone=917016797720&text=Digital%20Signer%20Support" target="_blank" class="btn-3d btn-tool">
            💬 WhatsApp: +91 7016797720
        </a>
    </div>
</header>

<!-- ====================================================================
     OVERLAY 1: OFFLINE SERVER (Requires Background Desktop Tool)
     Includes the Exact Multi-OS Cards Grid
     ==================================================================== -->
<div id="offline-overlay" class="overlay-backdrop">
    <div class="glass-3d modal-3d">
        <span class="modal-badge" style="background: rgba(239, 68, 68, 0.15); color:#f87171; border: 1px solid rgba(239, 68, 68, 0.3);">
            ⚠️ Background Software Required
        </span>
        <h2 style="font-family:'Outfit',sans-serif; font-size:1.9rem; font-weight:800; margin-bottom:10px;">
            Connect Your USB Hardware Token
        </h2>
        <p style="color:#94a3b8; font-size:0.95rem; max-width:680px; margin:0 auto 20px; line-height:1.6;">
            Web browsers cannot directly communicate with physical USB Cryptographic Hardware Tokens (ePass2003, Watchdata, mToken, TrustKey) due to browser security sandboxes. Please download and run the background A B INFOTECH Signer tool on your PC.
        </p>

        <!-- EXACT DOWNLOAD CARDS GRID (Windows, macOS, Linux) -->
        <div class="cards-grid">
            <!-- Windows Setup Card (Official Installer) -->
            <div class="os-card" style="border-color: rgba(59, 130, 246, 0.4); background: rgba(30, 58, 138, 0.25);">
                <div class="os-icon">🪟</div>
                <h2 class="os-title">Windows Setup</h2>
                <p class="os-desc">Windows 10, 11 (64-bit)<br><strong>Official Setup Installer</strong><br>Auto CA Cert + Desktop Icon</p>
                <a href="https://github.com/a-b-infotech/signer/releases/latest/download/Abinfo_Signer_Windows_Setup.exe" class="btn-download btn-win">
                    <span>⬇️ Download Windows Setup</span>
                </a>
                <span class="file-info">Abinfo_Signer_Windows_Setup.exe</span>
            </div>

            <!-- macOS Card -->
            <div class="os-card">
                <div class="os-icon">🍏</div>
                <h2 class="os-title">macOS</h2>
                <p class="os-desc">macOS Monterey, Ventura, Sonoma<br>Universal Bundle with installer script</p>
                <a href="https://github.com/a-b-infotech/signer/releases/latest/download/Abinfo_Signer_macOS.zip" class="btn-download btn-mac">
                    <span>⬇️ Download for macOS</span>
                </a>
                <span class="file-info">Abinfo_Signer_macOS.zip</span>
            </div>

            <!-- Linux Card -->
            <div class="os-card">
                <div class="os-icon">🐧</div>
                <h2 class="os-title">Linux</h2>
                <p class="os-desc">Ubuntu, Debian, Fedora, Arch<br>x64 Package with auto-installer</p>
                <a href="https://github.com/a-b-infotech/signer/releases/latest/download/Abinfo_Signer_Linux.tar.gz" class="btn-download btn-linux">
                    <span>⬇️ Download for Linux</span>
                </a>
                <span class="file-info">Abinfo_Signer_Linux.tar.gz</span>
            </div>
        </div>

        <div style="margin-top: 15px;">
            <button onclick="checkBackgroundServer()" class="btn-3d btn-cyan" style="min-width: 220px;">
                ↻ Retry Server Connection
            </button>
        </div>
    </div>
</div>

<!-- ====================================================================
     OVERLAY 2: SOFTWARE UPDATE REQUIRED
     Includes the Exact Multi-OS Cards Grid
     ==================================================================== -->
<div id="update-overlay" class="overlay-backdrop">
    <div class="glass-3d modal-3d">
        <span class="modal-badge" style="background: rgba(245, 158, 11, 0.15); color:#fbbf24; border: 1px solid rgba(245, 158, 11, 0.3);">
            🔄 Version Update Required
        </span>
        <h2 style="font-family:'Outfit',sans-serif; font-size:1.9rem; font-weight:800; margin-bottom:10px;">
            Update Your A B INFOTECH Signer Suite
        </h2>
        <p id="updateVersionDetails" style="color:#94a3b8; font-size:0.95rem; max-width:680px; margin:0 auto 20px; line-height:1.6;">
            A newer release of A B INFOTECH Signer is available on GitHub (checked live from <code>version.json</code>). Please install the updated package to maintain PDF signing security and token driver compliance.
        </p>

        <!-- EXACT DOWNLOAD CARDS GRID (Windows, macOS, Linux) -->
        <div class="cards-grid">
            <!-- Windows Setup Card (Official Installer) -->
            <div class="os-card" style="border-color: rgba(59, 130, 246, 0.4); background: rgba(30, 58, 138, 0.25);">
                <div class="os-icon">🪟</div>
                <h2 class="os-title">Windows Setup</h2>
                <p class="os-desc">Windows 10, 11 (64-bit)<br><strong>Official Setup Installer</strong><br>Auto CA Cert + Desktop Icon</p>
                <a href="https://github.com/a-b-infotech/signer/releases/latest/download/Abinfo_Signer_Windows_Setup.exe" class="btn-download btn-win">
                    <span>⬇️ Download Windows Setup</span>
                </a>
                <span class="file-info">Abinfo_Signer_Windows_Setup.exe</span>
            </div>

            <!-- macOS Card -->
            <div class="os-card">
                <div class="os-icon">🍏</div>
                <h2 class="os-title">macOS</h2>
                <p class="os-desc">macOS Monterey, Ventura, Sonoma<br>Universal Bundle with installer script</p>
                <a href="https://github.com/a-b-infotech/signer/releases/latest/download/Abinfo_Signer_macOS.zip" class="btn-download btn-mac">
                    <span>⬇️ Download for macOS</span>
                </a>
                <span class="file-info">Abinfo_Signer_macOS.zip</span>
            </div>

            <!-- Linux Card -->
            <div class="os-card">
                <div class="os-icon">🐧</div>
                <h2 class="os-title">Linux</h2>
                <p class="os-desc">Ubuntu, Debian, Fedora, Arch<br>x64 Package with auto-installer</p>
                <a href="https://github.com/a-b-infotech/signer/releases/latest/download/Abinfo_Signer_Linux.tar.gz" class="btn-download btn-linux">
                    <span>⬇️ Download for Linux</span>
                </a>
                <span class="file-info">Abinfo_Signer_Linux.tar.gz</span>
            </div>
        </div>

        <div style="margin-top: 15px;">
            <button onclick="checkBackgroundServer()" class="btn-3d btn-cyan" style="min-width: 220px;">
                ↻ Re-check Version & Connect
            </button>
        </div>
    </div>
</div>

<!-- ====================================================================
     OVERLAY 3: LICENSE EXPIRED
     ==================================================================== -->
<div id="expired-overlay" class="overlay-backdrop">
    <div class="glass-3d modal-3d" style="max-width: 520px;">
        <span class="modal-badge" style="background: rgba(239, 68, 68, 0.15); color:#f87171; border: 1px solid rgba(239, 68, 68, 0.3);">
            ⏳ License Expired
        </span>
        <h2 style="font-family:'Outfit',sans-serif; font-size:1.8rem; font-weight:800; margin-bottom:12px;">
            License Renewal Required
        </h2>
        <p style="color:#94a3b8; font-size:0.95rem; line-height:1.6; margin-bottom: 24px;">
            Your A B INFOTECH Digital Signer license subscription has expired. Please renew your key to continue signing documents without restrictions.
        </p>

        <a href="https://pay.a-b-infotech.in/license.php" target="_blank" class="btn-3d btn-amber" style="width: 100%; font-size: 1rem; margin-bottom: 14px;">
            💳 Renew / Purchase License Online
        </a>

        <div style="background: rgba(10, 15, 28, 0.6); padding: 18px; border-radius: 14px; margin-bottom: 16px; border: 1px solid rgba(255, 255, 255, 0.08);">
            <div style="color: #64748b; font-size: 0.8rem; margin-bottom: 4px;">Direct Helpdesk Support:</div>
            <div style="font-size: 1.15rem; font-weight: 700; color: #34d399; margin-bottom: 4px;">
                📞 <a href="tel:7016797720" style="color: inherit; text-decoration: none;">+91 7016797720</a>
            </div>
            <div style="font-size: 0.95rem; font-weight: 600; color: #38bdf8;">
                ✉️ <a href="mailto:sales@a-b-infotech.in" style="color: inherit; text-decoration: none;">sales@a-b-infotech.in</a>
            </div>
        </div>

        <a href="https://api.whatsapp.com/send?phone=917016797720&text=I%20want%20to%20renew%20my%20PDF%20Signer%20License" target="_blank" class="btn-3d btn-green" style="width: 100%;">
            💬 Renew on WhatsApp
        </a>
    </div>
</div>

<!-- ====================================================================
     MODAL 4: DEMO RESTRICTION NOTICE
     ==================================================================== -->
<div id="licenseModal" class="overlay-backdrop">
    <div class="glass-3d modal-3d" style="max-width: 480px;">
        <span class="modal-badge" style="background: rgba(245, 158, 11, 0.15); color:#fbbf24; border: 1px solid rgba(245, 158, 11, 0.3);">
            DEMO VERSION ACTIVE
        </span>
        <h2 style="font-family:'Outfit',sans-serif; font-size:1.6rem; font-weight:800; margin-bottom:12px;">
            Single Signature Box Limit
        </h2>
        <p style="color:#94a3b8; font-size:0.92rem; line-height:1.6; margin-bottom:20px;">
            In Demo Mode, only <b>one signature area</b> is allowed per document. To unlock multi-page placement, bulk batch signing, and custom stamps, please activate a Pro license.
        </p>

        <a href="https://pay.a-b-infotech.in/license.php" target="_blank" class="btn-3d btn-amber" style="width: 100%; margin-bottom: 12px;">
            💳 Purchase Pro License Online
        </a>
        <a href="https://api.whatsapp.com/send?phone=917016797720&text=Licence%20PDF%20Key" target="_blank" class="btn-3d btn-green" style="width: 100%; margin-bottom: 14px;">
            💬 Contact on WhatsApp (+91 7016797720)
        </a>
        <button onclick="document.getElementById('licenseModal').style.display='none';" class="btn-3d btn-tool" style="width: 100%;">
            Continue with 1 Signature Box
        </button>
    </div>
</div>

<!-- ====================================================================
     PAGE 1: PDF UPLOAD SCREEN (When no PDF is in session)
     ==================================================================== -->
<?php if (!isset($_SESSION['pdfPath'])): ?>

<main class="upload-card-wrapper">
    <div class="glass-3d" style="padding: 40px 30px;">
        <div class="upload-icon-pulse">📑</div>
        <h1 style="font-family:'Outfit',sans-serif; font-size:2rem; font-weight:800; margin-bottom:8px;">
            Open PDF for Digital Signing
        </h1>
        <p style="color:#94a3b8; font-size:0.95rem; margin-bottom: 28px;">
            Select any PDF document to position your digital signature visually on any page.
        </p>

        <?php if ($uploadError): ?>
            <div style="background:rgba(239,68,68,0.15); color:#f87171; border:1px solid rgba(239,68,68,0.3); padding:10px; border-radius:10px; margin-bottom:20px; font-size:0.9rem;">
                <?= $uploadError ?>
            </div>
        <?php endif; ?>

        <form method="POST" enctype="multipart/form-data">
            <label for="pdfFile" class="upload-dropzone">
                <div style="font-size: 2rem; margin-bottom: 8px;">📂</div>
                <div id="fileChosenText" style="font-weight: 700; font-size: 1.05rem; color: #38bdf8;">
                    Click here or Drag & Drop PDF
                </div>
                <div style="font-size: 0.8rem; color: #64748b; margin-top: 6px;">
                    Supports documents up to 50 MB
                </div>
            </label>
            <input type="file" id="pdfFile" name="pdfFile" accept=".pdf" required>
            
            <button type="submit" class="btn-3d btn-cyan" style="width:100%; font-size:1.05rem; padding:15px;">
                🚀 Upload & Open in Signing Studio
            </button>
        </form>
    </div>
</main>

<script>
const fileInput = document.getElementById('pdfFile');
const chosenText = document.getElementById('fileChosenText');
fileInput.addEventListener('change', function() {
    if (this.files && this.files[0]) {
        const sizeMb = (this.files[0].size / (1024 * 1024)).toFixed(2);
        chosenText.innerHTML = `✓ ${this.files[0].name} <span style="font-size:0.8rem; color:#94a3b8;">(${sizeMb} MB)</span>`;
    }
});
</script>

<!-- ====================================================================
     PAGE 2: INTERACTIVE SIGNING STUDIO WORKSPACE
     ==================================================================== -->
<?php else: ?>

<div class="workspace-container">
    <!-- LEFT SIDEBAR: Comprehensive Signature Settings -->
    <aside class="glass-3d sidebar-panel">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px; border-bottom:1px solid rgba(255,255,255,0.08); padding-bottom:10px;">
            <h3 style="font-family:'Outfit',sans-serif; font-size:1.15rem; font-weight:700; color:#38bdf8;">
                ⚙️ Signature Settings
            </h3>
            <span class="status-pill" style="padding:3px 10px; font-size:0.7rem;">Active</span>
        </div>

        <div style="background:rgba(10,15,28,0.5); padding:10px 12px; border-radius:10px; margin-bottom:16px; border:1px solid rgba(255,255,255,0.06);">
            <div style="font-size:0.75rem; color:#64748b; font-weight:600;">ACTIVE DOCUMENT</div>
            <div style="word-break:break-all; font-size:0.88rem; font-weight:600; color:#e2e8f0;">
                <?= sanitizeInput($_SESSION['fileName']) ?>
            </div>
        </div>

        <form id="signForm" style="display:flex; flex-direction:column; flex:1;">
            <!-- 1. Driver Selection -->
            <label style="font-size:0.8rem; color:#94a3b8; font-weight:700; margin-bottom:4px;">
                1. USB Token Driver
            </label>
            <select class="glass-input" id="driverDropdownWorkspace"></select>

            <!-- 2. Certificate Selection -->
            <label style="font-size:0.8rem; color:#94a3b8; font-weight:700; margin-bottom:4px;">
                2. Digital Certificate
            </label>
            <select class="glass-input" name="certAlias" required>
                <option value="">-- Choose Certificate --</option>
            </select>

            <!-- 3. Hardware Token PIN -->
            <label style="font-size:0.8rem; color:#94a3b8; font-weight:700; margin-bottom:4px;">
                3. USB Hardware Token PIN
            </label>
            <div style="position:relative; margin-bottom:14px;">
                <input type="password" class="glass-input" id="tokenPinInput" name="tokenPassword" placeholder="Enter Token User PIN" style="margin-bottom:0;" required>
                <button type="button" onclick="togglePinVisibility()" style="position:absolute; right:10px; top:50%; transform:translateY(-50%); background:transparent; border:none; color:#94a3b8; cursor:pointer; font-size:0.85rem;">
                    👁️
                </button>
            </div>

            <!-- 4. Signature Metadata & Appearance -->
            <label style="font-size:0.8rem; color:#94a3b8; font-weight:700; margin-bottom:4px;">
                4. Signing Reason
            </label>
            <select class="glass-input" id="signReasonSelect" name="signReason">
                <option value="I approve this document">I approve this document</option>
                <option value="I am the author of this document">I am the author of this document</option>
                <option value="Official Authentication">Official Authentication</option>
                <option value="Verified and Approved">Verified and Approved</option>
            </select>

            <label style="font-size:0.8rem; color:#94a3b8; font-weight:700; margin-bottom:4px;">
                5. Signer Location / Address
            </label>
            <input type="text" class="glass-input" id="signLocationInput" name="signLocation" placeholder="e.g. Gujarat, India">

            <!-- Checkbox Options Cluster -->
            <div style="background:rgba(10,15,28,0.4); padding:10px; border-radius:10px; margin-bottom:16px; border:1px solid rgba(255,255,255,0.06);">
                <div style="font-size:0.75rem; color:#64748b; font-weight:700; margin-bottom:6px;">DISPLAY ELEMENTS IN STAMP</div>
                <div style="display:grid; grid-template-columns: 1fr 1fr; gap:6px; font-size:0.8rem;">
                    <label><input type="checkbox" id="chkName" checked> Signer Name</label>
                    <label><input type="checkbox" id="chkDate" checked> Timestamp</label>
                    <label><input type="checkbox" id="chkReason" checked> Reason</label>
                    <label><input type="checkbox" id="chkLocation" checked> Location</label>
                    <label><input type="checkbox" id="chkTick" checked> Green Tick</label>
                    <label><input type="checkbox" id="chkBorder" checked> Box Border</label>
                </div>
            </div>

            <!-- Placed Signature Areas Summary -->
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                <span style="font-size:0.8rem; color:#94a3b8; font-weight:700;">PLACED SIGNATURE BOXES</span>
                <span id="placedCountBadge" style="font-size:0.75rem; color:#38bdf8; font-weight:700;">0 Boxes</span>
            </div>
            <div id="signatureList" style="min-height:75px; max-height:140px; overflow-y:auto; background:rgba(10,15,28,0.5); padding:10px; border-radius:10px; margin-bottom:16px; border:1px solid rgba(255,255,255,0.06); font-size:0.8rem;">
                No signatures drawn yet. Click 'Draw Signature Box' on right.
            </div>

            <!-- Demo Mode Box Warning -->
            <div id="demoWarningMsg" style="display:none; color:#f87171; font-size:0.8rem; margin-bottom:14px; text-align:center; border:1px solid rgba(239,68,68,0.3); padding:10px; border-radius:10px; background:rgba(239,68,68,0.1);">
                <b>DEMO VERSION</b> (Max 1 Signature Box)<br>
                <a href="https://pay.a-b-infotech.in/license.php" target="_blank" style="color:#fbbf24; text-decoration:underline;">Upgrade to Pro Suite</a>
            </div>

            <!-- Action Buttons -->
            <div style="margin-top:auto;">
                <button type="submit" class="btn-3d btn-green" id="finalSignBtn" disabled style="width: 100%; font-size: 1rem; padding: 14px; margin-bottom: 10px;">
                    ✍️ Sign Document Now
                </button>
                <a href="?action=reset" class="btn-3d btn-red" style="width: 100%; font-size: 0.85rem; padding: 10px;">
                    🗑️ Reset / Close Document
                </a>
            </div>
        </form>
    </aside>

    <!-- RIGHT STAGE: 3D PDF Document Viewport -->
    <main class="glass-3d editor-stage">
        <!-- Toolbar Ribbon -->
        <div class="stage-toolbar">
            <div style="display:flex; align-items:center; gap:8px;">
                <button id="prevPageBtn" class="btn-3d btn-tool">◀ Prev</button>
                <span style="font-weight:700; font-size:0.85rem; color:#cbd5e1; padding:0 6px;">
                    Page <span id="currentPageNum" style="color:#38bdf8;">1</span> / <span id="totalPages">0</span>
                </span>
                <button id="nextPageBtn" class="btn-3d btn-tool">Next ▶</button>
            </div>

            <div style="display:flex; align-items:center; gap:8px;">
                <button onclick="changeZoom(-0.15)" class="btn-3d btn-tool" title="Zoom Out">🔍 -</button>
                <span id="zoomLevelDisplay" style="font-size:0.82rem; font-weight:700; color:#94a3b8; min-width:44px; text-align:center;">130%</span>
                <button onclick="changeZoom(0.15)" class="btn-3d btn-tool" title="Zoom In">🔍 +</button>
            </div>

            <div style="display:flex; align-items:center; gap:8px;">
                <button id="clearAreasBtn" class="btn-3d btn-red" style="padding:8px 14px; font-size:0.82rem;">
                    🗑️ Clear Areas
                </button>
                <button id="selectAreaBtn" class="btn-3d btn-cyan" style="padding:8px 18px; font-size:0.85rem;">
                    ✏️ Draw Signature Box
                </button>
            </div>
        </div>

        <!-- Canvas Viewport -->
        <div class="canvas-viewport">
            <div class="pdf-bezel" id="pdfWrapper">
                <canvas id="pdfCanvas"></canvas>
                <div class="interaction-layer" id="interactionLayer"></div>
            </div>
        </div>
    </main>
</div>

<!-- ====================================================================
     CLIENT-SIDE INTERACTIVE ENGINE
     ==================================================================== -->
<script>
document.addEventListener('DOMContentLoaded', function() {
    const LOCAL_SERVER = 'http://127.0.0.1:5000';
    const GITHUB_VERSION_URL = 'https://raw.githubusercontent.com/a-b-infotech/signer/main/version.json';
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
    let scale = 1.3;

    window.isDemoMode = false;

    // Load Token Drivers from Local Server
    async function loadDrivers() {
        try {
            const response = await fetch(`${LOCAL_SERVER}/api/drivers`);
            const drivers = await response.json();
            const select = document.getElementById('driverDropdownWorkspace');
            if (!select) return;
            select.innerHTML = '';
            drivers.forEach(driver => {
                const opt = document.createElement('option');
                opt.value = driver;
                opt.textContent = driver;
                select.appendChild(opt);
            });
            select.addEventListener('change', fetchCertificates);
            fetchCertificates();
        } catch (e) {}
    }

    // Load Digital Certificates from Local Server
    async function fetchCertificates() {
        const driver = document.getElementById('driverDropdownWorkspace');
        if (!driver) return;
        try {
            const response = await fetch(`${LOCAL_SERVER}/api/certificates?driver_name=${encodeURIComponent(driver.value)}`);
            const certs = await response.json();
            const certSelect = document.querySelector('select[name="certAlias"]');
            
            certSelect.innerHTML = '<option value="">-- Choose Certificate --</option>';
            certs.forEach(cert => {
                const opt = document.createElement('option');
                opt.value = cert.alias;
                let displayName = cert.subject;
                const match = cert.subject.match(/CN=([^,]+)/);
                if (match) displayName = match[1];
                opt.textContent = `${displayName} (${cert.source})`;
                certSelect.appendChild(opt);
            });
        } catch (e) {}
    }

    // Render PDF Document
    pdfjsLib.getDocument('<?= str_replace("\\", "/", $_SESSION["pdfPath"]) ?>').promise.then(pdf => {
        pdfDoc = pdf;
        document.getElementById('totalPages').textContent = pdf.numPages;
        renderPage(pageNum);
    });

    function renderPage(num) {
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

    window.changeZoom = function(delta) {
        let newScale = scale + delta;
        if (newScale < 0.6) newScale = 0.6;
        if (newScale > 2.5) newScale = 2.5;
        scale = newScale;
        document.getElementById('zoomLevelDisplay').textContent = Math.round(scale * 100) + '%';
        renderPage(pageNum);
    };

    window.togglePinVisibility = function() {
        const pinInput = document.getElementById('tokenPinInput');
        pinInput.type = (pinInput.type === 'password') ? 'text' : 'password';
    };

    document.getElementById('prevPageBtn').addEventListener('click', () => {
        if (pageNum <= 1) return;
        pageNum--; renderPage(pageNum);
    });

    document.getElementById('nextPageBtn').addEventListener('click', () => {
        if (pageNum >= pdfDoc.numPages) return;
        pageNum++; renderPage(pageNum);
    });

    document.getElementById('clearAreasBtn').addEventListener('click', function() {
        signatureAreas = [];
        updateSignatureList();
        drawSavedAreas();
        if (tempBox) { tempBox.remove(); tempBox = null; }
        currentArea = null; isSelecting = false;
        interactionLayer.classList.remove('active-selection');
        const selectBtn = document.getElementById('selectAreaBtn');
        selectBtn.className = 'btn-3d btn-cyan';
        selectBtn.textContent = '✏️ Draw Signature Box';
    });

    document.getElementById('selectAreaBtn').addEventListener('click', function() {
        if (window.isDemoMode && signatureAreas.length >= 1) {
            document.getElementById('licenseModal').style.display = 'flex';
            return;
        }
        isSelecting = !isSelecting;
        if (isSelecting) {
            this.className = 'btn-3d btn-amber';
            this.textContent = '✏️ Drag Box on Canvas...';
        } else {
            this.className = 'btn-3d btn-cyan';
            this.textContent = '✏️ Draw Signature Box';
        }
        interactionLayer.classList.toggle('active-selection');
    });

    let startX, startY;

    interactionLayer.addEventListener('mousedown', e => {
        if (!isSelecting) return;
        const rect = interactionLayer.getBoundingClientRect();
        startX = e.clientX - rect.left;
        startY = e.clientY - rect.top;
        currentArea = { x: startX, y: startY, width: 0, height: 0 };
        tempBox = document.createElement('div');
        tempBox.className = 'selection-ghost';
        interactionLayer.appendChild(tempBox);
    });

    interactionLayer.addEventListener('mousemove', e => {
        if (!isSelecting || !currentArea) return;
        const rect = interactionLayer.getBoundingClientRect();
        currentArea.width = (e.clientX - rect.left) - startX;
        currentArea.height = (e.clientY - rect.top) - startY;
        tempBox.style.left = (currentArea.width < 0 ? startX + currentArea.width : startX) + 'px';
        tempBox.style.top = (currentArea.height < 0 ? startY + currentArea.height : startY) + 'px';
        tempBox.style.width = Math.abs(currentArea.width) + 'px';
        tempBox.style.height = Math.abs(currentArea.height) + 'px';
    });

    interactionLayer.addEventListener('mouseup', () => {
        if (!currentArea) return;

        if (window.isDemoMode && signatureAreas.length >= 1) {
            currentArea = null;
            if (tempBox) tempBox.remove();
            tempBox = null;
            isSelecting = false;
            interactionLayer.classList.remove('active-selection');
            document.getElementById('selectAreaBtn').className = 'btn-3d btn-cyan';
            document.getElementById('selectAreaBtn').textContent = '✏️ Draw Signature Box';
            document.getElementById('licenseModal').style.display = 'flex';
            return;
        }

        const x = currentArea.width < 0 ? startX + currentArea.width : startX;
        const y = currentArea.height < 0 ? startY + currentArea.height : startY;
        const w = Math.abs(currentArea.width);
        const h = Math.abs(currentArea.height);

        if (w > 12 && h > 12) {
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
        interactionLayer.classList.remove('active-selection');
        const selectBtn = document.getElementById('selectAreaBtn');
        selectBtn.className = 'btn-3d btn-cyan';
        selectBtn.textContent = '✏️ Draw Signature Box';
        drawSavedAreas();
    });

    function drawSavedAreas() {
        interactionLayer.querySelectorAll('.signature-stamp-box, .selection-ghost').forEach(el => el.remove());
        signatureAreas.forEach((area, idx) => {
            if (area.page !== pageNum) return;
            const div = document.createElement('div');
            div.className = 'signature-stamp-box';
            div.style.left = (area.x * scale) + 'px';
            div.style.top = (currentPdfHeight - (area.y + area.height) * scale) + 'px';
            div.style.width = (area.width * scale) + 'px';
            div.style.height = (area.height * scale) + 'px';
            div.innerHTML = `✓ Digital Signature #${idx + 1}<br><span style="font-size:10px; opacity:0.85;">(Page ${area.page})</span>`;
            interactionLayer.appendChild(div);
        });
    }

    function updateSignatureList() {
        const list = document.getElementById('signatureList');
        const countBadge = document.getElementById('placedCountBadge');
        countBadge.textContent = `${signatureAreas.length} Boxes`;

        list.innerHTML = '';
        if (signatureAreas.length === 0) {
            list.innerHTML = 'No signatures drawn yet. Click "Draw Signature Box" on right.';
        } else {
            signatureAreas.forEach((a, i) => {
                list.innerHTML += `<div style="display:flex; justify-content:space-between; padding:4px 0; border-bottom:1px solid rgba(255,255,255,0.06);"><span>Page ${a.page}</span><span style="color:#38bdf8;">Box #${i+1} (${Math.round(a.width)}x${Math.round(a.height)} pt)</span></div>`;
            });
        }
        document.getElementById('finalSignBtn').disabled = signatureAreas.length === 0;
    }

    // Submit Document Signing to Local Server (Port 5000)
    document.getElementById('signForm').addEventListener('submit', async function(e) {
        e.preventDefault();
        const certVal = document.querySelector('[name="certAlias"]').value;
        const passVal = document.getElementById('tokenPinInput').value;
        const driverVal = document.getElementById('driverDropdownWorkspace').value;
        const reasonVal = document.getElementById('signReasonSelect').value;
        const locationVal = document.getElementById('signLocationInput').value;

        if (!certVal) {
            alert("Please choose a Digital Certificate from the dropdown.");
            return;
        }
        if (!passVal) {
            alert("Please enter your USB Hardware Token PIN / Password.");
            return;
        }

        const signBtn = document.getElementById('finalSignBtn');
        const oldHtml = signBtn.innerHTML;
        signBtn.innerHTML = "⏳ Signing with Hardware Token...";
        signBtn.disabled = true;

        try {
            const formData = new FormData();
            const fileBlob = await fetch('<?= str_replace("\\", "/", $_SESSION["pdfPath"]) ?>').then(r => r.blob());

            formData.append('file', fileBlob, '<?= sanitizeInput($_SESSION["fileName"]) ?>');
            formData.append('certificate', JSON.stringify({ alias: certVal }));
            formData.append('areas', JSON.stringify(signatureAreas));
            formData.append('password', passVal);
            formData.append('driver_name', driverVal);
            formData.append('reason', reasonVal);
            formData.append('location', locationVal);

            const response = await fetch(`${LOCAL_SERVER}/api/sign`, { method: 'POST', body: formData });

            if (!response.ok) {
                const err = await response.json().catch(() => ({}));
                throw new Error(err.error || `Signing failed with HTTP code ${response.status}`);
            }

            const blob = await response.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'Signed_' + Date.now() + '.pdf';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            alert("✓ Success! The PDF document has been digitally signed using your USB Hardware Token.");
        } catch (err) {
            alert("Digital Signature Error:\n" + err.message);
        } finally {
            signBtn.innerHTML = oldHtml;
            signBtn.disabled = signatureAreas.length === 0;
        }
    });

    loadDrivers();
});
</script>
<?php endif; ?>

<!-- ====================================================================
     GLOBAL SYSTEM CHECKS: LOCAL SERVER & GITHUB VERSION.JSON COMPARISON
     Checked from: https://github.com/a-b-infotech/signer/blob/main/version.json
     ==================================================================== -->
<script>
function parseSemver(v) {
    if (!v) return [0, 0, 0];
    return String(v).replace(/^v/i, '').split('.').map(n => parseInt(n) || 0);
}

function isOlderThan(vClient, vRemote) {
    const c = parseSemver(vClient);
    const r = parseSemver(vRemote);
    for (let i = 0; i < 3; i++) {
        const cv = c[i] || 0;
        const rv = r[i] || 0;
        if (cv < rv) return true;
        if (cv > rv) return false;
    }
    return false;
}

let latestGithubVersion = null;

// Fetch Version from GitHub repository version.json
async function fetchLatestGithubVersion() {
    try {
        const res = await fetch('?action=get_latest_version');
        if (res.ok) {
            const data = await res.json();
            if (data && data.version) {
                latestGithubVersion = data.version;
                return latestGithubVersion;
            }
        }
    } catch (e) {}

    // Fallback direct check to GitHub raw
    try {
        const r2 = await fetch('https://raw.githubusercontent.com/a-b-infotech/signer/main/version.json');
        if (r2.ok) {
            const d2 = await r2.json();
            if (d2 && d2.version) {
                latestGithubVersion = d2.version;
                return latestGithubVersion;
            }
        }
    } catch (e2) {}

    return '2.2.0';
}

async function checkBackgroundServer() {
    const pill = document.getElementById('serverStatusPill');
    const pillText = document.getElementById('serverStatusText');
    const licensePill = document.getElementById('licensePill');
    const licenseTierText = document.getElementById('licenseTierText');

    try {
        const res = await fetch('http://127.0.0.1:5000/api/health', { mode: 'cors' });
        if (res.ok) {
            document.getElementById('offline-overlay').style.display = 'none';
            const data = await res.json();
            
            pill.className = 'status-pill';
            pillText.textContent = `Local Server: RUNNING (v${data.version || '2.2.0'})`;

            if (data.tier) {
                licensePill.style.display = 'inline-flex';
                licenseTierText.textContent = data.tier.toUpperCase() + (data.demo ? ' (DEMO)' : ' SUITE');
            }

            // Check version against GitHub version.json
            if (!latestGithubVersion) {
                await fetchLatestGithubVersion();
            }

            if (latestGithubVersion && data.version && isOlderThan(data.version, latestGithubVersion)) {
                const det = document.getElementById('updateVersionDetails');
                if (det) {
                    det.innerHTML = `Your local software (v${data.version}) is older than the latest release <b>v${latestGithubVersion}</b> on GitHub (<code>https://github.com/a-b-infotech/signer/blob/main/version.json</code>). Please install the latest release below.`;
                }
                document.getElementById('update-overlay').style.display = 'flex';
                return;
            } else {
                document.getElementById('update-overlay').style.display = 'none';
            }

            if (data.demo === true) {
                window.isDemoMode = true;
                const demoMsg = document.getElementById('demoWarningMsg');
                if (demoMsg) demoMsg.style.display = 'block';
                document.getElementById('expired-overlay').style.display = 'none';
            } else {
                // Verify license expiration in DB
                const formData = new FormData();
                formData.append('key', data.key || '');

                let verifyData = { status: 'active' };
                try {
                    const verifyRes = await fetch('?action=verify_license', { method: 'POST', body: formData });
                    verifyData = await verifyRes.json();
                } catch (ve) {
                    verifyData = { status: 'active' };
                }

                if (verifyData.status === 'expired') {
                    document.getElementById('expired-overlay').style.display = 'flex';
                    window.isDemoMode = true;
                } else if (verifyData.status === 'active') {
                    document.getElementById('expired-overlay').style.display = 'none';
                    window.isDemoMode = false;
                    const demoMsg = document.getElementById('demoWarningMsg');
                    if (demoMsg) demoMsg.style.display = 'none';
                }
            }
        } else {
            throw new Error('Local server offline');
        }
    } catch (e) {
        pill.className = 'status-pill offline';
        pillText.textContent = 'Local Server: OFFLINE (Port 5000)';
        document.getElementById('offline-overlay').style.display = 'flex';
        document.getElementById('update-overlay').style.display = 'none';
    }
}

window.addEventListener('load', () => {
    fetchLatestGithubVersion();
    checkBackgroundServer();
    setInterval(checkBackgroundServer, 2500);
});
</script>
</body>
</html>
