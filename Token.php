<?php
session_start();

// Set Timezone to India to ensure EXACT time matching for expiration
date_default_timezone_set('Asia/Kolkata');

// ====================================================================
// DATABASE CONFIGURATION (Supports db.php with Fallback PDO)
// ====================================================================
if (file_exists(__DIR__ . '/db.php')) {
    require_once __DIR__ . '/db.php';
}

if (!isset($pdo) || !$pdo) {
    $db_host = 'sql302.ezyro.com';
    $db_user = 'ezyro_37092101';
    $db_pass = 'abhi@123';
    $db_name = 'ezyro_37092101_fj';
    try {
        $pdo = new PDO("mysql:host=$db_host;dbname=$db_name;charset=utf8mb4", $db_user, $db_pass, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_TIMEOUT => 5
        ]);
    } catch (Exception $e) {
        $pdo = null;
    }
}

// ====================================================================
// 1. HANDLE BROWSER SYNC (Opens in browser, redirects to Python)
// ====================================================================
if (isset($_GET['action']) && $_GET['action'] === 'browser_sync') {
    $license_key = isset($_REQUEST['key']) ? trim($_REQUEST['key']) : '';
    
    if (empty($license_key)) {
        header("Location: http://127.0.0.1:5000/api/sync_callback?status=invalid");
        exit;
    }

    if ($license_key === 'ABI-MASTER-PASS') {
        header("Location: http://127.0.0.1:5000/api/sync_callback?status=active&tier=pro");
        exit;
    }

    try {
        if (!$pdo) {
            header("Location: http://127.0.0.1:5000/api/sync_callback?status=error");
            exit;
        }

        $stmt = $pdo->prepare("SELECT id, status, expiredate, license_tier, activated_at FROM license_keys WHERE license_key = :key LIMIT 1");
        $stmt->bindParam(':key', $license_key);
        $stmt->execute();

        if ($stmt->rowCount() > 0) {
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            $tier = (!empty($row['license_tier']) && strtolower($row['license_tier']) === 'basic') ? 'basic' : 'pro';
            
            // If key status is inactive, activate key and set starting date and time as current system time
            if (strtolower($row['status']) === 'inactive') {
                if (empty($row['expiredate']) || $row['expiredate'] === '0000-00-00 00:00:00') {
                    $upd = $pdo->prepare("UPDATE license_keys SET status = 'active', activated_at = NOW(), expiredate = DATE_ADD(NOW(), INTERVAL 1 YEAR) WHERE id = :id");
                    $upd->execute([':id' => $row['id']]);
                    $row['expiredate'] = date('Y-m-d H:i:s', strtotime('+1 year'));
                } else {
                    $upd = $pdo->prepare("UPDATE license_keys SET status = 'active', activated_at = NOW() WHERE id = :id");
                    $upd->execute([':id' => $row['id']]);
                }
                $row['status'] = 'active';
            }

            if ($row['status'] !== 'active') {
                header("Location: http://127.0.0.1:5000/api/sync_callback?status=inactive");
            } 
            elseif (!empty($row['expiredate']) && $row['expiredate'] !== 'never' && strtotime($row['expiredate']) < time()) {
                header("Location: http://127.0.0.1:5000/api/sync_callback?status=expired");
            } else {
                header("Location: http://127.0.0.1:5000/api/sync_callback?status=active&tier=" . urlencode($tier));
            }
        } else {
            header("Location: http://127.0.0.1:5000/api/sync_callback?status=invalid");
        }
    } catch (Exception $e) {
        header("Location: http://127.0.0.1:5000/api/sync_callback?status=error");
    }
    exit;
}

// ====================================================================
// 2. HANDLE BACKGROUND API VERIFICATION
// ====================================================================
if (isset($_GET['action']) && $_GET['action'] === 'verify_license') {
    header('Content-Type: application/json');
    $key = $_REQUEST['key'] ?? '';

    // Developer Bypass
    if ($key === 'ABI-MASTER-PASS') {
        echo json_encode([
            'status' => 'active',
            'tier' => 'pro',
            'expiredate' => 'never'
        ]);
        exit;
    }

    try {
        if (!$pdo) {
            echo json_encode(['status' => 'error', 'message' => 'Database Error']);
            exit;
        }

        $stmt = $pdo->prepare("SELECT status, expiredate, license_tier FROM license_keys WHERE license_key = :key LIMIT 1");
        $stmt->bindParam(':key', $key);
        $stmt->execute();

        if ($stmt->rowCount() > 0) {
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            $tier = (!empty($row['license_tier']) && strtolower($row['license_tier']) === 'basic') ? 'basic' : 'pro';
            
            if ($row['status'] !== 'active') {
                echo json_encode(['status' => 'inactive']);
            } 
            elseif (!empty($row['expiredate']) && $row['expiredate'] !== 'never' && strtotime($row['expiredate']) < time()) {
                echo json_encode(['status' => 'expired']);
            } else {
                echo json_encode([
                    'status' => 'active',
                    'tier' => $tier,
                    'expiredate' => !empty($row['expiredate']) ? $row['expiredate'] : 'never'
                ]);
            }
        } else {
            echo json_encode(['status' => 'invalid', 'message' => 'License key not found!']);
        }
    } catch (Exception $e) {
        echo json_encode(['status' => 'error', 'message' => 'Database Error']);
    }
    exit;
}

// ====================================================================
// 3. HANDLE BROWSER ACTIVATION (When User enters key in Desktop App)
// ====================================================================
if (isset($_REQUEST['key']) && (!isset($_GET['action']) || $_GET['action'] === 'activate' || $_GET['action'] === 'browser_activate')) {
    $license_key = trim($_REQUEST['key']);

    if (empty($license_key)) {
        header("Location: http://127.0.0.1:5000/api/activate_callback?status=invalid&message=" . urlencode("No license key provided. Please contact +91 7016797720 or sales@a-b-infotech.in"));
        exit;
    }

    if ($license_key === 'ABI-MASTER-PASS') {
        header("Location: http://127.0.0.1:5000/api/activate_callback?status=valid&key=ABI-MASTER-PASS&expiredate=never&tier=pro");
        exit;
    }

    try {
        if (!$pdo) {
            header("Location: http://127.0.0.1:5000/api/activate_callback?status=error&message=" . urlencode("Database Connection Error"));
            exit;
        }

        $query = "SELECT id, status, expiredate, license_tier, activated_at FROM license_keys WHERE license_key = :key LIMIT 1";
        $stmt = $pdo->prepare($query);
        $stmt->bindParam(':key', $license_key);
        $stmt->execute();

        if ($stmt->rowCount() > 0) {
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            
            // If key status in database is inactive: activate key and set starting date and time as current system date and time
            if (strtolower($row['status']) === 'inactive') {
                if (empty($row['expiredate']) || $row['expiredate'] === '0000-00-00 00:00:00') {
                    $upd = $pdo->prepare("UPDATE license_keys SET status = 'active', activated_at = NOW(), expiredate = DATE_ADD(NOW(), INTERVAL 1 YEAR) WHERE id = :id");
                    $upd->execute([':id' => $row['id']]);
                    $row['expiredate'] = date('Y-m-d H:i:s', strtotime('+1 year'));
                } else {
                    $upd = $pdo->prepare("UPDATE license_keys SET status = 'active', activated_at = NOW() WHERE id = :id");
                    $upd->execute([':id' => $row['id']]);
                }
                $row['status'] = 'active';
                $row['activated_at'] = date('Y-m-d H:i:s');
            }

            // Block if suspended, revoked or blocked
            if ($row['status'] !== 'active') {
                header("Location: http://127.0.0.1:5000/api/activate_callback?status=invalid&message=" . urlencode("This license key is " . $row['status'] . ". Please contact +91 7016797720 (sales@a-b-infotech.in) to activate."));
                exit;
            }

            // Block if expired
            if (!empty($row['expiredate']) && $row['expiredate'] !== 'never' && strtotime($row['expiredate']) < time()) {
                header("Location: http://127.0.0.1:5000/api/activate_callback?status=invalid&message=" . urlencode("This license key has expired. Please contact +91 7016797720 (sales@a-b-infotech.in) to renew."));
                exit;
            }

            // Update activated_at if first time activated and empty
            if (empty($row['activated_at']) || $row['activated_at'] === '0000-00-00 00:00:00') {
                $upd = $pdo->prepare("UPDATE license_keys SET activated_at = NOW() WHERE id = :id");
                $upd->execute([':id' => $row['id']]);
            }

            $exp_date = !empty($row['expiredate']) ? $row['expiredate'] : 'never';
            $tier = (!empty($row['license_tier']) && strtolower($row['license_tier']) === 'basic') ? 'basic' : 'pro';

            header("Location: http://127.0.0.1:5000/api/activate_callback?status=valid&key=" . urlencode($license_key) . "&expiredate=" . urlencode($exp_date) . "&tier=" . urlencode($tier));
            exit;
        } else {
            // If license key not found: send error
            header("Location: http://127.0.0.1:5000/api/activate_callback?status=invalid&message=" . urlencode("License key not found! Please check your license key or contact +91 7016797720 / sales@a-b-infotech.in."));
            exit;
        }
    } catch (Exception $e) {
        header("Location: http://127.0.0.1:5000/api/activate_callback?status=error&message=" . urlencode("Database Error: " . $e->getMessage()));
        exit;
    }
}

// ====================================================================
// 4. AJAX ENDPOINT: FETCH LATEST VERSION METADATA FROM GITHUB
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
            ],
            'ssl' => [
                'verify_peer' => false,
                'verify_peer_name' => false
            ]
        ]);
        $v_content = @file_get_contents($vurl, false, $ctx);
        if ($v_content) {
            $parsed = @json_decode($v_content, true);
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

function sanitizeInput($input)
{
    return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
}

if (isset($_GET['action']) && $_GET['action'] === 'reset') {
    if (isset($_SESSION['pdfPath']) && file_exists($_SESSION['pdfPath'])) {
        @unlink($_SESSION['pdfPath']);
    }
    unset($_SESSION['pdfPath'], $_SESSION['fileName']);
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

$uploadError = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['pdfFile'])) {
    $fileName = basename($_FILES['pdfFile']['name']);
    $fileExtension = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));

    if ($fileExtension !== 'pdf') {
        $uploadError = 'Only valid PDF documents are allowed.';
    } else {
        $uniqueFileName = uniqid('pdf_', true) . '.pdf';
        $filePath = $config['uploadDir'] . $uniqueFileName;

        if (move_uploaded_file($_FILES['pdfFile']['tmp_name'], $filePath)) {
            $_SESSION['pdfPath'] = $filePath;
            $_SESSION['fileName'] = $fileName;
            header('Location: ' . $_SERVER['PHP_SELF']);
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

<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700;800;900&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
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
    --card-bg: rgba(18, 25, 44, 0.82);
    --card-hover-bg: rgba(26, 36, 62, 0.88);
    --border-light: rgba(255, 255, 255, 0.12);
    --border-glow: rgba(13, 202, 240, 0.45);
    --primary-cyan: #0dcaf0;
    --primary-glow: rgba(13, 202, 240, 0.5);
    --accent-emerald: #10b981;
    --emerald-glow: rgba(16, 185, 129, 0.45);
    --win-color: #0078d4;
    --mac-color: #9333ea;
    --linux-color: #ea580c;
    --amber-color: #f59e0b;
    --red-color: #ef4444;
    --light-x: 50%;
    --light-y: 20%;
}

* {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
}

body {
    background: radial-gradient(1100px circle at var(--light-x) var(--light-y), rgba(13, 202, 240, 0.13), transparent 45%),
                radial-gradient(900px circle at 85% 85%, rgba(16, 185, 129, 0.09), transparent 40%),
                radial-gradient(700px circle at 15% 90%, rgba(147, 51, 234, 0.08), transparent 40%),
                #080d1a;
    color: #f8fafc;
    min-height: 100vh;
    overflow-x: hidden;
    position: relative;
    transition: background 0.05s ease-out;
}

#bg-img {
    position: fixed;
    top: 0; left: 0; width: 100%; height: 100%;
    object-fit: cover; z-index: -2; opacity: 0.25; pointer-events: none;
}

/* 3D Glassmorphism Cards with Specular Lighting Highlight */
.glass-3d {
    background: var(--card-bg);
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    border: 1px solid var(--border-light);
    border-radius: 20px;
    box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.75), 
                inset 0 1px 1px 0 rgba(255, 255, 255, 0.22),
                inset 0 -1px 1px 0 rgba(0, 0, 0, 0.4);
    position: relative;
    overflow: hidden;
    transition: transform 0.25s cubic-bezier(0.4, 0, 0.2, 1), box-shadow 0.25s ease, border-color 0.25s ease;
}

.glass-3d::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0; height: 1px;
    background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.4), transparent);
    pointer-events: none;
}

/* Top Navigation Bar with Specular Lighting */
.top-nav {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 12px 28px;
    background: rgba(11, 17, 33, 0.88);
    backdrop-filter: blur(16px);
    border-bottom: 1px solid rgba(255, 255, 255, 0.09);
    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5), inset 0 -1px 0 rgba(255, 255, 255, 0.05);
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
    box-shadow: 0 4px 14px rgba(0, 0, 0, 0.35), inset 0 1px 0 rgba(255, 255, 255, 0.9);
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
    text-shadow: 0 2px 10px rgba(255, 255, 255, 0.1);
}

.brand-subtitle {
    font-size: 0.75rem;
    color: #0dcaf0;
    font-weight: 700;
    letter-spacing: 0.4px;
    text-shadow: 0 0 12px rgba(13, 202, 240, 0.6);
}

.nav-actions {
    display: flex;
    align-items: center;
    gap: 12px;
}

/* 3D Glowing Status Pills */
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
    border: 1px solid rgba(16, 185, 129, 0.35);
    box-shadow: 0 0 14px rgba(16, 185, 129, 0.25), inset 0 1px 0 rgba(255, 255, 255, 0.2);
}

.status-pill.offline {
    background: rgba(239, 68, 68, 0.15);
    color: #f87171;
    border-color: rgba(239, 68, 68, 0.35);
    box-shadow: 0 0 14px rgba(239, 68, 68, 0.25), inset 0 1px 0 rgba(255, 255, 255, 0.1);
}

.status-pill.trial {
    background: rgba(245, 158, 11, 0.18);
    color: #fbbf24;
    border-color: rgba(245, 158, 11, 0.4);
    box-shadow: 0 0 14px rgba(245, 158, 11, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.2);
    animation: pulseGlow 2.5s infinite;
}

.status-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: currentColor;
    box-shadow: 0 0 10px currentColor;
}

@keyframes pulseGlow {
    0%, 100% { box-shadow: 0 0 14px rgba(245, 158, 11, 0.3); }
    50% { box-shadow: 0 0 22px rgba(245, 158, 11, 0.65); }
}

/* 3D Tactile Extruded Push Buttons */
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
    position: relative;
    transition: all 0.15s cubic-bezier(0.4, 0, 0.2, 1);
    box-shadow: 0 4px 0 rgba(0, 0, 0, 0.35), 0 8px 18px rgba(0, 0, 0, 0.4), inset 0 1px 0 rgba(255, 255, 255, 0.28);
}

.btn-3d:hover {
    transform: translateY(-2px);
    box-shadow: 0 6px 0 rgba(0, 0, 0, 0.35), 0 12px 24px rgba(0, 0, 0, 0.5), inset 0 1px 0 rgba(255, 255, 255, 0.35);
}

.btn-3d:active {
    transform: translateY(3px);
    box-shadow: 0 1px 0 rgba(0, 0, 0, 0.35), 0 4px 8px rgba(0, 0, 0, 0.4);
}

.btn-3d:disabled {
    opacity: 0.5;
    cursor: not-allowed;
    transform: none !important;
    box-shadow: none !important;
}

.btn-cyan {
    background: linear-gradient(135deg, #0dcaf0 0%, #0284c7 100%);
    color: #04101e;
}
.btn-cyan:hover {
    background: linear-gradient(135deg, #38bdf8 0%, #0369a1 100%);
    box-shadow: 0 6px 0 #0369a1, 0 12px 25px rgba(13, 202, 240, 0.45);
    color: #000000;
}

.btn-green {
    background: linear-gradient(135deg, #10b981 0%, #059669 100%);
    color: #ffffff;
}
.btn-green:hover {
    background: linear-gradient(135deg, #34d399 0%, #047857 100%);
    box-shadow: 0 6px 0 #047857, 0 12px 25px rgba(16, 185, 129, 0.45);
}

.btn-red {
    background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
    color: #ffffff;
}
.btn-red:hover {
    background: linear-gradient(135deg, #f87171 0%, #b91c1c 100%);
    box-shadow: 0 6px 0 #b91c1c, 0 12px 25px rgba(239, 68, 68, 0.45);
}

.btn-amber {
    background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
    color: #ffffff;
}
.btn-amber:hover {
    background: linear-gradient(135deg, #fbbf24 0%, #b45309 100%);
    box-shadow: 0 6px 0 #b45309, 0 12px 25px rgba(245, 158, 11, 0.45);
}

.btn-tool {
    background: rgba(255, 255, 255, 0.08);
    color: #e2e8f0;
    border: 1px solid rgba(255, 255, 255, 0.15);
    padding: 8px 16px;
    font-size: 0.85rem;
    box-shadow: 0 3px 0 rgba(0, 0, 0, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.15);
}
.btn-tool:hover {
    background: rgba(255, 255, 255, 0.18);
    color: #ffffff;
    box-shadow: 0 4px 0 rgba(0, 0, 0, 0.3), 0 6px 15px rgba(0, 0, 0, 0.4);
}

/* 3D Glass Form Inputs */
.glass-input {
    width: 100%;
    padding: 11px 14px;
    border-radius: 10px;
    border: 1px solid rgba(13, 202, 240, 0.28);
    background: rgba(10, 15, 28, 0.65);
    color: #ffffff;
    font-size: 0.88rem;
    margin-bottom: 12px;
    outline: none;
    box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.5), 0 1px 0 rgba(255, 255, 255, 0.08);
    transition: all 0.2s ease;
}

.glass-input:focus {
    border-color: #0dcaf0;
    background: rgba(10, 15, 28, 0.9);
    box-shadow: 0 0 15px rgba(13, 202, 240, 0.4), inset 0 2px 4px rgba(0, 0, 0, 0.5);
}

.glass-input option {
    background: #0f172a;
    color: #ffffff;
}

/* 3D Drag & Drop Upload Zone */
.upload-card-wrapper {
    max-width: 660px;
    margin: 5vh auto;
    padding: 40px;
    text-align: center;
}

.upload-dropzone {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    width: 100%;
    border: 2px dashed rgba(13, 202, 240, 0.5);
    border-radius: 20px;
    padding: 45px 24px;
    background: rgba(13, 202, 240, 0.03);
    cursor: pointer;
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    margin-bottom: 25px;
    box-shadow: inset 0 2px 10px rgba(0, 0, 0, 0.3);
}

.upload-dropzone:hover {
    border-color: #0dcaf0;
    background: rgba(13, 202, 240, 0.09);
    transform: translateY(-3px);
    box-shadow: 0 12px 30px rgba(13, 202, 240, 0.25), inset 0 2px 10px rgba(0, 0, 0, 0.3);
}

.upload-icon-pulse {
    font-size: 3.8rem;
    margin-bottom: 14px;
    display: inline-block;
    filter: drop-shadow(0 4px 14px rgba(13, 202, 240, 0.55));
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
    margin: 16px auto;
    height: calc(100vh - 95px);
}

.sidebar-panel {
    width: 360px;
    flex-shrink: 0;
    display: flex;
    flex-direction: column;
    padding: 18px;
    overflow-y: auto;
}

.editor-stage {
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow: hidden;
}

.stage-toolbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 10px 18px;
    background: rgba(10, 15, 28, 0.7);
    border-bottom: 1px solid rgba(255, 255, 255, 0.08);
    flex-wrap: wrap;
    gap: 10px;
}

.canvas-viewport {
    flex: 1;
    overflow: auto;
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 24px;
    background: radial-gradient(circle at 50% 50%, #151c2e 0%, #0a0f1d 100%);
    position: relative;
    scroll-behavior: smooth;
    scrollbar-width: thin;
    scrollbar-color: #0dcaf0 rgba(10, 15, 28, 0.95);
}

/* Custom 3D Glowing Scrollbars for PDF Viewport */
.canvas-viewport::-webkit-scrollbar {
    width: 12px;
    height: 12px;
}
.canvas-viewport::-webkit-scrollbar-track {
    background: rgba(10, 15, 28, 0.95);
    border-radius: 8px;
    border: 1px solid rgba(255, 255, 255, 0.08);
}
.canvas-viewport::-webkit-scrollbar-thumb {
    background: linear-gradient(180deg, #0284c7 0%, #0dcaf0 100%);
    border-radius: 8px;
    border: 2px solid #0b1120;
    box-shadow: 0 0 10px rgba(13, 202, 240, 0.5);
}
.canvas-viewport::-webkit-scrollbar-thumb:hover {
    background: linear-gradient(180deg, #38bdf8 0%, #22d3ee 100%);
    box-shadow: 0 0 16px rgba(13, 202, 240, 0.85);
}

/* Strict Scroll Lock when Drawing Signature Box */
.canvas-viewport.drawing-locked {
    overflow: hidden !important;
    touch-action: none !important;
    user-select: none !important;
    -webkit-user-select: none !important;
    overscroll-behavior: none !important;
}

.pdf-bezel {
    position: relative;
    background: #ffffff;
    box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.85), 0 0 30px rgba(13, 202, 240, 0.15);
    border-radius: 4px;
    overflow: hidden;
    transition: transform 0.2s ease;
    margin: 0 auto;
    flex-shrink: 0;
}

.interaction-layer {
    position: absolute;
    top: 0; left: 0; width: 100%; height: 100%;
    cursor: grab;
}

.interaction-layer.active-selection {
    cursor: crosshair !important;
}

/* Floating Smooth Scroll Navigator on Right Edge */
.floating-scroll-dock {
    position: absolute;
    right: 18px;
    top: 50%;
    transform: translateY(-50%);
    display: flex;
    flex-direction: column;
    gap: 8px;
    z-index: 50;
    background: rgba(15, 23, 42, 0.85);
    backdrop-filter: blur(10px);
    -webkit-backdrop-filter: blur(10px);
    padding: 8px 6px;
    border-radius: 24px;
    border: 1px solid rgba(56, 189, 248, 0.25);
    box-shadow: 0 12px 30px rgba(0, 0, 0, 0.6), 0 0 15px rgba(13, 202, 240, 0.2);
    transition: all 0.25s ease;
}

.floating-scroll-dock.hidden-during-draw {
    opacity: 0.2;
    pointer-events: none;
    transform: translateY(-50%) scale(0.9);
}

.btn-float-scroll {
    width: 36px;
    height: 36px;
    border-radius: 50%;
    background: rgba(30, 41, 59, 0.9);
    border: 1px solid rgba(56, 189, 248, 0.3);
    color: #38bdf8;
    font-size: 13px;
    font-weight: 800;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: all 0.2s ease;
    box-shadow: 0 4px 10px rgba(0, 0, 0, 0.4);
}

.btn-float-scroll:hover {
    background: linear-gradient(135deg, #0284c7 0%, #0dcaf0 100%);
    color: #ffffff;
    transform: scale(1.12);
    box-shadow: 0 0 14px rgba(13, 202, 240, 0.7);
    border-color: #38bdf8;
}

/* Watermark Preview Bar on Canvas Stage */
.stage-watermark-banner {
    width: 100%;
    background: rgba(245, 158, 11, 0.12);
    border: 1px solid rgba(245, 158, 11, 0.35);
    border-radius: 8px;
    padding: 6px 14px;
    margin-bottom: 14px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 0.8rem;
    color: #fbbf24;
    box-shadow: 0 2px 10px rgba(245, 158, 11, 0.15);
}

.selection-ghost {
    position: absolute;
    border: 2px dashed #0dcaf0;
    background: rgba(13, 202, 240, 0.2);
    pointer-events: none;
    border-radius: 4px;
}

.signature-stamp-box {
    position: absolute;
    border: 2px solid #10b981;
    background: rgba(16, 185, 129, 0.18);
    color: #10b981;
    font-weight: 700;
    font-size: 11px;
    padding: 6px;
    box-sizing: border-box;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    text-align: center;
    border-radius: 6px;
    box-shadow: 0 4px 12px rgba(16, 185, 129, 0.3);
}

/* 3D Multi-OS Download Cards Grid (Exact Specifications) */
.cards-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 16px;
    margin: 20px 0;
}

@media (max-width: 900px) {
    .cards-grid { grid-template-columns: 1fr; }
    .workspace-container { flex-direction: column; height: auto; }
    .sidebar-panel { width: 100%; }
}

.os-card {
    background: rgba(15, 23, 42, 0.7);
    border: 1px solid rgba(255, 255, 255, 0.1);
    border-radius: 16px;
    padding: 24px 18px;
    text-align: center;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    align-items: center;
    box-shadow: 0 15px 35px rgba(0, 0, 0, 0.5), inset 0 1px 0 rgba(255, 255, 255, 0.15);
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
}

.os-card:hover {
    transform: translateY(-6px);
    border-color: rgba(13, 202, 240, 0.5);
    box-shadow: 0 20px 45px rgba(0, 0, 0, 0.7), 0 0 25px rgba(13, 202, 240, 0.25);
}

.os-icon {
    font-size: 3rem;
    margin-bottom: 12px;
    filter: drop-shadow(0 4px 10px rgba(0, 0, 0, 0.5));
}

.os-title {
    font-family: 'Outfit', sans-serif;
    font-size: 1.35rem;
    font-weight: 800;
    margin-bottom: 6px;
    color: #ffffff;
}

.os-desc {
    font-size: 0.8rem;
    color: #94a3b8;
    line-height: 1.5;
    margin-bottom: 18px;
    min-height: 48px;
}

.btn-download {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    width: 100%;
    padding: 12px 14px;
    border-radius: 10px;
    font-size: 0.88rem;
    font-weight: 700;
    text-decoration: none;
    color: #ffffff;
    box-shadow: 0 4px 0 rgba(0, 0, 0, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.25);
    transition: all 0.2s ease;
}

.btn-download:hover {
    transform: translateY(-2px);
    box-shadow: 0 6px 15px rgba(0, 0, 0, 0.4);
}

.btn-win {
    background: linear-gradient(135deg, #0078d4 0%, #005a9e 100%);
}
.btn-mac {
    background: linear-gradient(135deg, #9333ea 0%, #6b21a8 100%);
}
.btn-linux {
    background: linear-gradient(135deg, #ea580c 0%, #c2410c 100%);
}

.file-info {
    font-size: 0.72rem;
    color: #64748b;
    margin-top: 10px;
    word-break: break-all;
}

/* 3D Modal Overlays */
.overlay-backdrop {
    position: fixed;
    top: 0; left: 0; width: 100%; height: 100%;
    background: rgba(4, 7, 15, 0.85);
    backdrop-filter: blur(14px);
    display: none;
    align-items: center;
    justify-content: center;
    z-index: 1000;
    padding: 20px;
}

.modal-3d {
    max-width: 780px;
    width: 100%;
    padding: 34px 28px;
    text-align: center;
    border-radius: 24px;
    border: 1px solid rgba(255, 255, 255, 0.15);
    box-shadow: 0 30px 70px rgba(0, 0, 0, 0.9), 0 0 40px rgba(13, 202, 240, 0.2);
    animation: modalPop 0.3s cubic-bezier(0.34, 1.56, 0.64, 1);
}

@keyframes modalPop {
    from { transform: scale(0.9) translateY(20px); opacity: 0; }
    to { transform: scale(1) translateY(0); opacity: 1; }
}

.modal-badge {
    display: inline-block;
    padding: 5px 14px;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 800;
    letter-spacing: 0.5px;
    margin-bottom: 12px;
}
</style>
</head>
<body>

<img id="bg-img" src="image_546aa0.png" alt="A B INFOTECH Background" onerror="this.style.display='none'">

<!-- ====================================================================
     TOP NAVIGATION BAR WITH 3D LIGHT EFFECT & TRIAL STATUS
     ==================================================================== -->
<header class="top-nav">
    <a href="Token.php" class="brand-section">
        <div class="logo-badge">
            <img src="app_icon.png" alt="A B INFOTECH" style="height:36px; width:36px; object-fit:contain;">
        </div>
        <div>
            <div class="brand-title">A B INFOTECH</div>
            <div class="brand-subtitle">WEB DIGITAL SIGNER SUITE</div>
        </div>
    </a>

    <div class="nav-actions">
        <!-- 4-Day Free Web Trial Badge -->
        <span id="trialBadge" class="status-pill trial" style="display:none;" title="Click for trial info">
            <span class="status-dot"></span>
            <span id="trialBadgeText">🎁 4-Day Free Trial</span>
        </span>

        <!-- Local Server Status Pill (Clickable to Reopen Download Modal) -->
        <div id="serverStatusPill" class="status-pill offline" onclick="openOfflineModal()" style="cursor:pointer;" title="Click to view software setup & download options">
            <span class="status-dot"></span>
            <span id="serverStatusText">Local Server: OFFLINE</span>
        </div>

        <!-- License Tier Pill -->
        <div id="licensePill" class="status-pill" style="display:none; background: rgba(59, 130, 246, 0.15); color: #60a5fa; border-color: rgba(59, 130, 246, 0.35);">
            <span class="status-dot"></span>
            <span id="licenseTierText">PRO SUITE</span>
        </div>

        <a href="https://pay.a-b-infotech.in/license.php" target="_blank" class="btn-3d btn-amber" style="padding: 7px 14px; font-size: 0.8rem;">
            🛒 Buy License
        </a>

        <a href="https://api.whatsapp.com/send?phone=917016797720&text=Hi%20A%20B%20INFOTECH%20Team" target="_blank" class="btn-3d btn-green" style="padding: 7px 14px; font-size: 0.8rem;">
            💬 Support
        </a>
    </div>
</header>

<!-- ====================================================================
     OVERLAY 1: LOCAL API SERVER REQUIRED
     Includes the Exact Multi-OS Cards Grid
     ==================================================================== -->
<div id="offline-overlay" class="overlay-backdrop">
    <div class="glass-3d modal-3d" style="position:relative;">
        <button type="button" onclick="closeOfflineModal()" style="position:absolute; top:16px; right:18px; background:rgba(255,255,255,0.1); border:none; color:#cbd5e1; font-size:1.1rem; width:32px; height:32px; border-radius:50%; cursor:pointer; display:flex; align-items:center; justify-content:center; transition:background 0.2s;" title="Close popup">✕</button>
        <span class="modal-badge" style="background: rgba(239, 68, 68, 0.15); color:#f87171; border: 1px solid rgba(239, 68, 68, 0.3);">
            🔌 Local Signing Server Required
        </span>
        <h2 style="font-family:'Outfit',sans-serif; font-size:1.85rem; font-weight:800; margin-bottom:8px;">
            A B INFOTECH Background Local Signer 
        </h2>
        <p style="color:#94a3b8; font-size:0.92rem; max-width:680px; margin:0 auto 18px; line-height:1.5;">
            To digitally sign PDF documents using physical USB Cryptographic Tokens, the background signing service must be running on your machine.
            If you already installed it, please launch <b>A B INFOTECH SIGNER</b> from your desktop or start menu.
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

        <div style="margin-top: 10px;">
            <button onclick="checkBackgroundServer()" class="btn-3d btn-cyan" style="min-width: 220px;">
                ↻ Retry Server Connection
            </button>
        </div>
    </div>
</div>

<!-- ====================================================================
     OVERLAY 2: SOFTWARE UPDATE REQUIRED (CHECKED FROM GITHUB VERSION.JSON)
     ==================================================================== -->
<div id="update-overlay" class="overlay-backdrop">
    <div class="glass-3d modal-3d">
        <span class="modal-badge" style="background: rgba(245, 158, 11, 0.15); color:#fbbf24; border: 1px solid rgba(245, 158, 11, 0.3);">
            🔄 Version Update Required
        </span>
        <h2 style="font-family:'Outfit',sans-serif; font-size:1.85rem; font-weight:800; margin-bottom:8px;">
            Update Your A B INFOTECH Signer Suite
        </h2>
        <p id="updateVersionDetails" style="color:#94a3b8; font-size:0.92rem; max-width:680px; margin:0 auto 18px; line-height:1.5;">
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

        <div style="margin-top: 10px;">
            <button onclick="checkBackgroundServer()" class="btn-3d btn-cyan" style="min-width: 220px;">
                ↻ Re-check Version & Connect
            </button>
        </div>
    </div>
</div>

<!-- ====================================================================
     OVERLAY 3: 4-DAY FREE TRIAL EXPIRED (WEB TRIAL LIMIT REACHED)
     ==================================================================== -->
<div id="trial-expired-overlay" class="overlay-backdrop">
    <div class="glass-3d modal-3d" style="max-width: 520px;">
        <span class="modal-badge" style="background: rgba(239, 68, 68, 0.15); color:#f87171; border: 1px solid rgba(239, 68, 68, 0.3);">
            ⏳ 4-Day Free Trial Expired
        </span>
        <h2 style="font-family:'Outfit',sans-serif; font-size:1.8rem; font-weight:800; margin-bottom:12px;">
            Trial Period Ended
        </h2>
        <p style="color:#94a3b8; font-size:0.92rem; line-height:1.6; margin-bottom: 22px;">
            Your <b>4-day free trial</b> of A B INFOTECH Web Signer has expired. To continue signing your PDF documents with USB tokens and remove the demo trial watermark, please purchase an active license key.
        </p>

        <a href="https://pay.a-b-infotech.in/license.php" target="_blank" class="btn-3d btn-amber" style="width: 100%; font-size: 1rem; margin-bottom: 12px;">
            💳 Buy / Activate License Key Online
        </a>

        <a href="https://api.whatsapp.com/send?phone=917016797720&text=Hi%20A%20B%20INFOTECH%20Team%2C%20My%204-day%20free%20trial%20expired%20and%20I%20want%20to%20buy%20a%20license" target="_blank" class="btn-3d btn-green" style="width: 100%; margin-bottom: 14px;">
            💬 WhatsApp Support (+91 7016797720)
        </a>

        <div style="background: rgba(10, 15, 28, 0.6); padding: 14px; border-radius: 12px; border: 1px solid rgba(255, 255, 255, 0.08); font-size: 0.8rem; color: #64748b;">
            Helpline: <b style="color:#38bdf8;">+91 7016797720</b> | Email: <b style="color:#38bdf8;">sales@a-b-infotech.in</b>
        </div>
    </div>
</div>

<!-- ====================================================================
     OVERLAY 4: SERVER LICENSE EXPIRED
     ==================================================================== -->
<div id="expired-overlay" class="overlay-backdrop">
    <div class="glass-3d modal-3d" style="max-width: 520px;">
        <span class="modal-badge" style="background: rgba(239, 68, 68, 0.15); color:#f87171; border: 1px solid rgba(239, 68, 68, 0.3);">
            ⏳ License Subscription Expired
        </span>
        <h2 style="font-family:'Outfit',sans-serif; font-size:1.8rem; font-weight:800; margin-bottom:12px;">
            License Renewal Required
        </h2>
        <p style="color:#94a3b8; font-size:0.92rem; line-height:1.6; margin-bottom: 22px;">
            Your A B INFOTECH Digital Signer license subscription has expired. Please renew your key to continue signing documents without restrictions.
        </p>

        <a href="https://pay.a-b-infotech.in/license.php" target="_blank" class="btn-3d btn-amber" style="width: 100%; font-size: 1rem; margin-bottom: 12px;">
            💳 Renew / Purchase License Online
        </a>

        <a href="https://api.whatsapp.com/send?phone=917016797720&text=I%20want%20to%20renew%20my%20PDF%20Signer%20License" target="_blank" class="btn-3d btn-green" style="width: 100%;">
            💬 Renew on WhatsApp (+91 7016797720)
        </a>
    </div>
</div>

<!-- ====================================================================
     PAGE 1: PDF UPLOAD SCREEN (When no PDF is in session)
     ==================================================================== -->
<?php if (!isset($_SESSION['pdfPath'])): ?>

<main class="upload-card-wrapper">
    <div class="glass-3d" style="padding: 40px 30px;">
        <div class="upload-icon-pulse">📑</div>
        <h1 style="font-family:'Outfit',sans-serif; font-size:2.1rem; font-weight:800; margin-bottom:8px;">
            Open PDF for Digital Signing
        </h1>
        <p style="color:#94a3b8; font-size:0.95rem; margin-bottom: 26px;">
            Select any PDF document to position your digital signature visually on any page.
        </p>

        <!-- 4-Day Trial Notice Badge -->
        <div id="uploadTrialBanner" style="display:none; background:rgba(245, 158, 11, 0.12); border:1px solid rgba(245, 158, 11, 0.3); border-radius:12px; padding:12px 16px; margin-bottom:20px; font-size:0.85rem; color:#fbbf24; text-align:center;">
            🎁 <b>4-Day Free Web Trial Active:</b> You can sign documents using your USB Hardware Token. In trial mode, documents include a small <code>ABINFO SIGN DEMO</code> watermark on each page.
        </div>

        <!-- Server Offline Warning Banner -->
        <div id="uploadOfflineBanner" style="display:none; background:rgba(239, 68, 68, 0.15); border:1px solid rgba(239, 68, 68, 0.4); border-radius:12px; padding:14px 18px; margin-bottom:20px; font-size:0.88rem; color:#f87171; text-align:center;">
            🔌 <b>Local Signing Server is OFFLINE:</b> Physical USB tokens require the local signing service.<br>
            <div style="margin-top:8px;">
                <button type="button" onclick="openOfflineModal()" class="btn-3d btn-cyan" style="padding:6px 16px; font-size:0.8rem;">
                    ⬇️ Download / Setup Desktop Client
                </button>
            </div>
        </div>

        <?php if ($uploadError): ?>
            <div style="background:rgba(239,68,68,0.15); color:#f87171; border:1px solid rgba(239,68,68,0.3); padding:10px; border-radius:10px; margin-bottom:20px; font-size:0.9rem;">
                <?= $uploadError ?>
            </div>
        <?php endif; ?>

        <form method="POST" enctype="multipart/form-data">
            <label for="pdfFile" class="upload-dropzone">
                <div style="font-size: 2.2rem; margin-bottom: 8px;">📂</div>
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
if (fileInput) {
    fileInput.addEventListener('change', function() {
        if (this.files && this.files[0]) {
            const sizeMb = (this.files[0].size / (1024 * 1024)).toFixed(2);
            chosenText.innerHTML = `✓ ${this.files[0].name} <span style="font-size:0.8rem; color:#94a3b8;">(${sizeMb} MB)</span>`;
        }
    });
}
</script>

<!-- ====================================================================
     PAGE 2: INTERACTIVE SIGNING STUDIO WORKSPACE
     ==================================================================== -->
<?php else: ?>

<div class="workspace-container">
    <!-- LEFT SIDEBAR: Comprehensive Signature Settings -->
    <aside class="glass-3d sidebar-panel">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px; border-bottom:1px solid rgba(255,255,255,0.08); padding-bottom:10px;">
            <h3 style="font-family:'Outfit',sans-serif; font-size:1.15rem; font-weight:700; color:#38bdf8;">
                ⚙️ Signature Settings
            </h3>
            <span id="workspaceLicenseTag" class="status-pill" style="padding:3px 10px; font-size:0.7rem;">Active</span>
        </div>

        <div style="background:rgba(10,15,28,0.5); padding:10px 12px; border-radius:10px; margin-bottom:14px; border:1px solid rgba(255,255,255,0.06);">
            <div style="font-size:0.72rem; color:#64748b; font-weight:600;">ACTIVE DOCUMENT</div>
            <div style="word-break:break-all; font-size:0.85rem; font-weight:600; color:#e2e8f0;">
                <?= sanitizeInput($_SESSION['fileName']) ?>
            </div>
        </div>

        <!-- 4-Day Trial Sidebar Notice -->
        <div id="trialSidebarNotice" style="display:none; background:rgba(245, 158, 11, 0.12); border:1px solid rgba(245, 158, 11, 0.3); border-radius:10px; padding:10px; margin-bottom:14px; font-size:0.78rem; color:#fbbf24;">
            🎁 <b>4-Day Free Web Trial:</b> <span id="trialDaysRemainingText">4 days remaining</span>.<br>
            Signed document will contain small <code>ABINFO SIGN DEMO</code> watermark at the bottom of each page.
        </div>

        <form id="signForm" style="display:flex; flex-direction:column; flex:1;">
            <!-- 1. Driver Selection -->
            <label style="font-size:0.78rem; color:#94a3b8; font-weight:700; margin-bottom:4px;">
                1. USB Token Driver
            </label>
            <select class="glass-input" id="driverDropdownWorkspace"></select>

            <!-- 2. Certificate Selection -->
            <label style="font-size:0.78rem; color:#94a3b8; font-weight:700; margin-bottom:4px;">
                2. Digital Certificate
            </label>
            <select class="glass-input" name="certAlias" required>
                <option value="">-- Choose Certificate --</option>
            </select>

            <!-- 3. Hardware Token PIN -->
            <label style="font-size:0.78rem; color:#94a3b8; font-weight:700; margin-bottom:4px;">
                3. USB Hardware Token PIN
            </label>
            <div style="position:relative; margin-bottom:12px;">
                <input type="password" class="glass-input" id="tokenPinInput" name="tokenPassword" placeholder="Enter Token User PIN" style="margin-bottom:0;" required>
                <button type="button" onclick="togglePinVisibility()" style="position:absolute; right:10px; top:50%; transform:translateY(-50%); background:transparent; border:none; color:#94a3b8; cursor:pointer; font-size:0.85rem;">
                    👁️
                </button>
            </div>

            <!-- 4. Signature Metadata & Appearance -->
            <label style="font-size:0.78rem; color:#94a3b8; font-weight:700; margin-bottom:4px;">
                4. Signing Reason
            </label>
            <select class="glass-input" id="signReasonSelect" name="signReason">
                <option value="I approve this document">I approve this document</option>
                <option value="I am the author of this document">I am the author of this document</option>
                <option value="Official Authentication">Official Authentication</option>
                <option value="Verified and Approved">Verified and Approved</option>
            </select>

            <label style="font-size:0.78rem; color:#94a3b8; font-weight:700; margin-bottom:4px;">
                5. Signer Location / Address
            </label>
            <input type="text" class="glass-input" id="signLocationInput" name="signLocation" placeholder="e.g. Gujarat, India">

            <!-- Checkbox Options Cluster -->
            <div style="background:rgba(10,15,28,0.4); padding:10px; border-radius:10px; margin-bottom:14px; border:1px solid rgba(255,255,255,0.06);">
                <div style="font-size:0.72rem; color:#64748b; font-weight:700; margin-bottom:6px;">DISPLAY ELEMENTS IN STAMP</div>
                <div style="display:grid; grid-template-columns: 1fr 1fr; gap:6px; font-size:0.78rem;">
                    <label><input type="checkbox" id="chkName" checked> Signer Name</label>
                    <label><input type="checkbox" id="chkDate" checked> Timestamp</label>
                    <label><input type="checkbox" id="chkReason" checked> Reason</label>
                    <label><input type="checkbox" id="chkLocation" checked> Location</label>
                    <label><input type="checkbox" id="chkTick" checked> Green Tick</label>
                    <label><input type="checkbox" id="chkBorder" checked> Box Border</label>
                </div>

                <!-- ALL PAGES SIGN CHECKBOX -->
                <div style="margin-top: 10px; padding-top: 8px; border-top: 1px solid rgba(255,255,255,0.08);">
                    <label style="display:flex; align-items:center; gap:8px; font-size:0.82rem; font-weight:700; color:#38bdf8; cursor:pointer;">
                        <input type="checkbox" id="chkAllPages" name="allPages" style="width:16px; height:16px;">
                        📑 Sign on All Pages
                    </label>
                    <div id="allPagesNote" style="display:none; font-size:0.72rem; color:#94a3b8; margin-top:3px; margin-left:24px;">
                        ✓ Stamp will be placed at this exact position on every page.
                    </div>
                </div>
            </div>

            <!-- CUSTOM LOGO SECTION -->
            <div style="background:rgba(10,15,28,0.45); padding:10px 12px; border-radius:10px; margin-bottom:14px; border:1px solid rgba(255,255,255,0.06);">
                <div style="font-size:0.72rem; color:#64748b; font-weight:700; margin-bottom:6px;">CUSTOM STAMP LOGO (OPTIONAL)</div>
                <div style="display:flex; align-items:center; gap:8px;">
                    <label for="customLogoInput" class="btn-3d btn-tool" style="cursor:pointer; font-size:0.78rem; padding:6px 12px; margin:0;">
                        📁 Choose Logo...
                    </label>
                    <input type="file" id="customLogoInput" accept="image/png,image/jpeg" style="display:none;">
                    <span id="logoFileNameDisplay" style="font-size:0.75rem; color:#94a3b8; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; max-width:130px;">Default Seal</span>
                    <button type="button" id="removeLogoBtn" style="display:none; background:transparent; border:none; color:#f87171; cursor:pointer; font-size:0.85rem;" title="Remove Custom Logo">✕</button>
                </div>
                <div id="logoPreviewBox" style="display:none; margin-top:8px; align-items:center; gap:8px;">
                    <img id="customLogoPreview" src="" alt="Logo Preview" style="height:32px; max-width:70px; object-fit:contain; border-radius:4px; background:#ffffff; padding:2px; border:1px solid #38bdf8;">
                    <span style="font-size:0.72rem; color:#34d399; font-weight:600;">✓ Custom logo active</span>
                </div>
            </div>

            <!-- Placed Signature Areas Summary -->
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                <span style="font-size:0.78rem; color:#94a3b8; font-weight:700;">PLACED SIGNATURE BOXES</span>
                <span id="placedCountBadge" style="font-size:0.75rem; color:#38bdf8; font-weight:700;">0 Boxes</span>
            </div>
            <div id="signatureList" style="min-height:70px; max-height:120px; overflow-y:auto; background:rgba(10,15,28,0.5); padding:8px 10px; border-radius:10px; margin-bottom:14px; border:1px solid rgba(255,255,255,0.06); font-size:0.78rem;">
                No signatures drawn yet. Click 'Draw Signature Box' on right.
            </div>

            <!-- Action Buttons -->
            <div style="margin-top:auto;">
                <button type="submit" class="btn-3d btn-green" id="finalSignBtn" disabled style="width: 100%; font-size: 0.95rem; padding: 13px; margin-bottom: 8px;">
                    ✍️ Sign Document Now
                </button>
                <a href="?action=reset" class="btn-3d btn-red" style="width: 100%; font-size: 0.82rem; padding: 8px;">
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

            <!-- PDF Scroll Navigation Controls (Smooth Scroll / Lock Mode) -->
            <div class="scroll-toolbar-group" style="display:flex; align-items:center; gap:6px; background:rgba(255,255,255,0.04); padding:4px 10px; border-radius:10px; border:1px solid rgba(255,255,255,0.08);">
                <span id="scrollStatusBadge" style="font-size:0.75rem; color:#38bdf8; font-weight:700; display:flex; align-items:center; gap:4px;">
                    <span id="scrollModeIcon">📜</span> Scroll:
                </span>
                <button type="button" onclick="scrollPdfStage(-180)" class="btn-3d btn-tool" title="Scroll Up (or use mouse wheel / drag to pan)" style="padding:6px 10px; font-size:0.8rem;">▲ Up</button>
                <button type="button" onclick="scrollPdfStage(180)" class="btn-3d btn-tool" title="Scroll Down (or use mouse wheel / drag to pan)" style="padding:6px 10px; font-size:0.8rem;">▼ Down</button>
                <button type="button" onclick="fitPdfToView()" class="btn-3d btn-tool" title="Auto-Fit PDF to Viewport Width" style="padding:6px 10px; font-size:0.8rem;">⛶ Fit</button>
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

        <!-- Canvas Viewport with Floating Quick-Scroll Dock -->
        <div class="canvas-viewport" id="canvasViewport">
            <!-- Floating Quick Scroll Dock -->
            <div class="floating-scroll-dock" id="floatingScrollDock" title="PDF Scroll Navigator">
                <button type="button" onclick="scrollPdfToTop()" class="btn-float-scroll" title="Scroll to Top">⇱</button>
                <button type="button" onclick="scrollPdfStage(-220)" class="btn-float-scroll" title="Scroll Up">▲</button>
                <button type="button" onclick="scrollPdfStage(220)" class="btn-float-scroll" title="Scroll Down">▼</button>
                <button type="button" onclick="scrollPdfToBottom()" class="btn-float-scroll" title="Scroll to Bottom">⇲</button>
            </div>

            <!-- Subtle Watermark Notice Banner on Preview Stage -->
            <div id="canvasWatermarkBanner" class="stage-watermark-banner" style="display:none; max-width:620px;">
                <span>🏷️ <b>4-Day Free Web Trial:</b> Stamping small <code>ABINFO SIGN DEMO</code> watermark at the bottom of each page.</span>
                <a href="https://pay.a-b-infotech.in/license.php" target="_blank" style="color:#38bdf8; text-decoration:underline; font-weight:700;">Remove Watermark</a>
            </div>

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
    const pdfjsLib = window['pdfjs-dist/build/pdf'];
    const canvas = document.getElementById('pdfCanvas');
    const ctx = canvas ? canvas.getContext('2d') : null;
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
            if (!certSelect) return;
            
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
    <?php if (isset($_SESSION['pdfPath'])): ?>
    pdfjsLib.getDocument('<?= str_replace('\\', '/', $_SESSION['pdfPath']) ?>').promise.then(pdf => {
        pdfDoc = pdf;
        const totalPgs = document.getElementById('totalPages');
        if (totalPgs) totalPgs.textContent = pdf.numPages;
        renderPage(pageNum);
    });
    <?php endif; ?>

    function renderPage(num) {
        if (!pdfDoc || !canvas) return;
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
        const curEl = document.getElementById('currentPageNum');
        if (curEl) curEl.textContent = num;
    }

    window.changeZoom = function(delta) {
        let newScale = scale + delta;
        if (newScale < 0.6) newScale = 0.6;
        if (newScale > 2.5) newScale = 2.5;
        scale = newScale;
        const zoomDisplay = document.getElementById('zoomLevelDisplay');
        if (zoomDisplay) zoomDisplay.textContent = Math.round(scale * 100) + '%';
        renderPage(pageNum);
    };

    window.togglePinVisibility = function() {
        const pinInput = document.getElementById('tokenPinInput');
        if (pinInput) pinInput.type = (pinInput.type === 'password') ? 'text' : 'password';
    };

    const prevBtn = document.getElementById('prevPageBtn');
    if (prevBtn) {
        prevBtn.addEventListener('click', () => {
            if (pageNum <= 1) return;
            pageNum--; renderPage(pageNum);
        });
    }

    const nextBtn = document.getElementById('nextPageBtn');
    if (nextBtn) {
        nextBtn.addEventListener('click', () => {
            if (!pdfDoc || pageNum >= pdfDoc.numPages) return;
            pageNum++; renderPage(pageNum);
        });
    }

    const canvasViewport = document.getElementById('canvasViewport') || document.querySelector('.canvas-viewport');

    // Scroll Helper Functions
    window.scrollPdfStage = function(amount) {
        if (isSelecting) return; // STRICT: Do not scroll when drawing box
        if (canvasViewport) {
            canvasViewport.scrollBy({ top: amount, behavior: 'smooth' });
        }
    };

    window.scrollPdfToTop = function() {
        if (isSelecting) return;
        if (canvasViewport) {
            canvasViewport.scrollTo({ top: 0, behavior: 'smooth' });
        }
    };

    window.scrollPdfToBottom = function() {
        if (isSelecting) return;
        if (canvasViewport) {
            canvasViewport.scrollTo({ top: canvasViewport.scrollHeight, behavior: 'smooth' });
        }
    };

    window.fitPdfToView = function() {
        if (!pdfDoc || !canvas || !canvasViewport) return;
        pdfDoc.getPage(pageNum).then(page => {
            const unscaledViewport = page.getViewport({ scale: 1.0 });
            const availableWidth = Math.max(300, canvasViewport.clientWidth - 80);
            scale = Math.max(0.6, Math.min(2.5, availableWidth / unscaledViewport.width));
            const zoomDisplay = document.getElementById('zoomLevelDisplay');
            if (zoomDisplay) zoomDisplay.textContent = Math.round(scale * 100) + '%';
            renderPage(pageNum);
        });
    };

    // Strict Scroll Blocker Handler for Drawing Mode
    function blockScrollEvent(e) {
        if (isSelecting) {
            e.preventDefault();
            e.stopPropagation();
            return false;
        }
    }

    // Toggle Drawing Mode & Lock/Unlock Viewport Scroll
    function setDrawingMode(active) {
        isSelecting = active;
        const selectBtn = document.getElementById('selectAreaBtn');
        const scrollDock = document.getElementById('floatingScrollDock');
        const scrollBadge = document.getElementById('scrollStatusBadge');

        if (isSelecting) {
            if (selectBtn) {
                selectBtn.className = 'btn-3d btn-amber';
                selectBtn.innerHTML = '✏️ Drag to Draw (Scroll Locked)';
            }
            if (interactionLayer) {
                interactionLayer.classList.add('active-selection');
                interactionLayer.style.cursor = 'crosshair';
            }
            if (canvasViewport) {
                canvasViewport.classList.add('drawing-locked');
                canvasViewport.addEventListener('wheel', blockScrollEvent, { passive: false });
                canvasViewport.addEventListener('touchmove', blockScrollEvent, { passive: false });
            }
            window.addEventListener('wheel', blockScrollEvent, { passive: false });
            if (scrollDock) scrollDock.classList.add('hidden-during-draw');
            if (scrollBadge) {
                scrollBadge.style.color = '#f59e0b';
                scrollBadge.innerHTML = '<span id="scrollModeIcon">🔒</span> Locked (Draw Mode)';
            }
        } else {
            if (selectBtn) {
                selectBtn.className = 'btn-3d btn-cyan';
                selectBtn.innerHTML = '✏️ Draw Signature Box';
            }
            if (interactionLayer) {
                interactionLayer.classList.remove('active-selection');
                interactionLayer.style.cursor = 'grab';
            }
            if (canvasViewport) {
                canvasViewport.classList.remove('drawing-locked');
                canvasViewport.removeEventListener('wheel', blockScrollEvent);
                canvasViewport.removeEventListener('touchmove', blockScrollEvent);
            }
            window.removeEventListener('wheel', blockScrollEvent);
            if (scrollDock) scrollDock.classList.remove('hidden-during-draw');
            if (scrollBadge) {
                scrollBadge.style.color = '#38bdf8';
                scrollBadge.innerHTML = '<span id="scrollModeIcon">📜</span> Scroll:';
            }
        }
    }

    let isDrawingBox = false;
    let isPanning = false;
    let panStartX = 0, panStartY = 0;
    let scrollStartLeft = 0, scrollStartTop = 0;
    let startX = 0, startY = 0;

    const clearBtn = document.getElementById('clearAreasBtn');
    if (clearBtn) {
        clearBtn.addEventListener('click', function() {
            signatureAreas = [];
            updateSignatureList();
            drawSavedAreas();
            if (tempBox) { tempBox.remove(); tempBox = null; }
            currentArea = null;
            isDrawingBox = false;
            setDrawingMode(false);
        });
    }

    const selectBtn = document.getElementById('selectAreaBtn');
    if (selectBtn) {
        selectBtn.addEventListener('click', function() {
            setDrawingMode(!isSelecting);
        });
    }

    if (interactionLayer) {
        // Mousedown on interaction layer: Handles either Drawing Box (locked) or Panning / Scrolling
        interactionLayer.addEventListener('mousedown', e => {
            if (isSelecting) {
                // STRICT DRAWING MODE: ZERO SCROLL
                e.preventDefault();
                e.stopPropagation();
                isDrawingBox = true;

                const rect = interactionLayer.getBoundingClientRect();
                startX = Math.max(0, Math.min(e.clientX - rect.left, rect.width));
                startY = Math.max(0, Math.min(e.clientY - rect.top, rect.height));
                currentArea = { x: startX, y: startY, width: 0, height: 0 };

                if (tempBox) tempBox.remove();
                tempBox = document.createElement('div');
                tempBox.className = 'selection-ghost';
                tempBox.style.left = startX + 'px';
                tempBox.style.top = startY + 'px';
                tempBox.style.width = '0px';
                tempBox.style.height = '0px';
                interactionLayer.appendChild(tempBox);
            } else {
                // NORMAL MODE: DRAG TO PAN / SCROLL PDF
                if (e.button === 0 && canvasViewport) {
                    isPanning = true;
                    panStartX = e.clientX;
                    panStartY = e.clientY;
                    scrollStartLeft = canvasViewport.scrollLeft;
                    scrollStartTop = canvasViewport.scrollTop;
                    interactionLayer.style.cursor = 'grabbing';
                }
            }
        });
    }

    // Window mousemove handles both Drawing and Panning smoothly without edge-jumping
    window.addEventListener('mousemove', e => {
        if (isSelecting && isDrawingBox && currentArea && tempBox && interactionLayer) {
            e.preventDefault();
            e.stopPropagation();

            const rect = interactionLayer.getBoundingClientRect();
            // Strict clamping inside PDF canvas bounds prevents browser viewport auto-scrolling
            const curX = Math.max(0, Math.min(e.clientX - rect.left, rect.width));
            const curY = Math.max(0, Math.min(e.clientY - rect.top, rect.height));

            currentArea.width = curX - startX;
            currentArea.height = curY - startY;

            tempBox.style.left = (currentArea.width < 0 ? curX : startX) + 'px';
            tempBox.style.top = (currentArea.height < 0 ? curY : startY) + 'px';
            tempBox.style.width = Math.abs(currentArea.width) + 'px';
            tempBox.style.height = Math.abs(currentArea.height) + 'px';
        } else if (isPanning && canvasViewport) {
            const dx = e.clientX - panStartX;
            const dy = e.clientY - panStartY;
            canvasViewport.scrollLeft = scrollStartLeft - dx;
            canvasViewport.scrollTop = scrollStartTop - dy;
        }
    });

    // Window mouseup completes drawing or panning
    window.addEventListener('mouseup', e => {
        if (isPanning) {
            isPanning = false;
            if (interactionLayer) {
                interactionLayer.style.cursor = isSelecting ? 'crosshair' : 'grab';
            }
        }

        if (isSelecting && isDrawingBox) {
            isDrawingBox = false;

            if (currentArea && interactionLayer) {
                const rect = interactionLayer.getBoundingClientRect();
                const curX = Math.max(0, Math.min(e.clientX - rect.left, rect.width));
                const curY = Math.max(0, Math.min(e.clientY - rect.top, rect.height));

                const w = Math.abs(curX - startX);
                const h = Math.abs(curY - startY);
                const x = Math.min(startX, curX);
                const y = Math.min(startY, curY);

                if (w > 15 && h > 15) {
                    signatureAreas.push({
                        page: pageNum,
                        x: x / scale,
                        y: (currentPdfHeight - y - h) / scale,
                        width: w / scale,
                        height: h / scale
                    });
                }
            }

            currentArea = null;
            if (tempBox) tempBox.remove();
            tempBox = null;

            // DRAWING BOX COMPLETE: RESTORE SCROLL IMMEDIATELY!
            setDrawingMode(false);
            updateSignatureList();
            drawSavedAreas();
        }
    });

    function drawSavedAreas() {
        if (!interactionLayer) return;
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
        if (countBadge) countBadge.textContent = `${signatureAreas.length} Boxes`;

        if (list) {
            list.innerHTML = '';
            if (signatureAreas.length === 0) {
                list.innerHTML = 'No signatures drawn yet. Click "Draw Signature Box" on right.';
            } else {
                signatureAreas.forEach((a, i) => {
                    list.innerHTML += `<div style="display:flex; justify-content:space-between; padding:4px 0; border-bottom:1px solid rgba(255,255,255,0.06);"><span>Page ${a.page}</span><span style="color:#38bdf8;">Box #${i+1} (${Math.round(a.width)}x${Math.round(a.height)} pt)</span></div>`;
                });
            }
        }
        const signBtn = document.getElementById('finalSignBtn');
        if (signBtn) signBtn.disabled = signatureAreas.length === 0;
    }

    // Submit Document Signing to Local Server (Port 5000)
    const signForm = document.getElementById('signForm');
    if (signForm) {
        signForm.addEventListener('submit', async function(e) {
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
                const fileBlob = await fetch('<?= str_replace('\\', '/', $_SESSION['pdfPath'] ?? '') ?>').then(r => r.blob());

                formData.append('file', fileBlob, '<?= sanitizeInput($_SESSION['fileName'] ?? 'document.pdf') ?>');
                formData.append('certificate', JSON.stringify({ alias: certVal }));
                formData.append('areas', JSON.stringify(signatureAreas));
                formData.append('password', passVal);
                formData.append('driver_name', driverVal);
                formData.append('reason', reasonVal);
                formData.append('location', locationVal);

                // Pass All Pages Sign option
                const chkAllPages = document.getElementById('chkAllPages');
                if (chkAllPages && chkAllPages.checked) {
                    formData.append('all_pages', 'true');
                }

                // Pass Custom Stamp Logo if selected
                const logoInput = document.getElementById('customLogoInput');
                if (logoInput && logoInput.files && logoInput.files[0]) {
                    formData.append('custom_logo', logoInput.files[0]);
                }

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
    }

    // All Pages Sign Checkbox Handler
    const chkAllPages = document.getElementById('chkAllPages');
    const allPagesNote = document.getElementById('allPagesNote');
    if (chkAllPages && allPagesNote) {
        chkAllPages.addEventListener('change', function() {
            allPagesNote.style.display = this.checked ? 'block' : 'none';
        });
    }

    // Custom Stamp Logo Upload Handler
    const logoInput = document.getElementById('customLogoInput');
    const logoDisplay = document.getElementById('logoFileNameDisplay');
    const logoPreviewBox = document.getElementById('logoPreviewBox');
    const logoPreviewImg = document.getElementById('customLogoPreview');
    const removeLogoBtn = document.getElementById('removeLogoBtn');

    if (logoInput) {
        logoInput.addEventListener('change', function() {
            if (this.files && this.files[0]) {
                const file = this.files[0];
                logoDisplay.textContent = file.name;
                const reader = new FileReader();
                reader.onload = function(e) {
                    logoPreviewImg.src = e.target.result;
                    logoPreviewBox.style.display = 'flex';
                    removeLogoBtn.style.display = 'inline-block';
                };
                reader.readAsDataURL(file);
            }
        });
    }

    if (removeLogoBtn) {
        removeLogoBtn.addEventListener('click', function() {
            if (logoInput) logoInput.value = '';
            logoDisplay.textContent = 'Default Seal';
            logoPreviewBox.style.display = 'none';
            removeLogoBtn.style.display = 'none';
        });
    }

    loadDrivers();
});
</script>
<?php endif; ?>

<!-- ====================================================================
     GLOBAL SYSTEM CHECKS: 3D LIGHTING TRACKER, 4-DAY FREE TRIAL & GITHUB VERSION CHECK
     Checked from: https://github.com/a-b-infotech/signer/blob/main/version.json
     ==================================================================== -->
<script>
// 1. Dynamic 3D Ambient Light Tracker
window.addEventListener('mousemove', e => {
    document.documentElement.style.setProperty('--light-x', e.clientX + 'px');
    document.documentElement.style.setProperty('--light-y', e.clientY + 'px');
});

// 2. 4-Day Free Web Trial Manager
const TRIAL_DURATION_DAYS = 4;
const TRIAL_MS = TRIAL_DURATION_DAYS * 24 * 60 * 60 * 1000;

function getTrialInfo() {
    let startTs = localStorage.getItem('abinfo_web_trial_start');
    if (!startTs) {
        startTs = Date.now().toString();
        localStorage.setItem('abinfo_web_trial_start', startTs);
    }
    const elapsed = Date.now() - parseInt(startTs);
    const remainingMs = Math.max(0, TRIAL_MS - elapsed);
    const remainingDays = Math.ceil(remainingMs / (24 * 60 * 60 * 1000));
    const isExpired = remainingMs <= 0;
    return { isExpired, remainingDays, remainingMs };
}

function updateTrialVisuals(isServerDemo) {
    const trial = getTrialInfo();
    const trialBadge = document.getElementById('trialBadge');
    const trialBadgeText = document.getElementById('trialBadgeText');
    const uploadTrialBanner = document.getElementById('uploadTrialBanner');
    const trialSidebarNotice = document.getElementById('trialSidebarNotice');
    const trialDaysRemainingText = document.getElementById('trialDaysRemainingText');
    const canvasWatermarkBanner = document.getElementById('canvasWatermarkBanner');
    const workspaceLicenseTag = document.getElementById('workspaceLicenseTag');

    if (isServerDemo) {
        if (trial.isExpired) {
            // 4-Day Trial Expired: Show Trial Expired Overlay
            document.getElementById('trial-expired-overlay').style.display = 'flex';
            if (trialBadge) {
                trialBadge.style.display = 'inline-flex';
                trialBadge.className = 'status-pill offline';
                trialBadgeText.textContent = '⏳ Trial Expired';
            }
            const signBtn = document.getElementById('finalSignBtn');
            if (signBtn) signBtn.disabled = true;
        } else {
            // Free Trial Active
            document.getElementById('trial-expired-overlay').style.display = 'none';
            if (trialBadge) {
                trialBadge.style.display = 'inline-flex';
                trialBadge.className = 'status-pill trial';
                trialBadgeText.textContent = `🎁 Free Trial (${trial.remainingDays}d Left)`;
            }
            if (uploadTrialBanner) uploadTrialBanner.style.display = 'block';
            if (trialSidebarNotice) {
                trialSidebarNotice.style.display = 'block';
                if (trialDaysRemainingText) trialDaysRemainingText.textContent = `${trial.remainingDays} day(s) remaining`;
            }
            if (canvasWatermarkBanner) canvasWatermarkBanner.style.display = 'flex';
            if (workspaceLicenseTag) {
                workspaceLicenseTag.textContent = '4-Day Trial (Demo Watermark)';
                workspaceLicenseTag.style.color = '#fbbf24';
            }
        }
    } else {
        // Licensed Active Suite: Hide all trial banners and watermark indicators
        document.getElementById('trial-expired-overlay').style.display = 'none';
        if (trialBadge) trialBadge.style.display = 'none';
        if (uploadTrialBanner) uploadTrialBanner.style.display = 'none';
        if (trialSidebarNotice) trialSidebarNotice.style.display = 'none';
        if (canvasWatermarkBanner) canvasWatermarkBanner.style.display = 'none';
        if (workspaceLicenseTag) {
            workspaceLicenseTag.textContent = 'Active Pro License';
            workspaceLicenseTag.style.color = '#34d399';
        }
    }
}

// 3. SemVer comparison & Live GitHub version.json check
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

let userDismissedOfflineModal = false;

window.openOfflineModal = function() {
    userDismissedOfflineModal = false;
    const modal = document.getElementById('offline-overlay');
    if (modal) modal.style.display = 'flex';
};

window.closeOfflineModal = function() {
    userDismissedOfflineModal = true;
    const modal = document.getElementById('offline-overlay');
    if (modal) modal.style.display = 'none';
};

async function checkBackgroundServer() {
    const pill = document.getElementById('serverStatusPill');
    const pillText = document.getElementById('serverStatusText');
    const licensePill = document.getElementById('licensePill');
    const licenseTierText = document.getElementById('licenseTierText');

    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 2000);
        const res = await fetch('http://127.0.0.1:5000/api/health', { mode: 'cors', signal: controller.signal });
        clearTimeout(timeoutId);
        if (res.ok) {
            document.getElementById('offline-overlay').style.display = 'none';
            const upOff = document.getElementById('uploadOfflineBanner');
            if (upOff) upOff.style.display = 'none';
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
                    det.innerHTML = `Your local software (v${data.version}) is older than the latest release <b>v${latestGithubVersion}</b> on GitHub (<code>https://github.com/a-b-infotech/signer/blob/main/version.json</code>). Please install the updated package below.`;
                }
                document.getElementById('update-overlay').style.display = 'flex';
                return;
            } else {
                document.getElementById('update-overlay').style.display = 'none';
            }

            const isServerDemo = (data.demo === true);
            updateTrialVisuals(isServerDemo);

            if (!isServerDemo) {
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
                    updateTrialVisuals(true);
                } else if (verifyData.status === 'active') {
                    document.getElementById('expired-overlay').style.display = 'none';
                    updateTrialVisuals(false);
                }
            }
        } else {
            throw new Error('Local server offline');
        }
    } catch (e) {
        if (pill) pill.className = 'status-pill offline';
        if (pillText) pillText.textContent = 'Local Server: OFFLINE';
        if (!userDismissedOfflineModal) {
            const offModal = document.getElementById('offline-overlay');
            if (offModal) offModal.style.display = 'flex';
        }
        const upOff = document.getElementById('uploadOfflineBanner');
        if (upOff) upOff.style.display = 'block';
        const updModal = document.getElementById('update-overlay');
        if (updModal) updModal.style.display = 'none';
    }
}

// Immediate execution so offline modal & version check trigger without delay
checkBackgroundServer();
fetchLatestGithubVersion();
setInterval(checkBackgroundServer, 2500);
</script>
</body>
</html>
