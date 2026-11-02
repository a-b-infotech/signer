<?php
// Token.php
// A B INFOTECH - Unified Digital Signer & Web Signing Workspace
// Handles both Web PDF Signing Portal and License API Services
ini_set('display_errors', 0);
error_reporting(0);

// Set Timezone to India for exact expiration and timestamping
date_default_timezone_set('Asia/Kolkata');

// Database connection if present
if (file_exists('db.php')) {
    require_once 'db.php';
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
        header("Location: http://127.0.0.1:5000/api/sync_callback?status=active&id=1&key=ABI-MASTER-PASS&status_val=active&tier=pro&client_email=" . urlencode("sales@a-b-infotech.in") . "&activated_at=" . urlencode(date('Y-m-d H:i:s')) . "&expiredate=never");
        exit;
    }

    if (isset($pdo)) {
        try {
            $stmt = $pdo->prepare("SELECT id, license_key, status, expiredate, license_tier, client_email, activated_at FROM license_keys WHERE license_key = :key LIMIT 1");
            $stmt->bindParam(':key', $license_key);
            $stmt->execute();

            if ($stmt->rowCount() > 0) {
                $row = $stmt->fetch(PDO::FETCH_ASSOC);
                $tier = (!empty($row['license_tier']) && strtolower($row['license_tier']) === 'basic') ? 'basic' : 'pro';
                
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
                exit;
            } else {
                header("Location: http://127.0.0.1:5000/api/sync_callback?status=invalid");
                exit;
            }
        } catch (Exception $e) {
            header("Location: http://127.0.0.1:5000/api/sync_callback?status=error");
            exit;
        }
    } else {
        header("Location: http://127.0.0.1:5000/api/sync_callback?status=active&id=1&key=" . urlencode($license_key) . "&status_val=active&tier=pro&client_email=" . urlencode("sales@a-b-infotech.in") . "&activated_at=" . urlencode(date('Y-m-d H:i:s')) . "&expiredate=never");
        exit;
    }
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
            'id' => 1,
            'license_key' => 'ABI-MASTER-PASS',
            'status_val' => 'active',
            'tier' => 'pro',
            'license_tier' => 'pro',
            'client_email' => 'sales@a-b-infotech.in',
            'activated_at' => date('Y-m-d H:i:s'),
            'expiredate' => 'never'
        ]);
        exit;
    }

    if (isset($pdo)) {
        try {
            $stmt = $pdo->prepare("SELECT id, license_key, status, expiredate, license_tier, client_email, activated_at FROM license_keys WHERE license_key = :key LIMIT 1");
            $stmt->bindParam(':key', $key);
            $stmt->execute();

            if ($stmt->rowCount() > 0) {
                $row = $stmt->fetch(PDO::FETCH_ASSOC);
                $tier = (!empty($row['license_tier']) && strtolower($row['license_tier']) === 'basic') ? 'basic' : 'pro';
                
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

                $is_expired = (!empty($row['expiredate']) && $row['expiredate'] !== 'never' && strtotime($row['expiredate']) < time());
                $final_status = $is_expired ? 'expired' : $row['status'];

                echo json_encode([
                    'status' => $final_status,
                    'id' => (int)$row['id'],
                    'license_key' => $row['license_key'],
                    'status_val' => $row['status'],
                    'tier' => $tier,
                    'license_tier' => $tier,
                    'client_email' => $row['client_email'] ?? '',
                    'activated_at' => $row['activated_at'] ?? '',
                    'expiredate' => !empty($row['expiredate']) ? $row['expiredate'] : 'never'
                ]);
            } else {
                echo json_encode(['status' => 'invalid', 'message' => 'License key not found!']);
            }
        } catch (Exception $e) {
            echo json_encode(['status' => 'error', 'message' => 'Database Error: ' . $e->getMessage()]);
        }
    } else {
        echo json_encode([
            'status' => 'active',
            'id' => 1,
            'license_key' => $key,
            'status_val' => 'active',
            'tier' => 'pro',
            'license_tier' => 'pro',
            'client_email' => 'sales@a-b-infotech.in',
            'activated_at' => date('Y-m-d H:i:s'),
            'expiredate' => 'never'
        ]);
    }
    exit;
}

// ====================================================================
// 3. HANDLE BROWSER ACTIVATION (When User enters key in Desktop App)
// ====================================================================
if (isset($_REQUEST['key']) && !empty($_REQUEST['key']) && !isset($_GET['app'])) {
    $license_key = trim($_REQUEST['key']);

    if ($license_key === 'ABI-MASTER-PASS') {
        header("Location: http://127.0.0.1:5000/api/activate_callback?status=valid&id=1&key=" . urlencode($license_key) . "&status_val=active&expiredate=never&tier=pro&client_email=" . urlencode("sales@a-b-infotech.in") . "&activated_at=" . urlencode(date('Y-m-d H:i:s')));
        exit;
    }

    if (isset($pdo)) {
        try {
            $stmt = $pdo->prepare("SELECT id, license_key, status, expiredate, license_tier, client_email, activated_at FROM license_keys WHERE license_key = :key LIMIT 1");
            $stmt->bindParam(':key', $license_key);
            $stmt->execute();

            if ($stmt->rowCount() > 0) {
                $row = $stmt->fetch(PDO::FETCH_ASSOC);
                
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

                if ($row['status'] !== 'active') {
                    header("Location: http://127.0.0.1:5000/api/activate_callback?status=invalid&message=" . urlencode("This license key is " . $row['status'] . ". Please contact +91 7016797720 (sales@a-b-infotech.in) to activate."));
                    exit;
                }

                if (!empty($row['expiredate']) && $row['expiredate'] !== 'never' && strtotime($row['expiredate']) < time()) {
                    header("Location: http://127.0.0.1:5000/api/activate_callback?status=invalid&message=" . urlencode("This license key has expired. Please contact +91 7016797720 (sales@a-b-infotech.in) to renew."));
                    exit;
                }

                if (empty($row['activated_at']) || $row['activated_at'] === '0000-00-00 00:00:00') {
                    $upd = $pdo->prepare("UPDATE license_keys SET activated_at = NOW() WHERE id = :id");
                    $upd->execute([':id' => $row['id']]);
                    $row['activated_at'] = date('Y-m-d H:i:s');
                }

                $exp_date = !empty($row['expiredate']) ? $row['expiredate'] : 'never';
                $tier = (!empty($row['license_tier']) && strtolower($row['license_tier']) === 'basic') ? 'basic' : 'pro';
                $client_email = $row['client_email'] ?? '';
                $activated_at = $row['activated_at'] ?? '';
                $id = $row['id'];

                header("Location: http://127.0.0.1:5000/api/activate_callback?status=valid"
                    . "&id=" . urlencode($id)
                    . "&key=" . urlencode($license_key)
                    . "&status_val=" . urlencode($row['status'])
                    . "&expiredate=" . urlencode($exp_date)
                    . "&tier=" . urlencode($tier)
                    . "&client_email=" . urlencode($client_email)
                    . "&activated_at=" . urlencode($activated_at));
                exit;
            } else {
                header("Location: http://127.0.0.1:5000/api/activate_callback?status=invalid&message=" . urlencode("License key not found! Please check your license key or contact +91 7016797720 / sales@a-b-infotech.in."));
                exit;
            }
        } catch (Exception $e) {
            header("Location: http://127.0.0.1:5000/api/activate_callback?status=error&message=" . urlencode("Database Error: " . $e->getMessage()));
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
    <title>A B INFOTECH - Web Digital PDF Signer (USB Hardware Token)</title>
    <!-- Fonts & Icons -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;600;700;800&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <!-- PDF.js CDN -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js"></script>
    <style>
        :root {
            --primary: #1E3A8A;
            --primary-light: #3B82F6;
            --accent: #059669;
            --accent-hover: #047857;
            --bg: #0F172A;
            --panel: #1E293B;
            --panel-card: #27354E;
            --border: #334155;
            --text-main: #F8FAFC;
            --text-sub: #94A3B8;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
        }

        body {
            background-color: var(--bg);
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }

        header {
            background: linear-gradient(135deg, #0F172A 0%, #1E293B 100%);
            border-bottom: 1px solid var(--border);
            padding: 14px 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            position: sticky;
            top: 0;
            z-index: 100;
        }

        .brand-box {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .brand-logo {
            width: 36px;
            height: 36px;
            border-radius: 8px;
            background: linear-gradient(135deg, #1E3A8A, #3B82F6);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.2rem;
            font-weight: 800;
            color: #FFFFFF;
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4);
        }

        .brand-title {
            font-family: 'Outfit', sans-serif;
            font-size: 1.25rem;
            font-weight: 800;
            letter-spacing: 0.5px;
            color: #FFFFFF;
        }

        .brand-sub {
            font-size: 0.75rem;
            color: #38BDF8;
            font-weight: 600;
        }

        .server-status-pill {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 6px 14px;
            border-radius: 9999px;
            font-size: 0.8rem;
            font-weight: 600;
            background: rgba(15, 23, 42, 0.7);
            border: 1px solid var(--border);
            transition: all 0.3s ease;
        }

        .status-dot {
            width: 9px;
            height: 9px;
            border-radius: 50%;
            background-color: #EF4444;
            box-shadow: 0 0 8px #EF4444;
        }

        .status-dot.online {
            background-color: #10B981;
            box-shadow: 0 0 8px #10B981;
        }

        /* Main Workspace Layout */
        main {
            flex: 1;
            display: flex;
            flex-direction: column;
            padding: 20px 24px;
            gap: 20px;
            max-width: 1440px;
            margin: 0 auto;
            width: 100%;
        }

        .app-grid {
            display: grid;
            grid-template-columns: 1fr 380px;
            gap: 24px;
            height: calc(100vh - 120px);
            min-height: 650px;
        }

        @media (max-width: 1024px) {
            .app-grid {
                grid-template-columns: 1fr;
                height: auto;
            }
        }

        /* Left Canvas & Viewer Section */
        .viewer-card {
            background: var(--panel);
            border: 1px solid var(--border);
            border-radius: 16px;
            display: flex;
            flex-direction: column;
            overflow: hidden;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.4);
        }

        .viewer-toolbar {
            background: #182234;
            padding: 10px 16px;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            flex-wrap: wrap;
        }

        .toolbar-group {
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .btn-tool {
            background: var(--panel-card);
            border: 1px solid var(--border);
            color: var(--text-main);
            padding: 7px 14px;
            border-radius: 8px;
            font-size: 0.85rem;
            font-weight: 600;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            transition: all 0.2s ease;
        }

        .btn-tool:hover {
            background: #334155;
            border-color: #64748B;
        }

        .btn-tool.active {
            background: #0284C7;
            border-color: #38BDF8;
            color: #FFFFFF;
            box-shadow: 0 0 12px rgba(2, 132, 199, 0.5);
        }

        .btn-tool:disabled {
            opacity: 0.4;
            cursor: not-allowed;
        }

        .page-badge {
            font-size: 0.85rem;
            color: #94A3B8;
            font-weight: 600;
        }

        /* PDF Canvas Area */
        .canvas-viewport {
            flex: 1;
            background: #334155;
            overflow: auto;
            display: flex;
            justify-content: center;
            align-items: flex-start;
            padding: 24px;
            position: relative;
        }

        #pdfWrapper {
            position: relative;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.6);
            display: none;
            background: #FFFFFF;
        }

        #pdfCanvas {
            display: block;
        }

        #interactionLayer {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            cursor: default;
            user-select: none;
        }

        #interactionLayer.active-layer {
            cursor: crosshair;
        }

        /* Selection Rectangles & Signature Cards */
        .selection-box {
            position: absolute;
            border: 2px dashed #0284C7;
            background: rgba(2, 132, 199, 0.25);
            pointer-events: none;
            z-index: 10;
        }

        .signature-area {
            position: absolute;
            border: 2px solid #059669;
            background: rgba(5, 150, 105, 0.2);
            color: #059669;
            font-weight: 700;
            font-size: 0.8rem;
            display: flex;
            align-items: center;
            justify-content: center;
            text-align: center;
            border-radius: 6px;
            box-shadow: 0 4px 12px rgba(5, 150, 105, 0.3);
            backdrop-filter: blur(2px);
            z-index: 5;
            padding: 4px;
        }

        /* Upload Placeholder */
        .upload-placeholder {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            height: 100%;
            width: 100%;
            padding: 40px;
            text-align: center;
            cursor: pointer;
            border: 2px dashed #475569;
            border-radius: 12px;
            background: rgba(30, 41, 59, 0.5);
            transition: all 0.25s ease;
        }

        .upload-placeholder:hover {
            border-color: #38BDF8;
            background: rgba(30, 41, 59, 0.8);
        }

        .upload-icon {
            font-size: 3.5rem;
            margin-bottom: 12px;
            color: #38BDF8;
        }

        /* Right Control & Token Settings Sidebar */
        .sidebar-card {
            background: var(--panel);
            border: 1px solid var(--border);
            border-radius: 16px;
            display: flex;
            flex-direction: column;
            padding: 20px;
            gap: 18px;
            overflow-y: auto;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.4);
        }

        .sidebar-title {
            font-family: 'Outfit', sans-serif;
            font-size: 1.15rem;
            font-weight: 700;
            color: #FFFFFF;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .form-section {
            display: flex;
            flex-direction: column;
            gap: 6px;
        }

        label {
            font-size: 0.8rem;
            font-weight: 600;
            color: var(--text-sub);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        select, input[type="password"], input[type="text"] {
            background: var(--panel-card);
            border: 1px solid var(--border);
            border-radius: 10px;
            color: #FFFFFF;
            padding: 10px 14px;
            font-size: 0.9rem;
            outline: none;
            width: 100%;
            transition: border-color 0.2s ease;
        }

        select:focus, input:focus {
            border-color: #38BDF8;
            box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.2);
        }

        .areas-list-box {
            background: #182234;
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 10px;
            max-height: 140px;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            gap: 6px;
        }

        .area-item {
            background: var(--panel-card);
            padding: 6px 10px;
            border-radius: 6px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            font-size: 0.8rem;
            font-weight: 600;
            color: #34D399;
        }

        .empty-hint {
            font-size: 0.8rem;
            color: #64748B;
            text-align: center;
            padding: 10px 0;
            font-style: italic;
        }

        /* 3D Primary Action Button */
        .btn-sign {
            background: linear-gradient(135deg, #059669 0%, #047857 100%);
            border: 1px solid #10B981;
            color: #FFFFFF;
            font-family: 'Outfit', sans-serif;
            font-size: 1.05rem;
            font-weight: 700;
            padding: 14px 20px;
            border-radius: 12px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            box-shadow: 0 8px 20px rgba(5, 150, 105, 0.4);
            transition: all 0.25s ease;
            margin-top: auto;
        }

        .btn-sign:hover:not(:disabled) {
            transform: translateY(-2px);
            box-shadow: 0 12px 25px rgba(5, 150, 105, 0.6);
            background: linear-gradient(135deg, #10B981 0%, #059669 100%);
        }

        .btn-sign:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
        }

        /* Offline Alert Banner */
        #offlineBanner {
            display: none;
            background: linear-gradient(135deg, #991B1B 0%, #7F1D1D 100%);
            border: 1px solid #EF4444;
            color: #FEE2E2;
            padding: 12px 18px;
            border-radius: 12px;
            font-size: 0.85rem;
            line-height: 1.4;
            margin-bottom: 12px;
        }

        #offlineBanner strong {
            display: block;
            margin-bottom: 4px;
            font-size: 0.95rem;
        }

        /* Spinner Overlay */
        .spinner-overlay {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100vw;
            height: 100vh;
            background: rgba(15, 23, 42, 0.85);
            backdrop-filter: blur(8px);
            z-index: 999;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            gap: 16px;
        }

        .spinner {
            width: 50px;
            height: 50px;
            border: 4px solid rgba(56, 189, 248, 0.2);
            border-top-color: #38BDF8;
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        .spinner-text {
            font-family: 'Outfit', sans-serif;
            font-size: 1.1rem;
            font-weight: 700;
            color: #FFFFFF;
        }
    </style>
</head>
<body>

<header>
    <div class="brand-box">
        <div class="brand-logo">AB</div>
        <div>
            <div class="brand-title">A B INFOTECH</div>
            <div class="brand-sub">Web Digital PDF Signer (USB Hardware Token)</div>
        </div>
    </div>
    <div class="server-status-pill" id="serverPill">
        <div class="status-dot" id="statusDot"></div>
        <span id="statusText">Checking Local Server...</span>
    </div>
</header>

<main>
    <div id="offlineBanner">
        <strong>⚠️ Local API Server (Port 5000) is Offline</strong>
        To sign PDFs using your USB Hardware Token from the web, please launch the <strong>A B INFOTECH Signer</strong> desktop application on this PC.
    </div>

    <div class="app-grid">
        <!-- Left: PDF Canvas & Interactive Drawing Viewport -->
        <div class="viewer-card">
            <div class="viewer-toolbar">
                <div class="toolbar-group">
                    <label for="pdfFileInput" class="btn-tool" style="cursor:pointer;">
                        📂 Choose PDF
                    </label>
                    <input type="file" id="pdfFileInput" accept="application/pdf" style="display:none;">
                    <button class="btn-tool" id="selectAreaBtn" disabled onclick="toggleAreaSelection()">
                        ✍️ Draw Signature Box
                    </button>
                    <button class="btn-tool" id="clearBoxesBtn" disabled onclick="clearSignatureBoxes()">
                        🗑️ Clear Boxes
                    </button>
                </div>

                <div class="toolbar-group">
                    <button class="btn-tool" id="prevPageBtn" disabled onclick="changePage(-1)">◀ Prev</button>
                    <span class="page-badge" id="pageIndicator">Page 0 / 0</span>
                    <button class="btn-tool" id="nextPageBtn" disabled onclick="changePage(1)">Next ▶</button>
                    <button class="btn-tool" id="zoomOutBtn" disabled onclick="zoom(-0.2)">🔍-</button>
                    <button class="btn-tool" id="zoomInBtn" disabled onclick="zoom(0.2)">🔍+</button>
                </div>
            </div>

            <div class="canvas-viewport" id="viewport">
                <div class="upload-placeholder" id="placeholder" onclick="document.getElementById('pdfFileInput').click()">
                    <div class="upload-icon">📄</div>
                    <div style="font-family:'Outfit',sans-serif; font-size:1.25rem; font-weight:700; margin-bottom:6px;">Upload PDF Document</div>
                    <p style="color:#94A3B8; font-size:0.85rem; max-width:400px;">Click here or drag and drop a PDF file to preview pages and draw digital signature placements.</p>
                </div>

                <div id="pdfWrapper">
                    <canvas id="pdfCanvas"></canvas>
                    <div id="interactionLayer"></div>
                </div>
            </div>
        </div>

        <!-- Right: Token Driver, Certificate & Signing Action -->
        <div class="sidebar-card">
            <div class="sidebar-title">
                <span>🔐</span> Token & Signing Settings
            </div>

            <div class="form-section">
                <label>1. Select USB Token Driver</label>
                <select id="driverDropdownWorkspace" onchange="fetchCertificates()">
                    <option value="">Auto-Detect / Select Driver...</option>
                </select>
            </div>

            <div class="form-section">
                <label>2. Digital Certificate</label>
                <select id="certDropdown" name="certAlias">
                    <option value="">Select Certificate from Token...</option>
                </select>
            </div>

            <div class="form-section">
                <label>3. Token Password / User PIN</label>
                <input type="password" id="tokenPin" name="tokenPassword" placeholder="Enter USB Token PIN..." autocomplete="off">
            </div>

            <div class="form-section">
                <label>4. Placed Signature Boxes</label>
                <div class="areas-list-box" id="signatureList">
                    <div class="empty-hint">No signature boxes drawn yet.<br>Click "Draw Signature Box" to place.</div>
                </div>
            </div>

            <button class="btn-sign" id="finalSignBtn" disabled onclick="executeSigning()">
                ✍️ DIGITALLY SIGN PDF
            </button>
        </div>
    </div>
</main>

<!-- Live Spinner Overlay -->
<div class="spinner-overlay" id="loadingOverlay">
    <div class="spinner"></div>
    <div class="spinner-text" id="spinnerText">Processing...</div>
</div>

<script>
// Local API server configuration
const LOCAL_SERVER = "http://127.0.0.1:5000";
let pdfDoc = null;
let pageNum = 1;
let scale = 1.25;
let currentPdfHeight = 0;
let isSelecting = false;
let startX = 0, startY = 0;
let currentArea = null;
let tempBox = null;
let signatureAreas = [];
let loadedPdfFile = null;

// Initialize PDF.js worker
pdfjsLib.GlobalWorkerOptions.workerSrc = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';

// -------------------------------------------------------------
// 1. Health & Driver Synchronization with Local API Server
// -------------------------------------------------------------
async function checkServerHealth() {
    try {
        const resp = await fetch(`${LOCAL_SERVER}/api/health`, { method: 'GET', signal: AbortSignal.timeout(2000) });
        if (resp.ok) {
            const data = await resp.json();
            document.getElementById('statusDot').className = 'status-dot online';
            document.getElementById('statusText').textContent = `Connected (v${data.version || '2.2.0'} PRO)`;
            document.getElementById('offlineBanner').style.display = 'none';
            if (document.getElementById('driverDropdownWorkspace').options.length <= 1) {
                loadDrivers();
            }
        } else {
            throw new Error();
        }
    } catch (e) {
        document.getElementById('statusDot').className = 'status-dot';
        document.getElementById('statusText').textContent = 'Server Offline (Port 5000)';
        document.getElementById('offlineBanner').style.display = 'block';
    }
}

async function loadDrivers() {
    try {
        const resp = await fetch(`${LOCAL_SERVER}/api/drivers`);
        if (resp.ok) {
            const drivers = await resp.json();
            const dd = document.getElementById('driverDropdownWorkspace');
            dd.innerHTML = '<option value="">Auto-Detect / Select Driver...</option>';
            drivers.forEach(d => {
                const opt = document.createElement('option');
                opt.value = d;
                opt.textContent = d;
                dd.appendChild(opt);
            });
        }
    } catch (e) {
        console.warn("Could not load drivers:", e);
    }
}

async function fetchCertificates() {
    const driverName = document.getElementById('driverDropdownWorkspace').value;
    const certDd = document.getElementById('certDropdown');
    certDd.innerHTML = '<option value="">Reading Token Certificates...</option>';

    try {
        const url = driverName ? `${LOCAL_SERVER}/api/certificates?driver_name=${encodeURIComponent(driverName)}` : `${LOCAL_SERVER}/api/certificates`;
        const resp = await fetch(url);
        if (resp.ok) {
            const certs = await resp.json();
            certDd.innerHTML = '';
            if (certs.length === 0) {
                certDd.innerHTML = '<option value="">No certificates found in token</option>';
            } else {
                certs.forEach(c => {
                    const opt = document.createElement('option');
                    opt.value = c.alias;
                    opt.textContent = `${c.cn} (${c.source})`;
                    certDd.appendChild(opt);
                });
            }
        }
    } catch (e) {
        certDd.innerHTML = '<option value="">Error reading certificates</option>';
    }
}

// -------------------------------------------------------------
// 2. PDF Rendering & Navigation
// -------------------------------------------------------------
document.getElementById('pdfFileInput').addEventListener('change', function(e) {
    const file = e.target.files[0];
    if (file && file.type === "application/pdf") {
        loadedPdfFile = file;
        const reader = new FileReader();
        reader.onload = function() {
            loadPdfData(new Uint8Array(this.result));
        };
        reader.readAsArrayBuffer(file);
    }
});

function loadPdfData(pdfData) {
    pdfjsLib.getDocument({ data: pdfData }).promise.then(doc => {
        pdfDoc = doc;
        pageNum = 1;
        signatureAreas = [];
        document.getElementById('placeholder').style.display = 'none';
        document.getElementById('pdfWrapper').style.display = 'block';
        document.getElementById('selectAreaBtn').disabled = false;
        document.getElementById('clearBoxesBtn').disabled = false;
        document.getElementById('zoomInBtn').disabled = false;
        document.getElementById('zoomOutBtn').disabled = false;
        renderCurrentPage();
    }).catch(err => {
        alert("Failed to load PDF document: " + err.message);
    });
}

function renderCurrentPage() {
    if (!pdfDoc) return;
    pdfDoc.getPage(pageNum).then(page => {
        const viewport = page.getViewport({ scale: scale });
        const canvas = document.getElementById('pdfCanvas');
        const context = canvas.getContext('2d');
        canvas.width = viewport.width;
        canvas.height = viewport.height;
        currentPdfHeight = viewport.height;

        const renderContext = {
            canvasContext: context,
            viewport: viewport
        };

        page.render(renderContext).promise.then(() => {
            drawSavedAreas();
            document.getElementById('pageIndicator').textContent = `Page ${pageNum} / ${pdfDoc.numPages}`;
            document.getElementById('prevPageBtn').disabled = (pageNum <= 1);
            document.getElementById('nextPageBtn').disabled = (pageNum >= pdfDoc.numPages);
        });
    });
}

function changePage(delta) {
    if (!pdfDoc) return;
    const newPage = pageNum + delta;
    if (newPage >= 1 && newPage <= pdfDoc.numPages) {
        pageNum = newPage;
        renderCurrentPage();
    }
}

function zoom(delta) {
    if (!pdfDoc) return;
    scale = Math.max(0.6, Math.min(3.0, scale + delta));
    renderCurrentPage();
}

// -------------------------------------------------------------
// 3. Interactive Signature Box Drawing on Canvas
// -------------------------------------------------------------
const interactionLayer = document.getElementById('interactionLayer');

function toggleAreaSelection() {
    isSelecting = !isSelecting;
    const btn = document.getElementById('selectAreaBtn');
    if (isSelecting) {
        interactionLayer.classList.add('active-layer');
        btn.classList.add('active');
        btn.textContent = '✖ Cancel Drawing';
    } else {
        interactionLayer.classList.remove('active-layer');
        btn.classList.remove('active');
        btn.textContent = '✍️ Draw Signature Box';
        if (tempBox) tempBox.remove();
        tempBox = null;
        currentArea = null;
    }
}

interactionLayer.addEventListener('mousedown', e => {
    if (!isSelecting) return;
    const rect = interactionLayer.getBoundingClientRect();
    startX = e.clientX - rect.left;
    startY = e.clientY - rect.top;
    currentArea = { x: startX, y: startY, width: 0, height: 0 };
    tempBox = document.createElement('div');
    tempBox.className = 'selection-box';
    interactionLayer.appendChild(tempBox);
});

interactionLayer.addEventListener('mousemove', e => {
    if (!isSelecting || !currentArea) return;
    const rect = interactionLayer.getBoundingClientRect();
    currentArea.width = (e.clientX - rect.left) - startX;
    currentArea.height = (e.clientY - rect.top) - startY;

    const x = currentArea.width < 0 ? startX + currentArea.width : startX;
    const y = currentArea.height < 0 ? startY + currentArea.height : startY;
    const w = Math.abs(currentArea.width);
    const h = Math.abs(currentArea.height);

    tempBox.style.left = x + 'px';
    tempBox.style.top = y + 'px';
    tempBox.style.width = w + 'px';
    tempBox.style.height = h + 'px';
});

interactionLayer.addEventListener('mouseup', () => {
    if (!currentArea || Math.abs(currentArea.width) < 15 || Math.abs(currentArea.height) < 15) {
        if (tempBox) tempBox.remove();
        tempBox = null;
        currentArea = null;
        return;
    }

    const x = currentArea.width < 0 ? startX + currentArea.width : startX;
    const y = currentArea.height < 0 ? startY + currentArea.height : startY;
    const w = Math.abs(currentArea.width);
    const h = Math.abs(currentArea.height);

    signatureAreas.push({
        page: pageNum,
        x: x / scale,
        y: (currentPdfHeight - y - h) / scale,
        width: w / scale,
        height: h / scale
    });

    updateSignatureList();
    currentArea = null;
    if (tempBox) tempBox.remove();
    tempBox = null;
    toggleAreaSelection();
    drawSavedAreas();
});

function drawSavedAreas() {
    interactionLayer.querySelectorAll('.signature-area, .selection-box').forEach(el => el.remove());
    signatureAreas.forEach((area, idx) => {
        if (area.page !== pageNum) return;
        const div = document.createElement('div');
        div.className = 'signature-area';
        div.style.left = (area.x * scale) + 'px';
        div.style.top = (currentPdfHeight - (area.y + area.height) * scale) + 'px';
        div.style.width = (area.width * scale) + 'px';
        div.style.height = (area.height * scale) + 'px';
        div.innerHTML = `✓ Digital Signature #${idx + 1}<br><span style="font-size:0.65rem; opacity:0.85;">(Page ${area.page})</span>`;
        interactionLayer.appendChild(div);
    });
}

function updateSignatureList() {
    const list = document.getElementById('signatureList');
    list.innerHTML = '';
    if (signatureAreas.length === 0) {
        list.innerHTML = '<div class="empty-hint">No signature boxes drawn yet.<br>Click "Draw Signature Box" to place.</div>';
    } else {
        signatureAreas.forEach((a, i) => {
            list.innerHTML += `<div class="area-item"><span>Page ${a.page}</span><span>Box #${i + 1} (${Math.round(a.width)}x${Math.round(a.height)} pt)</span></div>`;
        });
    }
    document.getElementById('finalSignBtn').disabled = (signatureAreas.length === 0);
}

function clearSignatureBoxes() {
    signatureAreas = [];
    updateSignatureList();
    drawSavedAreas();
}

// -------------------------------------------------------------
// 4. Submit to Local Server (/api/sign) and Download Signed PDF
// -------------------------------------------------------------
async function executeSigning() {
    if (!loadedPdfFile) {
        alert("Please upload a PDF document first.");
        return;
    }
    if (signatureAreas.length === 0) {
        alert("Please draw at least one signature box on the PDF page.");
        return;
    }
    const pin = document.getElementById('tokenPin').value.trim();
    if (!pin) {
        alert("Please enter your USB Hardware Token PIN / Password.");
        document.getElementById('tokenPin').focus();
        return;
    }

    const certAlias = document.getElementById('certDropdown').value;
    const driverName = document.getElementById('driverDropdownWorkspace').value;

    const overlay = document.getElementById('loadingOverlay');
    const spinnerText = document.getElementById('spinnerText');
    spinnerText.textContent = "Connecting to USB Hardware Token & Signing Document...";
    overlay.style.display = 'flex';

    try {
        const formData = new FormData();
        formData.append('file', loadedPdfFile, loadedPdfFile.name);
        formData.append('certificate', JSON.stringify({ alias: certAlias }));
        formData.append('areas', JSON.stringify(signatureAreas));
        formData.append('password', pin);
        formData.append('driver_name', driverName);

        const response = await fetch(`${LOCAL_SERVER}/api/sign`, {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            const errData = await response.json().catch(() => ({}));
            throw new Error(errData.error || `Signing failed with HTTP code ${response.status}`);
        }

        const blob = await response.blob();
        const downloadUrl = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = downloadUrl;
        const origBase = loadedPdfFile.name.replace(/\.pdf$/i, '');
        a.download = `${origBase}_Signed_${Date.now()}.pdf`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);

        overlay.style.display = 'none';
        alert("✓ Success! The PDF document has been digitally signed using your USB Hardware Token and downloaded to your computer.");
    } catch (err) {
        overlay.style.display = 'none';
        alert("Signing Error: " + err.message);
    }
}

// Check server health on load and every 5 seconds
window.addEventListener('DOMContentLoaded', () => {
    checkServerHealth();
    setInterval(checkServerHealth, 5000);
});
</script>
</body>
</html>
