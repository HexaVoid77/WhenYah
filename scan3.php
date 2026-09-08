<?php
/**
 * ============================================================
 *  WEBSHELL SCANNER — Web UI Edition
 *  Comprehensive PHP Webshell Detection Scanner
 * ============================================================
 *  Scans directories for known webshell patterns with
 *  severity classification: Critical, High, Medium, Low
 * ============================================================
 */

// ──────────────────────────────────────────────────────────────
//  CONFIGURATION
// ──────────────────────────────────────────────────────────────
$SCANNER_VERSION = '3.0';
$MAX_FILE_SIZE   = 5 * 1024 * 1024; // 5MB max per file
// JS files removed: jQuery/TinyMCE/CodeMirror etc cause massive false positives.
// Malicious JS embedded in PHP webshells is caught when scanning the .php file.
$SCAN_EXTENSIONS = ['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phps', 'pht', 'phar', 'inc'];

// ──────────────────────────────────────────────────────────────
//  DETECTION RULES — learned from 15 real webshell samples
// ──────────────────────────────────────────────────────────────
function getDetectionRules() {
    // Each rule has 'keywords' for fast strpos() pre-filtering.
    // Regex only runs if at least one keyword matches.
    return [

        // ═══════════════════════════════════════════
        //  CRITICAL — Confirmed Webshell Patterns
        // ═══════════════════════════════════════════
        [
            'severity' => 'critical', 'id' => 'C01',
            'name'     => 'eval() with user input',
            'description' => 'Direct eval of user-controlled input — backdoor RCE',
            'keywords' => ['eval', '$_GET', '$_POST', '$_REQUEST', '$_COOKIE'],
            'pattern'  => '/\beval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)\b/i',
        ],
        [
            'severity' => 'critical', 'id' => 'C02',
            'name'     => 'eval() + base64_decode()',
            'description' => 'Eval of base64-decoded payload — classic webshell packer',
            'keywords' => ['eval', 'base64_decode'],
            'pattern'  => '/\beval\s*\(\s*(?:@\s*)?base64_decode\s*\(/i',
        ],
        [
            'severity' => 'critical', 'id' => 'C03',
            'name'     => 'eval() + gzuncompress/gzinflate',
            'description' => 'Eval of decompressed payload — packed webshell',
            'keywords' => ['eval', 'gzuncompress', 'gzinflate'],
            'pattern'  => '/\beval\s*\(\s*(?:@\s*)?(?:base64_decode\s*\(\s*)?(?:gzuncompress|gzinflate)\s*\(/i',
        ],
        [
            'severity' => 'critical', 'id' => 'C04',
            'name'     => 'shell_exec() with user input',
            'description' => 'Direct OS command execution via shell_exec with user data',
            'keywords' => ['shell_exec', '$_GET', '$_POST', '$_REQUEST'],
            'pattern'  => '/\bshell_exec\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i',
        ],
        [
            'severity' => 'critical', 'id' => 'C05',
            'name'     => 'system() with variable',
            'description' => 'OS command execution via system() with variable arg',
            'keywords' => ['system('],
            'pattern'  => '/(?<![a-zA-Z_])\bsystem\s*\(\s*\$/i',
        ],
        [
            'severity' => 'critical', 'id' => 'C06',
            'name'     => 'passthru() call',
            'description' => 'OS command execution via passthru()',
            'keywords' => ['passthru'],
            'pattern'  => '/\bpassthru\s*\(\s*\$/i',
        ],
        [
            'severity' => 'critical', 'id' => 'C07',
            'name'     => 'exec() with user input',
            'description' => 'OS command execution via exec() with variable arg',
            'keywords' => ['exec('],
            // Exclude method calls: ->exec(), ::exec(), .exec() (JS regex)
            'pattern'  => '/(?<![a-zA-Z_.>:])\bexec\s*\(\s*\$/i',
        ],
        [
            'severity' => 'critical', 'id' => 'C10',
            'name'     => 'eval() with remote content',
            'description' => 'Eval of remotely fetched content — remote code loader',
            'keywords' => ['eval', '?>'],
            'pattern'  => '/\beval\s*\(\s*[\'"]?\s*\?>\s*[\'"]?\s*\.\s*\$/i',
        ],
        [
            'severity' => 'critical', 'id' => 'C11',
            'name'     => 'eval() with hex/octal prefix',
            'description' => 'Eval using hex/octal encoded "?>" prefix — webshell loader',
            'keywords' => ['eval', '\\x3'],
            'pattern'  => '/\beval\s*\(\s*["\']\\\\0?[0-7x][0-9a-fx]+/i',
        ],
        [
            'severity' => 'critical', 'id' => 'C13',
            'name'     => 'eval() + base64_decode of user input',
            'description' => 'Eval of base64-decoded user data — backdoor code execution',
            'keywords' => ['eval', 'base64_decode', '$_'],
            'pattern'  => '/\beval\s*\(\s*(?:@\s*)?base64_decode\s*\(\s*\$_(GET|POST|REQUEST)/i',
        ],
        [
            'severity' => 'critical', 'id' => 'C14',
            'name'     => '$GLOBALS hex obfuscation',
            'description' => 'GLOBALS accessed via hex encoding — webshell-exclusive',
            'keywords' => ['\\x47', '\\x4c', 'GLOBALS'],
            'pattern'  => '/\$\{\s*["\']\\\\x47/i',
        ],
        [
            'severity' => 'critical', 'id' => 'C15',
            'name'     => 'Heavy hex string encoding (10+)',
            'description' => 'Excessive hex escape sequences — malicious obfuscation',
            'keywords' => ['\\x'],
            // Threshold 10+ to skip ZIP magic bytes and regex char classes
            'pattern'  => '/(\\\\x[0-9a-fA-F]{2}){10,}/',
        ],
        [
            'severity' => 'critical', 'id' => 'C16',
            'name'     => 'Heavy octal string encoding (10+)',
            'description' => 'Excessive octal escape sequences — malicious obfuscation',
            'keywords' => ['\\1', '\\0', '\\2', '\\3'],
            // Threshold 10+ to skip short legitimate octal sequences
            'pattern'  => '/(\\\\[0-7]{2,3}){10,}/',
        ],
        [
            'severity' => 'critical', 'id' => 'C17',
            'name'     => 'chr() character building (15+)',
            'description' => 'Long string built via chr() — webshell obfuscation',
            'keywords' => ['chr('],
            // Threshold 15+ to skip legitimate accent char definitions (stemmers)
            'pattern'  => '/(?:chr\s*\(\s*\d+\s*\)\s*\.?\s*){15,}/i',
        ],
        [
            // fromCharCode demoted: standard JS function used in jQuery/TinyMCE/CodeMirror
            'severity' => 'low', 'id' => 'C18',
            'name'     => 'String.fromCharCode (JS)',
            'description' => 'Standard JS function — only suspicious in PHP files with embedded JS',
            'keywords' => ['fromCharCode'],
            'pattern'  => '/String\.fromCharCode\s*\(/i',
        ],
        // file_get_contents + eval in same file = webshell remote loader
        [
            'severity' => 'critical', 'id' => 'C19',
            'name'     => 'file_get_contents + eval',
            'description' => 'Remote content fetched and eval\'d — webshell remote code loader',
            'keywords' => ['file_get_contents', 'eval'],
            'pattern'  => '/file_get_contents\s*\(.*eval|eval.*file_get_contents/is',
        ],
        // curl + eval in same file = webshell remote loader
        [
            'severity' => 'critical', 'id' => 'C20',
            'name'     => 'curl_exec + eval',
            'description' => 'cURL fetch and eval — webshell remote payload loader',
            'keywords' => ['curl_exec', 'eval'],
            'pattern'  => '/curl_exec\s*\(.*eval|eval.*curl_exec/is',
        ],

        // ═══════════════════════════════════════════
        //  HIGH — Strong Webshell Indicators
        // ═══════════════════════════════════════════
        [
            'severity' => 'high', 'id' => 'H01',
            'name'     => 'assert() as eval',
            'description' => 'assert() used as code execution vector',
            'keywords' => ['assert'],
            'pattern'  => '/\bassert\s*\(\s*\$/i',
        ],
        [
            'severity' => 'high', 'id' => 'H02',
            'name'     => 'create_function()',
            'description' => 'Dynamic function creation — deprecated code execution',
            'keywords' => ['create_function'],
            'pattern'  => '/\bcreate_function\s*\(/i',
        ],
        [
            'severity' => 'high', 'id' => 'H03',
            'name'     => 'call_user_func() with variable',
            'description' => 'Indirect function call with variable function name',
            'keywords' => ['call_user_func'],
            'pattern'  => '/\bcall_user_func(?:_array)?\s*\(\s*\$/i',
        ],
        [
            'severity' => 'high', 'id' => 'H04',
            'name'     => 'preg_replace with /e modifier',
            'description' => 'Regex with eval modifier — code execution via regex',
            'keywords' => ['preg_replace', '/e'],
            'pattern'  => '/\bpreg_replace\s*\(\s*[\'"].*\/e[\'"]/i',
        ],
        [
            'severity' => 'high', 'id' => 'H06',
            'name'     => 'base64_decode + eval nearby',
            'description' => 'base64_decode used near eval — obfuscated execution',
            'keywords' => ['base64_decode', 'eval'],
            'pattern'  => '/base64_decode\s*\(.*\beval\b/i',
        ],
        [
            'severity' => 'high', 'id' => 'H07',
            'name'     => 'gzinflate/gzuncompress + base64',
            'description' => 'Decompression + decode — webshell unpacker',
            'keywords' => ['gzinflate', 'gzuncompress'],
            'pattern'  => '/\b(?:gzinflate|gzuncompress)\s*\(\s*base64_decode/i',
        ],
        [
            'severity' => 'high', 'id' => 'H08',
            'name'     => 'str_rot13 + eval/exec context',
            'description' => 'ROT13 used near eval/exec — obfuscated execution',
            'keywords' => ['str_rot13', 'eval'],
            'pattern'  => '/str_rot13\s*\(.*eval|eval.*str_rot13/is',
        ],
        [
            'severity' => 'high', 'id' => 'H09',
            'name'     => 'Variable function call with user input',
            'description' => 'Dynamic function call with $_GET/$_POST — indirect RCE',
            'keywords' => ['$_GET', '$_POST', '$_REQUEST'],
            'pattern'  => '/\$[a-zA-Z_]\w*\s*\(\s*\$_(GET|POST|REQUEST)/i',
        ],
        [
            'severity' => 'high', 'id' => 'H12',
            'name'     => 'password_verify backdoor gate',
            'description' => 'Backdoor auth gate using password_verify with hardcoded bcrypt',
            'keywords' => ['password_verify', '$2'],
            'pattern'  => '/password_verify\s*\(\s*\$.*\$2[aby]\$\d+\$/i',
        ],
        [
            'severity' => 'high', 'id' => 'H13',
            'name'     => 'MD5 hash auth gate',
            'description' => 'Backdoor access control via hardcoded MD5 comparison',
            'keywords' => ['md5('],
            'pattern'  => '/md5\s*\(\s*\$.*===?\s*[\'"][a-f0-9]{32}[\'"]/i',
        ],
        [
            'severity' => 'high', 'id' => 'H14',
            'name'     => 'Leet-speak parameter names',
            'description' => 'Disguised parameter names (d1sGu1s3, n0p3, r00t)',
            'keywords' => ['r00t', 'n0p3', 'd1s'],
            'pattern'  => '/[\$_](GET|POST|REQUEST)\s*\[\s*[\'"](?:[a-z]+\d[a-z]*\d|r00t|n0p3|d1s)[^\'"]*[\'"]\s*\]/i',
        ],
        [
            'severity' => 'high', 'id' => 'H15',
            'name'     => 'Caesar cipher function',
            'description' => 'Custom ord/chr shift cipher — webshell URL obfuscation',
            'keywords' => ['chr', 'ord'],
            'pattern'  => '/chr\s*\(\s*ord\s*\(.*[\+\-]\s*\d+\s*\)/i',
        ],
        [
            'severity' => 'high', 'id' => 'H17',
            'name'     => 'btoa/atob data exfiltration',
            'description' => 'Base64 encoding of page URL — data exfiltration to C2',
            'keywords' => ['btoa', 'location'],
            'pattern'  => '/btoa\s*\(\s*(?:location|document|window)/i',
        ],
        [
            'severity' => 'high', 'id' => 'H18',
            'name'     => 'Fake 404 response camouflage',
            'description' => 'Script returns fake 404 to hide from discovery',
            'keywords' => ['http_response_code', '404'],
            'pattern'  => '/http_response_code\s*\(\s*404\s*\)/i',
        ],
        [
            'severity' => 'high', 'id' => 'H19',
            'name'     => 'shell_exec() general',
            'description' => 'shell_exec call — may be legitimate but review needed',
            'keywords' => ['shell_exec'],
            'pattern'  => '/\bshell_exec\s*\(/i',
        ],

        // ═══════════════════════════════════════════
        //  MEDIUM — Suspicious but may be legitimate
        // ═══════════════════════════════════════════
        [
            'severity' => 'medium', 'id' => 'M01',
            'name'     => 'move_uploaded_file()',
            'description' => 'File upload handler — check if it validates file types',
            'keywords' => ['move_uploaded_file'],
            'pattern'  => '/\bmove_uploaded_file\s*\(/i',
        ],
        [
            'severity' => 'medium', 'id' => 'M02',
            'name'     => 'file_put_contents() with variable',
            'description' => 'File write with variable path — potential dropper',
            'keywords' => ['file_put_contents'],
            'pattern'  => '/\bfile_put_contents\s*\(\s*\$/i',
        ],
        [
            'severity' => 'medium', 'id' => 'M03',
            'name'     => 'fwrite() usage',
            'description' => 'File write via fwrite — may create backdoor files',
            'keywords' => ['fwrite'],
            'pattern'  => '/\bfwrite\s*\(\s*\$/i',
        ],
        [
            'severity' => 'medium', 'id' => 'M06',
            'name'     => '$_FILES processing',
            'description' => 'Direct file upload processing via $_FILES',
            'keywords' => ['$_FILES'],
            'pattern'  => '/\$_FILES\s*\[\s*[\'"][^\'"]+[\'"]\s*\]\s*\[\s*[\'"](?:tmp_name|name|type|size)[\'"]/',
        ],
        [
            'severity' => 'medium', 'id' => 'M07',
            'name'     => 'SSL verification disabled',
            'description' => 'SSL cert verification disabled — insecure remote connections',
            'keywords' => ['CURLOPT_SSL_VERIFYPEER', 'verify_peer'],
            'pattern'  => '/CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)|verify_peer\s*[\'"]?\s*=>\s*false/i',
        ],
        [
            'severity' => 'medium', 'id' => 'M08',
            'name'     => 'proc_open() call',
            'description' => 'Process execution via proc_open — review context',
            'keywords' => ['proc_open'],
            'pattern'  => '/\bproc_open\s*\(/i',
        ],
        [
            'severity' => 'medium', 'id' => 'M09',
            'name'     => 'popen() call',
            'description' => 'Process execution via popen — review context',
            'keywords' => ['popen('],
            'pattern'  => '/\bpopen\s*\(\s*\$/i',
        ],

        // ═══════════════════════════════════════════
        //  LOW — Weak indicators (common in CMS)
        // ═══════════════════════════════════════════
        [
            'severity' => 'low', 'id' => 'L01',
            'name'     => 'error_reporting(0)',
            'description' => 'Error reporting suppressed',
            'keywords' => ['error_reporting'],
            'pattern'  => '/error_reporting\s*\(\s*0\s*\)/i',
        ],
        [
            'severity' => 'low', 'id' => 'L02',
            'name'     => '@set_time_limit(0)',
            'description' => 'Execution time limit removed',
            'keywords' => ['set_time_limit'],
            'pattern'  => '/@?\s*set_time_limit\s*\(\s*0\s*\)/i',
        ],
        [
            'severity' => 'low', 'id' => 'L03',
            'name'     => 'display_errors disabled',
            'description' => 'Display errors disabled via ini_set',
            'keywords' => ['display_errors'],
            'pattern'  => '/ini_set\s*\(\s*[\'"]display_errors[\'"]\s*,\s*[\'"]?0[\'"]?\s*\)/i',
        ],
        [
            'severity' => 'low', 'id' => 'L04',
            'name'     => 'eval() general usage',
            'description' => 'eval() call found — common in CMS, review context',
            'keywords' => ['eval('],
            'pattern'  => '/(?<![a-zA-Z_])\beval\s*\(/i',
        ],
    ];
}


// ──────────────────────────────────────────────────────────────
//  SCANNING ENGINE — with fast keyword pre-filter
// ──────────────────────────────────────────────────────────────

/**
 * Build a master keyword list from all rules.
 * Used for a single fast pass to skip clean files entirely.
 */
function buildMasterKeywords($rules) {
    $all = [];
    foreach ($rules as $rule) {
        foreach ($rule['keywords'] as $kw) {
            $all[$kw] = true;
        }
    }
    return array_keys($all);
}

/**
 * Fast check: does this content contain ANY suspicious keyword?
 * Uses strpos() which is 100x faster than preg_match.
 */
function hasAnySuspiciousKeyword($content, $masterKeywords) {
    $lower = strtolower($content);
    foreach ($masterKeywords as $kw) {
        if (strpos($lower, strtolower($kw)) !== false) {
            return true;
        }
    }
    return false;
}

/**
 * Check if a rule's keywords exist in the content.
 * ALL keywords must be present (AND logic) for multi-keyword rules,
 * except we use OR for single-keyword rules.
 */
function ruleKeywordsMatch($content, $keywords) {
    $lower = strtolower($content);
    // For rules with multiple keywords, require at least one match
    foreach ($keywords as $kw) {
        if (strpos($lower, strtolower($kw)) !== false) {
            return true;
        }
    }
    return false;
}

function scanFile($filePath, $rules, $scannerFile, $masterKeywords) {
    $findings = [];
    $realScannerPath = realpath($scannerFile);
    $realFilePath    = realpath($filePath);

    // Self-exclusion
    if ($realScannerPath && $realFilePath && $realScannerPath === $realFilePath) {
        return $findings;
    }

    $fileSize = @filesize($filePath);
    if ($fileSize === false || $fileSize === 0) return $findings;

    global $MAX_FILE_SIZE;
    if ($fileSize > $MAX_FILE_SIZE) return $findings;

    $content = @file_get_contents($filePath);
    if ($content === false) return $findings;

    // ★ FAST PRE-FILTER: skip file if no suspicious keywords at all
    if (!hasAnySuspiciousKeyword($content, $masterKeywords)) {
        return $findings;
    }

    $lines = explode("\n", $content);
    $lineCount = count($lines);
    $matchedRules = [];
    $isSingleLine = ($lineCount <= 5 && strlen($content) > 1000);

    foreach ($rules as $rule) {
        // ★ Per-rule keyword check: skip regex if this rule's keywords aren't present
        if (!ruleKeywordsMatch($content, $rule['keywords'])) {
            continue;
        }

        if ($isSingleLine) {
            // Large single-line file — check full content
            if (@preg_match($rule['pattern'], $content)) {
                if (!isset($matchedRules[$rule['id']])) {
                    $matchedRules[$rule['id']] = true;
                    $lineNum = 1;
                    $snippet = mb_substr($lines[0], 0, 200);
                    foreach ($lines as $idx => $line) {
                        if (@preg_match($rule['pattern'], $line, $m, PREG_OFFSET_CAPTURE)) {
                            $lineNum = $idx + 1;
                            $matchPos = $m[0][1];
                            $start = max(0, $matchPos - 40);
                            $snippet = mb_substr($line, $start, 200);
                            break;
                        }
                    }
                    $findings[] = [
                        'file'        => str_replace('\\', '/', $filePath),
                        'severity'    => $rule['severity'],
                        'rule_id'     => $rule['id'],
                        'rule_name'   => $rule['name'],
                        'description' => $rule['description'],
                        'line'        => $lineNum,
                        'snippet'     => htmlspecialchars($snippet, ENT_QUOTES, 'UTF-8'),
                    ];
                }
            }
        } else {
            // Multi-line file — check line by line, stop at first match per rule
            foreach ($lines as $idx => $line) {
                if (@preg_match($rule['pattern'], $line, $m, PREG_OFFSET_CAPTURE)) {
                    if (!isset($matchedRules[$rule['id']])) {
                        $matchedRules[$rule['id']] = true;
                        $matchPos = $m[0][1];
                        $start = max(0, $matchPos - 40);
                        $snippet = mb_substr($line, $start, 200);

                        $findings[] = [
                            'file'        => str_replace('\\', '/', $filePath),
                            'severity'    => $rule['severity'],
                            'rule_id'     => $rule['id'],
                            'rule_name'   => $rule['name'],
                            'description' => $rule['description'],
                            'line'        => $idx + 1,
                            'snippet'     => htmlspecialchars($snippet, ENT_QUOTES, 'UTF-8'),
                        ];
                    }
                    break; // first match per rule is enough
                }
            }
        }
    }

    return $findings;
}

function streamScanDirectory($dir, $rules, $scannerFile, &$filesScanned, &$counts, &$uniqueFiles, $masterKeywords, $progressInterval = 50) {
    global $SCAN_EXTENSIONS;
    $dir = rtrim($dir, '/\\');

    $items = @scandir($dir);
    if ($items === false) {
        sendStreamLine(['type' => 'error', 'message' => 'Cannot read directory: ' . $dir]);
        return;
    }

    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;

        $fullPath = $dir . DIRECTORY_SEPARATOR . $item;

        if (is_dir($fullPath)) {
            if (in_array($item, ['.git', '.svn', 'node_modules', '.idea', '__pycache__', 'vendor', '.hg'])) continue;
            streamScanDirectory($fullPath, $rules, $scannerFile, $filesScanned, $counts, $uniqueFiles, $masterKeywords, $progressInterval);
        } elseif (is_file($fullPath)) {
            $ext = strtolower(pathinfo($fullPath, PATHINFO_EXTENSION));
            if (in_array($ext, $SCAN_EXTENSIONS) || $ext === '') {
                $filesScanned++;
                $findings = scanFile($fullPath, $rules, $scannerFile, $masterKeywords);

                foreach ($findings as $f) {
                    $counts[$f['severity']]++;
                    $uniqueFiles[$f['file']] = true;
                    sendStreamLine(['type' => 'finding', 'data' => $f]);
                }

                if ($filesScanned % $progressInterval === 0) {
                    sendStreamLine([
                        'type' => 'progress',
                        'filesScanned' => $filesScanned,
                        'counts' => $counts,
                        'currentDir' => str_replace('\\', '/', $dir),
                    ]);
                }
            }
        }
    }
}

function sendStreamLine($data) {
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n";
    if (ob_get_level()) ob_flush();
    flush();
}

// ──────────────────────────────────────────────────────────────
//  AJAX HANDLER — Streaming NDJSON
// ──────────────────────────────────────────────────────────────
// ──────────────────────────────────────────────────────────────
//  AJAX HANDLER — Read File for Code Viewer
// ──────────────────────────────────────────────────────────────
if (isset($_POST['action']) && $_POST['action'] === 'read_file') {
    header('Content-Type: application/json; charset=utf-8');
    $filePath = isset($_POST['file']) ? $_POST['file'] : '';

    if (empty($filePath) || !is_file($filePath)) {
        echo json_encode(['error' => 'File not found: ' . $filePath]);
        exit;
    }
    if (filesize($filePath) > 10 * 1024 * 1024) {
        echo json_encode(['error' => 'File too large (>10MB)']);
        exit;
    }
    $content = @file_get_contents($filePath);
    if ($content === false) {
        echo json_encode(['error' => 'Cannot read file']);
        exit;
    }
    // Ensure UTF-8
    if (!mb_check_encoding($content, 'UTF-8')) {
        $content = mb_convert_encoding($content, 'UTF-8', 'ISO-8859-1');
    }
    echo json_encode(['content' => $content, 'file' => $filePath], JSON_UNESCAPED_UNICODE);
    exit;
}

// ──────────────────────────────────────────────────────────────
//  AJAX HANDLER — Save File from Code Editor
// ──────────────────────────────────────────────────────────────
if (isset($_POST['action']) && $_POST['action'] === 'save_file') {
    header('Content-Type: application/json; charset=utf-8');
    $filePath = isset($_POST['file']) ? $_POST['file'] : '';
    $content  = isset($_POST['content']) ? $_POST['content'] : '';

    if (empty($filePath) || !is_file($filePath)) {
        echo json_encode(['error' => 'File not found']);
        exit;
    }
    $bytes = @file_put_contents($filePath, $content);
    if ($bytes === false) {
        echo json_encode(['error' => 'Failed to write file — check permissions']);
        exit;
    }
    echo json_encode(['success' => true, 'bytes' => $bytes]);
    exit;
}

// ──────────────────────────────────────────────────────────────
//  AJAX HANDLER — Delete File
// ──────────────────────────────────────────────────────────────
if (isset($_POST['action']) && $_POST['action'] === 'delete_file') {
    header('Content-Type: application/json; charset=utf-8');
    $filePath = isset($_POST['file']) ? $_POST['file'] : '';

    if (empty($filePath) || !is_file($filePath)) {
        echo json_encode(['error' => 'File not found']);
        exit;
    }
    // Safety: don't delete self
    if (realpath($filePath) === realpath(__FILE__)) {
        echo json_encode(['error' => 'Cannot delete the scanner itself']);
        exit;
    }
    if (!@unlink($filePath)) {
        echo json_encode(['error' => 'Failed to delete file — check permissions']);
        exit;
    }
    echo json_encode(['success' => true]);
    exit;
}

// ──────────────────────────────────────────────────────────────
//  AJAX HANDLER — Streaming Scan (NDJSON)
// ──────────────────────────────────────────────────────────────
if (isset($_POST['action']) && $_POST['action'] === 'scan') {
    // Prevent PHP from killing the scan on large dirs
    @error_reporting(0);
    @ini_set('display_errors', 0);
    @set_time_limit(0);
    @ini_set('max_execution_time', 0);
    @ini_set('memory_limit', '512M');

    // Disable output buffering for streaming
    while (ob_get_level()) ob_end_clean();

    header('Content-Type: application/x-ndjson; charset=utf-8');
    header('Cache-Control: no-cache');
    header('X-Accel-Buffering: no'); // nginx

    $scanPath = isset($_POST['path']) ? trim($_POST['path']) : '';

    if (empty($scanPath)) {
        sendStreamLine(['type' => 'error', 'message' => 'Please specify a directory path to scan.']);
        exit;
    }

    $scanPath = str_replace('\\', '/', $scanPath);
    $scanPath = rtrim($scanPath, '/');

    if (!is_dir($scanPath)) {
        sendStreamLine(['type' => 'error', 'message' => 'Directory not found: ' . $scanPath]);
        exit;
    }

    $rules          = getDetectionRules();
    $masterKeywords = buildMasterKeywords($rules);
    $filesScanned   = 0;
    $counts         = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0];
    $uniqueFiles    = [];

    sendStreamLine(['type' => 'start', 'path' => $scanPath]);

    $startTime = microtime(true);
    streamScanDirectory($scanPath, $rules, __FILE__, $filesScanned, $counts, $uniqueFiles, $masterKeywords);
    $elapsed = round(microtime(true) - $startTime, 3);

    // Final summary
    sendStreamLine([
        'type'          => 'done',
        'filesScanned'  => $filesScanned,
        'filesFlagged'  => count($uniqueFiles),
        'totalFindings' => array_sum($counts),
        'counts'        => $counts,
        'elapsed'       => $elapsed,
    ]);
    exit;
}

// ──────────────────────────────────────────────────────────────
//  WEB UI — HTML/CSS/JS
// ──────────────────────────────────────────────────────────────
$defaultPath = dirname(__FILE__);
$defaultPath = str_replace('\\', '/', $defaultPath);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Webshell Scanner — Threat Detection Dashboard</title>
    <meta name="description" content="Advanced PHP webshell detection scanner with severity classification">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        /* ═══════════════════════════════════════════════════════════════
           DESIGN SYSTEM — Dark Theme with Glassmorphism
           ═══════════════════════════════════════════════════════════════ */
        :root {
            --bg-primary: #0a0a1a;
            --bg-secondary: #12122a;
            --bg-card: rgba(20, 20, 50, 0.6);
            --bg-card-hover: rgba(30, 30, 70, 0.7);
            --glass-border: rgba(255, 255, 255, 0.08);
            --glass-highlight: rgba(255, 255, 255, 0.04);

            --text-primary: #e8e8f0;
            --text-secondary: #8888aa;
            --text-muted: #555570;

            --accent-gradient: linear-gradient(135deg, #6366f1, #8b5cf6, #a855f7);
            --accent-blue: #6366f1;
            --accent-purple: #8b5cf6;

            --critical-color: #ef4444;
            --critical-bg: rgba(239, 68, 68, 0.12);
            --critical-border: rgba(239, 68, 68, 0.3);

            --high-color: #f97316;
            --high-bg: rgba(249, 115, 22, 0.12);
            --high-border: rgba(249, 115, 22, 0.3);

            --medium-color: #eab308;
            --medium-bg: rgba(234, 179, 8, 0.12);
            --medium-border: rgba(234, 179, 8, 0.3);

            --low-color: #3b82f6;
            --low-bg: rgba(59, 130, 246, 0.12);
            --low-border: rgba(59, 130, 246, 0.3);

            --success-color: #22c55e;
            --radius-sm: 8px;
            --radius-md: 12px;
            --radius-lg: 16px;
            --radius-xl: 20px;

            --shadow-glow: 0 0 40px rgba(99, 102, 241, 0.15);
            --transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            overflow-x: hidden;
            line-height: 1.6;
        }

        /* Animated background gradient */
        body::before {
            content: '';
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background:
                radial-gradient(ellipse at 20% 20%, rgba(99, 102, 241, 0.08) 0%, transparent 50%),
                radial-gradient(ellipse at 80% 80%, rgba(139, 92, 246, 0.06) 0%, transparent 50%),
                radial-gradient(ellipse at 50% 50%, rgba(168, 85, 247, 0.04) 0%, transparent 70%);
            pointer-events: none;
            z-index: 0;
        }

        /* ─── Layout ─── */
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 24px 32px;
            position: relative;
            z-index: 1;
        }

        /* ─── Header ─── */
        .header {
            text-align: center;
            margin-bottom: 36px;
            padding: 40px 20px 32px;
        }
        .header-icon {
            font-size: 48px;
            margin-bottom: 12px;
            display: inline-block;
            animation: pulse-glow 2s ease-in-out infinite;
        }
        @keyframes pulse-glow {
            0%, 100% { filter: drop-shadow(0 0 8px rgba(99, 102, 241, 0.4)); transform: scale(1); }
            50% { filter: drop-shadow(0 0 20px rgba(139, 92, 246, 0.6)); transform: scale(1.05); }
        }
        .header h1 {
            font-size: 32px;
            font-weight: 800;
            background: var(--accent-gradient);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            letter-spacing: -0.5px;
            margin-bottom: 6px;
        }
        .header-subtitle {
            color: var(--text-secondary);
            font-size: 14px;
            font-weight: 400;
        }
        .version-badge {
            display: inline-block;
            background: var(--accent-gradient);
            color: #fff;
            font-size: 11px;
            font-weight: 600;
            padding: 2px 10px;
            border-radius: 20px;
            margin-left: 8px;
            vertical-align: middle;
        }

        /* ─── Glass Card ─── */
        .glass-card {
            background: var(--bg-card);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border: 1px solid var(--glass-border);
            border-radius: var(--radius-lg);
            padding: 28px;
            margin-bottom: 24px;
            transition: var(--transition);
        }
        .glass-card:hover {
            border-color: rgba(255, 255, 255, 0.12);
            box-shadow: var(--shadow-glow);
        }

        /* ─── Scan Controls ─── */
        .scan-controls {
            display: flex;
            gap: 14px;
            align-items: stretch;
        }
        .scan-input-wrap {
            flex: 1;
            position: relative;
        }
        .scan-input-icon {
            position: absolute;
            left: 16px;
            top: 50%;
            transform: translateY(-50%);
            font-size: 18px;
            color: var(--text-muted);
        }
        .scan-input {
            width: 100%;
            padding: 14px 18px 14px 46px;
            background: rgba(255, 255, 255, 0.04);
            border: 1px solid var(--glass-border);
            border-radius: var(--radius-md);
            color: var(--text-primary);
            font-family: 'JetBrains Mono', monospace;
            font-size: 14px;
            transition: var(--transition);
            outline: none;
        }
        .scan-input:focus {
            border-color: var(--accent-blue);
            box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.15);
            background: rgba(255, 255, 255, 0.06);
        }
        .scan-input::placeholder {
            color: var(--text-muted);
        }

        .btn-scan {
            padding: 14px 36px;
            background: var(--accent-gradient);
            color: #fff;
            border: none;
            border-radius: var(--radius-md);
            font-family: 'Inter', sans-serif;
            font-size: 15px;
            font-weight: 700;
            cursor: pointer;
            transition: var(--transition);
            display: flex;
            align-items: center;
            gap: 10px;
            white-space: nowrap;
            position: relative;
            overflow: hidden;
        }
        .btn-scan::before {
            content: '';
            position: absolute;
            top: 0; left: -100%; width: 100%; height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.15), transparent);
            transition: left 0.5s;
        }
        .btn-scan:hover::before {
            left: 100%;
        }
        .btn-scan:hover {
            transform: translateY(-1px);
            box-shadow: 0 8px 25px rgba(99, 102, 241, 0.3);
        }
        .btn-scan:active { transform: translateY(0); }
        .btn-scan:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none !important;
            box-shadow: none !important;
        }
        .btn-scan:disabled::before { display: none; }

        /* ─── Progress Bar ─── */
        .progress-container {
            display: none;
            margin-top: 20px;
        }
        .progress-container.active { display: block; }
        .progress-bar-track {
            width: 100%;
            height: 6px;
            background: rgba(255, 255, 255, 0.06);
            border-radius: 3px;
            overflow: hidden;
        }
        .progress-bar-fill {
            height: 100%;
            background: var(--accent-gradient);
            border-radius: 3px;
            width: 0%;
            animation: progress-indeterminate 1.8s ease-in-out infinite;
        }
        @keyframes progress-indeterminate {
            0% { width: 0%; margin-left: 0%; }
            50% { width: 60%; margin-left: 20%; }
            100% { width: 0%; margin-left: 100%; }
        }
        .progress-text {
            text-align: center;
            color: var(--text-secondary);
            font-size: 13px;
            margin-top: 10px;
            font-weight: 500;
        }
        .progress-text .spin {
            display: inline-block;
            animation: spin 1s linear infinite;
        }
        @keyframes spin { 100% { transform: rotate(360deg); } }

        /* ─── Stats Grid ─── */
        .stats-grid {
            display: none;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }
        .stats-grid.active { display: grid; }
        .stat-card {
            background: var(--bg-card);
            backdrop-filter: blur(12px);
            border: 1px solid var(--glass-border);
            border-radius: var(--radius-md);
            padding: 20px;
            text-align: center;
            transition: var(--transition);
            position: relative;
            overflow: hidden;
        }
        .stat-card::before {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0;
            height: 3px;
        }
        .stat-card:hover { transform: translateY(-2px); border-color: rgba(255,255,255,0.15); }

        .stat-card.stat-critical::before { background: var(--critical-color); }
        .stat-card.stat-high::before { background: var(--high-color); }
        .stat-card.stat-medium::before { background: var(--medium-color); }
        .stat-card.stat-low::before { background: var(--low-color); }
        .stat-card.stat-total::before { background: var(--accent-gradient); }
        .stat-card.stat-files::before { background: var(--success-color); }

        .stat-number {
            font-size: 36px;
            font-weight: 800;
            line-height: 1;
            margin-bottom: 6px;
        }
        .stat-card.stat-critical .stat-number { color: var(--critical-color); }
        .stat-card.stat-high .stat-number { color: var(--high-color); }
        .stat-card.stat-medium .stat-number { color: var(--medium-color); }
        .stat-card.stat-low .stat-number { color: var(--low-color); }
        .stat-card.stat-total .stat-number { background: var(--accent-gradient); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }
        .stat-card.stat-files .stat-number { color: var(--success-color); }

        .stat-label {
            color: var(--text-secondary);
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        /* ─── Filter Checkboxes ─── */
        .filter-bar {
            display: none;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
            margin-bottom: 20px;
            padding: 16px 20px;
            background: var(--bg-card);
            backdrop-filter: blur(12px);
            border: 1px solid var(--glass-border);
            border-radius: var(--radius-md);
        }
        .filter-bar.active { display: flex; }
        .filter-label {
            color: var(--text-secondary);
            font-size: 13px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            margin-right: 8px;
        }
        .filter-cb {
            display: none;
        }
        .filter-tag {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 8px 16px;
            border-radius: var(--radius-sm);
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            transition: var(--transition);
            user-select: none;
            border: 1.5px solid transparent;
        }
        .filter-tag .tag-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            flex-shrink: 0;
        }
        .filter-tag .tag-count {
            background: rgba(255,255,255,0.1);
            padding: 1px 7px;
            border-radius: 10px;
            font-size: 11px;
            margin-left: 4px;
        }

        /* Critical filter */
        .filter-tag.tag-critical {
            background: var(--critical-bg);
            color: var(--critical-color);
            border-color: var(--critical-border);
        }
        .filter-tag.tag-critical .tag-dot { background: var(--critical-color); }
        .filter-tag.tag-critical.unchecked {
            opacity: 0.35;
            border-color: transparent;
        }

        /* High filter */
        .filter-tag.tag-high {
            background: var(--high-bg);
            color: var(--high-color);
            border-color: var(--high-border);
        }
        .filter-tag.tag-high .tag-dot { background: var(--high-color); }
        .filter-tag.tag-high.unchecked {
            opacity: 0.35;
            border-color: transparent;
        }

        /* Medium filter */
        .filter-tag.tag-medium {
            background: var(--medium-bg);
            color: var(--medium-color);
            border-color: var(--medium-border);
        }
        .filter-tag.tag-medium .tag-dot { background: var(--medium-color); }
        .filter-tag.tag-medium.unchecked {
            opacity: 0.35;
            border-color: transparent;
        }

        /* Low filter */
        .filter-tag.tag-low {
            background: var(--low-bg);
            color: var(--low-color);
            border-color: var(--low-border);
        }
        .filter-tag.tag-low .tag-dot { background: var(--low-color); }
        .filter-tag.tag-low.unchecked {
            opacity: 0.35;
            border-color: transparent;
        }

        .filter-separator {
            width: 1px;
            height: 24px;
            background: var(--glass-border);
            margin: 0 8px;
        }

        .filter-info {
            margin-left: auto;
            color: var(--text-muted);
            font-size: 13px;
        }

        /* ─── Results Table ─── */
        .results-section {
            display: none;
        }
        .results-section.active { display: block; }

        .results-table-wrap {
            overflow-x: auto;
            border-radius: var(--radius-lg);
            border: 1px solid var(--glass-border);
            background: var(--bg-card);
            backdrop-filter: blur(12px);
        }
        .results-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }
        .results-table thead th {
            background: rgba(255, 255, 255, 0.04);
            padding: 14px 16px;
            text-align: left;
            font-weight: 700;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-secondary);
            border-bottom: 1px solid var(--glass-border);
            position: sticky;
            top: 0;
            z-index: 2;
            white-space: nowrap;
        }
        .results-table tbody tr {
            border-bottom: 1px solid rgba(255, 255, 255, 0.03);
            transition: var(--transition);
        }
        .results-table tbody tr:hover {
            background: var(--bg-card-hover);
        }
        .results-table tbody tr:last-child { border-bottom: none; }
        .results-table td {
            padding: 12px 16px;
            vertical-align: top;
        }

        /* Severity badge */
        .severity-badge {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            white-space: nowrap;
        }
        .severity-badge.badge-critical {
            background: var(--critical-bg);
            color: var(--critical-color);
            border: 1px solid var(--critical-border);
        }
        .severity-badge.badge-high {
            background: var(--high-bg);
            color: var(--high-color);
            border: 1px solid var(--high-border);
        }
        .severity-badge.badge-medium {
            background: var(--medium-bg);
            color: var(--medium-color);
            border: 1px solid var(--medium-border);
        }
        .severity-badge.badge-low {
            background: var(--low-bg);
            color: var(--low-color);
            border: 1px solid var(--low-border);
        }

        .file-path {
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            color: var(--accent-purple);
            word-break: break-all;
        }
        .rule-name {
            font-weight: 600;
            color: var(--text-primary);
        }
        .rule-desc {
            font-size: 11px;
            color: var(--text-muted);
            margin-top: 2px;
        }
        .line-num {
            font-family: 'JetBrains Mono', monospace;
            color: var(--text-secondary);
            font-size: 12px;
        }
        .code-snippet {
            font-family: 'JetBrains Mono', monospace;
            font-size: 11px;
            background: rgba(0, 0, 0, 0.3);
            padding: 8px 12px;
            border-radius: var(--radius-sm);
            color: var(--text-secondary);
            max-width: 400px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            cursor: pointer;
            transition: var(--transition);
            border: 1px solid rgba(255,255,255,0.04);
        }
        .code-snippet:hover {
            white-space: pre-wrap;
            word-break: break-all;
            background: rgba(0, 0, 0, 0.5);
            border-color: var(--accent-blue);
            max-width: none;
        }

        /* ─── Empty state / clean ─── */
        .clean-state {
            display: none;
            text-align: center;
            padding: 60px 20px;
        }
        .clean-state.active { display: block; }
        .clean-state-icon { font-size: 64px; margin-bottom: 16px; }
        .clean-state h3 {
            font-size: 22px;
            font-weight: 700;
            color: var(--success-color);
            margin-bottom: 8px;
        }
        .clean-state p { color: var(--text-secondary); }

        /* ─── Error state ─── */
        .error-box {
            display: none;
            background: rgba(239, 68, 68, 0.08);
            border: 1px solid rgba(239, 68, 68, 0.25);
            border-radius: var(--radius-md);
            padding: 16px 20px;
            margin-top: 16px;
            color: var(--critical-color);
            font-size: 14px;
        }
        .error-box.active { display: block; }

        /* ─── Scan Info Bar ─── */
        .scan-info {
            display: none;
            align-items: center;
            justify-content: space-between;
            padding: 12px 20px;
            background: var(--bg-card);
            border: 1px solid var(--glass-border);
            border-radius: var(--radius-md);
            margin-bottom: 20px;
            font-size: 13px;
            color: var(--text-secondary);
            flex-wrap: wrap;
            gap: 12px;
        }
        .scan-info.active { display: flex; }
        .scan-info strong { color: var(--text-primary); }

        /* ─── Scrollbar ─── */
        ::-webkit-scrollbar { width: 8px; height: 8px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb {
            background: rgba(255, 255, 255, 0.1);
            border-radius: 4px;
        }
        ::-webkit-scrollbar-thumb:hover { background: rgba(255, 255, 255, 0.2); }

        /* ─── Responsive ─── */
        @media (max-width: 768px) {
            .container { padding: 16px; }
            .scan-controls { flex-direction: column; }
            .header h1 { font-size: 24px; }
            .stats-grid { grid-template-columns: repeat(2, 1fr); }
            .filter-bar { gap: 6px; }
            .filter-tag { padding: 6px 10px; font-size: 12px; }
            .code-snippet { max-width: 200px; }
        }

        /* ─── Animations ─── */
        @keyframes fadeInUp {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .animate-in {
            animation: fadeInUp 0.5s ease-out forwards;
        }
        .delay-1 { animation-delay: 0.1s; }
        .delay-2 { animation-delay: 0.2s; }
        .delay-3 { animation-delay: 0.3s; }

        /* ═══════════════════════════════════════════════════════════════
           CODE VIEWER / EDITOR MODAL
           ═══════════════════════════════════════════════════════════════ */
        .cv-overlay {
            display: none;
            position: fixed;
            inset: 0;
            z-index: 9999;
            background: rgba(0, 0, 0, 0.75);
            backdrop-filter: blur(8px);
            animation: cvFadeIn 0.2s ease;
        }
        .cv-overlay.active { display: flex; align-items: center; justify-content: center; }
        @keyframes cvFadeIn { from { opacity: 0; } to { opacity: 1; } }

        .cv-modal {
            width: 92vw;
            height: 90vh;
            max-width: 1400px;
            background: #0d0d20;
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: var(--radius-lg);
            display: flex;
            flex-direction: column;
            overflow: hidden;
            box-shadow: 0 25px 80px rgba(0,0,0,0.6), 0 0 60px rgba(99,102,241,0.1);
            animation: cvSlideUp 0.25s ease;
        }
        @keyframes cvSlideUp { from { opacity:0; transform: translateY(30px); } to { opacity:1; transform: translateY(0); } }

        /* Toolbar */
        .cv-toolbar {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 12px 20px;
            background: rgba(255,255,255,0.03);
            border-bottom: 1px solid rgba(255,255,255,0.08);
            flex-shrink: 0;
        }
        .cv-toolbar-title {
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
            color: var(--accent-purple);
            flex: 1;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .cv-toolbar-badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            flex-shrink: 0;
        }
        .cv-toolbar-badge.sev-critical { background: var(--critical-bg); color: var(--critical-color); border: 1px solid var(--critical-border); }
        .cv-toolbar-badge.sev-high     { background: var(--high-bg);     color: var(--high-color);     border: 1px solid var(--high-border); }
        .cv-toolbar-badge.sev-medium   { background: var(--medium-bg);   color: var(--medium-color);   border: 1px solid var(--medium-border); }
        .cv-toolbar-badge.sev-low      { background: var(--low-bg);      color: var(--low-color);      border: 1px solid var(--low-border); }

        .cv-btn {
            padding: 7px 16px;
            border-radius: var(--radius-sm);
            border: 1px solid rgba(255,255,255,0.12);
            background: rgba(255,255,255,0.06);
            color: var(--text-primary);
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            transition: var(--transition);
            display: flex;
            align-items: center;
            gap: 5px;
            flex-shrink: 0;
        }
        .cv-btn:hover { background: rgba(255,255,255,0.12); border-color: rgba(255,255,255,0.2); }
        .cv-btn.cv-btn-save { background: rgba(99,102,241,0.2); border-color: rgba(99,102,241,0.4); color: #a5b4fc; }
        .cv-btn.cv-btn-save:hover { background: rgba(99,102,241,0.35); }
        .cv-btn.cv-btn-danger { background: rgba(239,68,68,0.15); border-color: rgba(239,68,68,0.3); color: #fca5a5; }
        .cv-btn.cv-btn-danger:hover { background: rgba(239,68,68,0.3); }
        .cv-btn.cv-btn-close { background: rgba(255,255,255,0.04); }

        /* Detection info bar */
        .cv-info-bar {
            display: flex;
            align-items: center;
            gap: 16px;
            padding: 8px 20px;
            background: rgba(255,255,255,0.02);
            border-bottom: 1px solid rgba(255,255,255,0.06);
            font-size: 12px;
            color: var(--text-secondary);
            flex-shrink: 0;
        }
        .cv-info-bar strong { color: var(--text-primary); }

        /* Code area */
        .cv-code-wrap {
            flex: 1;
            overflow: auto;
            position: relative;
        }
        .cv-code-table {
            width: 100%;
            border-collapse: collapse;
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
            line-height: 1.65;
        }
        .cv-code-table td {
            padding: 0;
            vertical-align: top;
            white-space: pre;
        }
        .cv-line-num {
            width: 60px;
            min-width: 60px;
            text-align: right;
            padding: 0 12px 0 8px !important;
            color: rgba(255,255,255,0.2);
            user-select: none;
            border-right: 1px solid rgba(255,255,255,0.06);
            background: rgba(0,0,0,0.2);
        }
        .cv-line-code {
            padding: 0 16px !important;
            color: #c5c8d4;
        }
        .cv-line-highlight {
            background: rgba(239, 68, 68, 0.12) !important;
        }
        .cv-line-highlight .cv-line-num {
            color: var(--critical-color) !important;
            font-weight: 700;
            background: rgba(239, 68, 68, 0.08);
        }
        .cv-line-highlight .cv-line-code {
            color: #f0f0f0;
        }

        /* Editor mode */
        .cv-editor-wrap {
            flex: 1;
            display: none;
            position: relative;
        }
        .cv-editor-wrap.active { display: flex; }
        .cv-editor-wrap textarea {
            flex: 1;
            width: 100%;
            background: #090918;
            color: #c5c8d4;
            border: none;
            padding: 12px 16px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
            line-height: 1.65;
            resize: none;
            outline: none;
            tab-size: 4;
        }

        /* Status bar */
        .cv-status {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 6px 20px;
            background: rgba(255,255,255,0.03);
            border-top: 1px solid rgba(255,255,255,0.06);
            font-size: 11px;
            color: var(--text-muted);
            flex-shrink: 0;
        }
        .cv-status-msg { transition: color 0.3s; }
        .cv-status-msg.success { color: var(--success-color); }
        .cv-status-msg.error { color: var(--critical-color); }

        /* View button in table */
        .btn-view-code {
            padding: 4px 12px;
            border-radius: 6px;
            border: 1px solid rgba(99,102,241,0.3);
            background: rgba(99,102,241,0.1);
            color: #a5b4fc;
            font-size: 11px;
            font-weight: 600;
            cursor: pointer;
            transition: var(--transition);
            white-space: nowrap;
        }
        .btn-view-code:hover {
            background: rgba(99,102,241,0.25);
            border-color: rgba(99,102,241,0.5);
        }

        /* Make result rows clickable */
        .results-table tbody tr { cursor: pointer; }
    </style>
</head>
<body>

<div class="container">

    <!-- ═══ HEADER ═══ -->
    <div class="header">
        <div class="header-icon">🛡️</div>
        <h1>Webshell Scanner <span class="version-badge">v<?php echo $SCANNER_VERSION; ?></span></h1>
        <p class="header-subtitle">Advanced threat detection with severity classification</p>
    </div>

    <!-- ═══ SCAN CONTROLS ═══ -->
    <div class="glass-card" id="scan-card">
        <div class="scan-controls">
            <div class="scan-input-wrap">
                <span class="scan-input-icon">📂</span>
                <input type="text"
                       id="scan-path"
                       class="scan-input"
                       placeholder="Enter directory path to scan..."
                       value="<?php echo htmlspecialchars($defaultPath); ?>"
                       autocomplete="off">
            </div>
            <button class="btn-scan" id="btn-scan" onclick="startScan()">
                <span>🔍</span>
                <span id="btn-scan-text">Start Scan</span>
            </button>
        </div>

        <!-- Progress -->
        <div class="progress-container" id="progress">
            <div class="progress-bar-track">
                <div class="progress-bar-fill"></div>
            </div>
            <div class="progress-text">
                <span class="spin">⚙️</span> Scanning files for webshell patterns...
            </div>
        </div>

        <!-- Error -->
        <div class="error-box" id="error-box"></div>
    </div>

    <!-- ═══ STATS GRID ═══ -->
    <div class="stats-grid" id="stats-grid">
        <div class="stat-card stat-critical animate-in">
            <div class="stat-number" id="stat-critical">0</div>
            <div class="stat-label">🔴 Critical</div>
        </div>
        <div class="stat-card stat-high animate-in delay-1">
            <div class="stat-number" id="stat-high">0</div>
            <div class="stat-label">🟠 High</div>
        </div>
        <div class="stat-card stat-medium animate-in delay-2">
            <div class="stat-number" id="stat-medium">0</div>
            <div class="stat-label">🟡 Medium</div>
        </div>
        <div class="stat-card stat-low animate-in delay-3">
            <div class="stat-number" id="stat-low">0</div>
            <div class="stat-label">🔵 Low</div>
        </div>
        <div class="stat-card stat-total animate-in delay-2">
            <div class="stat-number" id="stat-total">0</div>
            <div class="stat-label">📊 Total</div>
        </div>
        <div class="stat-card stat-files animate-in delay-3">
            <div class="stat-number" id="stat-files">0</div>
            <div class="stat-label">📁 Files Scanned</div>
        </div>
    </div>

    <!-- ═══ SCAN INFO ═══ -->
    <div class="scan-info" id="scan-info">
        <span id="scan-info-text"></span>
    </div>

    <!-- ═══ FILTER CHECKBOXES ═══ -->
    <div class="filter-bar" id="filter-bar">
        <span class="filter-label">🔎 Filter by</span>

        <input type="checkbox" class="filter-cb" id="cb-critical" checked onchange="applyFilters()">
        <label for="cb-critical" class="filter-tag tag-critical" id="tag-critical">
            <span class="tag-dot"></span> Critical <span class="tag-count" id="fc-critical">0</span>
        </label>

        <input type="checkbox" class="filter-cb" id="cb-high" checked onchange="applyFilters()">
        <label for="cb-high" class="filter-tag tag-high" id="tag-high">
            <span class="tag-dot"></span> High <span class="tag-count" id="fc-high">0</span>
        </label>

        <input type="checkbox" class="filter-cb" id="cb-medium" checked onchange="applyFilters()">
        <label for="cb-medium" class="filter-tag tag-medium" id="tag-medium">
            <span class="tag-dot"></span> Medium <span class="tag-count" id="fc-medium">0</span>
        </label>

        <input type="checkbox" class="filter-cb" id="cb-low" checked onchange="applyFilters()">
        <label for="cb-low" class="filter-tag tag-low" id="tag-low">
            <span class="tag-dot"></span> Low <span class="tag-count" id="fc-low">0</span>
        </label>

        <div class="filter-separator"></div>
        <span class="filter-info" id="filter-info">Showing all results</span>
    </div>

    <!-- ═══ RESULTS TABLE ═══ -->
    <div class="results-section" id="results-section">
        <div class="results-table-wrap">
            <table class="results-table" id="results-table">
                <thead>
                    <tr>
                        <th style="width:4%">#</th>
                        <th style="width:10%">Severity</th>
                        <th style="width:28%">File</th>
                        <th style="width:18%">Detection Rule</th>
                        <th style="width:4%">Line</th>
                        <th style="width:28%">Code Snippet</th>
                        <th style="width:8%">Action</th>
                    </tr>
                </thead>
                <tbody id="results-body"></tbody>
            </table>
        </div>
    </div>

    <!-- ═══ CLEAN STATE ═══ -->
    <div class="clean-state" id="clean-state">
        <div class="clean-state-icon">✅</div>
        <h3>All Clear!</h3>
        <p>No webshell patterns were detected in the scanned directory.</p>
    </div>

</div>

<!-- ═══ CODE VIEWER MODAL ═══ -->
<div class="cv-overlay" id="cv-overlay" onclick="if(event.target===this)closeCodeViewer()">
    <div class="cv-modal">
        <div class="cv-toolbar">
            <div class="cv-toolbar-title" id="cv-title"></div>
            <span class="cv-toolbar-badge" id="cv-sev-badge"></span>
            <button class="cv-btn cv-btn-save" id="cv-btn-edit" onclick="toggleEditMode()" title="Toggle edit mode">✏️ Edit</button>
            <button class="cv-btn cv-btn-save" id="cv-btn-save" onclick="saveFileFromViewer()" style="display:none" title="Save changes">💾 Save</button>
            <button class="cv-btn cv-btn-danger" id="cv-btn-delete" onclick="deleteFileFromViewer()" title="Delete this file">🗑️ Delete</button>
            <button class="cv-btn cv-btn-close" onclick="closeCodeViewer()" title="Close (Esc)">✕ Close</button>
        </div>
        <div class="cv-info-bar" id="cv-info-bar"></div>
        <div class="cv-code-wrap" id="cv-code-wrap"></div>
        <div class="cv-editor-wrap" id="cv-editor-wrap">
            <textarea id="cv-editor" spellcheck="false"></textarea>
        </div>
        <div class="cv-status">
            <span class="cv-status-msg" id="cv-status-msg">Ready</span>
            <span id="cv-line-count"></span>
        </div>
    </div>
</div>

<script>
// ──────────────────────────────────────────────────────────────
//  JAVASCRIPT — Scan Logic & Filtering
// ──────────────────────────────────────────────────────────────
let allResults = [];
let scanCounts = {critical:0, high:0, medium:0, low:0};
const severityIcons = {
    critical: '🔴',
    high:     '🟠',
    medium:   '🟡',
    low:      '🔵'
};

async function startScan() {
    const path = document.getElementById('scan-path').value.trim();
    if (!path) {
        showError('Please enter a directory path to scan.');
        return;
    }

    // Reset state
    allResults = [];
    scanCounts = {critical:0, high:0, medium:0, low:0};

    const btn = document.getElementById('btn-scan');
    const btnText = document.getElementById('btn-scan-text');
    btn.disabled = true;
    btnText.textContent = 'Scanning...';

    document.getElementById('progress').classList.add('active');
    document.getElementById('error-box').classList.remove('active');
    document.getElementById('stats-grid').classList.add('active');
    document.getElementById('filter-bar').classList.remove('active');
    document.getElementById('results-section').classList.add('active');
    document.getElementById('clean-state').classList.remove('active');
    document.getElementById('scan-info').classList.remove('active');
    document.getElementById('results-body').innerHTML = '';

    // Reset stats to 0
    updateStatsUI(scanCounts, 0, 0);

    const formData = new FormData();
    formData.append('action', 'scan');
    formData.append('path', path);

    try {
        const response = await fetch(window.location.href.split('?')[0], {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            throw new Error('Server returned ' + response.status);
        }

        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';

        while (true) {
            const {done, value} = await reader.read();
            if (done) break;

            buffer += decoder.decode(value, {stream: true});
            const lines = buffer.split('\n');
            buffer = lines.pop(); // keep incomplete last line

            for (const line of lines) {
                if (!line.trim()) continue;
                try {
                    const msg = JSON.parse(line);
                    handleStreamMessage(msg);
                } catch(e) {
                    // skip malformed lines
                }
            }
        }

        // Process remaining buffer
        if (buffer.trim()) {
            try {
                handleStreamMessage(JSON.parse(buffer));
            } catch(e) {}
        }

    } catch(err) {
        showError('Network error: ' + err.message);
    }

    document.getElementById('progress').classList.remove('active');
    btn.disabled = false;
    btnText.textContent = 'Start Scan';

    // Final filter apply
    if (allResults.length > 0) {
        document.getElementById('filter-bar').classList.add('active');
        applyFilters();
    } else {
        document.getElementById('clean-state').classList.add('active');
    }
}

function handleStreamMessage(msg) {
    switch(msg.type) {
        case 'start':
            document.getElementById('progress').querySelector('.progress-text').innerHTML =
                '<span class="spin">⚙️</span> Scanning <strong>' + escHtml(msg.path) + '</strong> ...';
            break;

        case 'finding':
            allResults.push(msg.data);
            scanCounts[msg.data.severity]++;
            appendFindingRow(msg.data, allResults.length);
            updateStatsUI(scanCounts, allResults.length, 0);
            break;

        case 'progress':
            updateStatsUI(msg.counts, allResults.length, msg.filesScanned);
            const dir = msg.currentDir || '';
            const short = dir.split('/').slice(-2).join('/');
            document.getElementById('progress').querySelector('.progress-text').innerHTML =
                `<span class="spin">⚙️</span> ${msg.filesScanned} files scanned... <span style="color:var(--text-muted)">/${short}</span>`;
            break;

        case 'done':
            updateStatsUI(msg.counts, msg.totalFindings, msg.filesScanned);
            const infoEl = document.getElementById('scan-info');
            document.getElementById('scan-info-text').innerHTML =
                `Scanned <strong>${msg.filesScanned}</strong> files in <strong>${msg.elapsed}s</strong> &nbsp;|&nbsp; <strong>${msg.filesFlagged}</strong> suspicious files &nbsp;|&nbsp; <strong>${msg.totalFindings}</strong> total findings`;
            infoEl.classList.add('active');
            break;

        case 'error':
            showError(msg.message);
            break;
    }
}

function updateStatsUI(counts, total, filesScanned) {
    document.getElementById('stat-critical').textContent = counts.critical;
    document.getElementById('stat-high').textContent     = counts.high;
    document.getElementById('stat-medium').textContent   = counts.medium;
    document.getElementById('stat-low').textContent      = counts.low;
    document.getElementById('stat-total').textContent     = total;
    if (filesScanned) document.getElementById('stat-files').textContent = filesScanned;

    document.getElementById('fc-critical').textContent = counts.critical;
    document.getElementById('fc-high').textContent     = counts.high;
    document.getElementById('fc-medium').textContent   = counts.medium;
    document.getElementById('fc-low').textContent      = counts.low;
}

function appendFindingRow(r, idx) {
    const tbody = document.getElementById('results-body');
    const tr = document.createElement('tr');
    tr.className = `result-row severity-${r.severity}`;
    tr.dataset.severity = r.severity;
    const badgeClass = 'badge-' + r.severity;
    tr.innerHTML = `
        <td style="color:var(--text-muted); font-weight:600;">${idx}</td>
        <td>
            <span class="severity-badge ${badgeClass}">
                ${severityIcons[r.severity]} ${r.severity}
            </span>
        </td>
        <td class="file-path" title="${escHtml(r.file)}">${escHtml(r.file)}</td>
        <td>
            <div class="rule-name">[${r.rule_id}] ${escHtml(r.rule_name)}</div>
            <div class="rule-desc">${escHtml(r.description)}</div>
        </td>
        <td class="line-num">${r.line}</td>
        <td><div class="code-snippet" title="Click to expand">${r.snippet}</div></td>
        <td><button class="btn-view-code" onclick="event.stopPropagation();openCodeViewer('${escAttr(r.file)}',${r.line},'${r.severity}','${escAttr(r.rule_id+' '+r.rule_name)}','${escAttr(r.description)}')">👁️ View</button></td>
    `;
    // Click row to open viewer
    tr.addEventListener('click', () => {
        openCodeViewer(r.file, r.line, r.severity, r.rule_id+' '+r.rule_name, r.description);
    });
    tbody.appendChild(tr);

    // Auto-scroll to latest if near bottom
    const wrap = tbody.closest('.results-table-wrap');
    if (wrap && wrap.scrollHeight - wrap.scrollTop - wrap.clientHeight < 200) {
        tr.scrollIntoView({behavior: 'smooth', block: 'end'});
    }
}

function escHtml(s) {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
}

function shortenPath(p) {
    return p; // Show full path
}

function escAttr(s) {
    return s.replace(/\\/g,'\\\\').replace(/'/g,"\\'").replace(/"/g,'&quot;');
}

function applyFilters() {
    const showCritical = document.getElementById('cb-critical').checked;
    const showHigh     = document.getElementById('cb-high').checked;
    const showMedium   = document.getElementById('cb-medium').checked;
    const showLow      = document.getElementById('cb-low').checked;

    document.getElementById('tag-critical').classList.toggle('unchecked', !showCritical);
    document.getElementById('tag-high').classList.toggle('unchecked', !showHigh);
    document.getElementById('tag-medium').classList.toggle('unchecked', !showMedium);
    document.getElementById('tag-low').classList.toggle('unchecked', !showLow);

    const rows = document.querySelectorAll('.result-row');
    let visibleCount = 0;

    rows.forEach(row => {
        const sv = row.dataset.severity;
        let show = (sv==='critical'&&showCritical)||(sv==='high'&&showHigh)||(sv==='medium'&&showMedium)||(sv==='low'&&showLow);
        row.style.display = show ? '' : 'none';
        if (show) visibleCount++;
    });

    let num = 0;
    rows.forEach(row => {
        if (row.style.display !== 'none') {
            num++;
            row.querySelector('td:first-child').textContent = num;
        }
    });

    const filterInfo = document.getElementById('filter-info');
    filterInfo.textContent = visibleCount === allResults.length
        ? 'Showing all results'
        : `Showing ${visibleCount} of ${allResults.length} results`;
}

function showError(msg) {
    const el = document.getElementById('error-box');
    el.innerHTML = '⚠️ ' + msg;
    el.classList.add('active');
}

document.getElementById('scan-path').addEventListener('keydown', function(e) {
    if (e.key === 'Enter') startScan();
});

// ──────────────────────────────────────────────────────────────
//  CODE VIEWER / EDITOR
// ──────────────────────────────────────────────────────────────
let cvCurrentFile = '';
let cvIsEditMode = false;
let cvFileContent = '';

async function openCodeViewer(filePath, lineNum, severity, ruleName, ruleDesc) {
    const overlay = document.getElementById('cv-overlay');
    const title = document.getElementById('cv-title');
    const badge = document.getElementById('cv-sev-badge');
    const infoBar = document.getElementById('cv-info-bar');
    const codeWrap = document.getElementById('cv-code-wrap');
    const statusMsg = document.getElementById('cv-status-msg');
    const lineCount = document.getElementById('cv-line-count');

    // Reset edit mode
    cvIsEditMode = false;
    document.getElementById('cv-editor-wrap').classList.remove('active');
    document.getElementById('cv-code-wrap').style.display = '';
    document.getElementById('cv-btn-save').style.display = 'none';
    document.getElementById('cv-btn-edit').innerHTML = '✏️ Edit';

    // Set header info
    title.textContent = filePath;
    title.title = filePath;
    badge.textContent = severityIcons[severity] + ' ' + severity;
    badge.className = 'cv-toolbar-badge sev-' + severity;
    infoBar.innerHTML = `<strong>Rule:</strong> ${escHtml(ruleName)} &nbsp;|&nbsp; ${escHtml(ruleDesc)} &nbsp;|&nbsp; <strong>Line:</strong> ${lineNum}`;

    // Show modal with loading state
    codeWrap.innerHTML = '<div style="padding:40px;text-align:center;color:var(--text-muted)"><span class="spin">⚙️</span> Loading file...</div>';
    statusMsg.textContent = 'Loading...';
    statusMsg.className = 'cv-status-msg';
    overlay.classList.add('active');
    document.body.style.overflow = 'hidden';
    cvCurrentFile = filePath;

    // Fetch file content
    const formData = new FormData();
    formData.append('action', 'read_file');
    formData.append('file', filePath);

    try {
        const resp = await fetch(window.location.href.split('?')[0], { method: 'POST', body: formData });
        const data = await resp.json();

        if (data.error) {
            codeWrap.innerHTML = `<div style="padding:40px;text-align:center;color:var(--critical-color)">⚠️ ${escHtml(data.error)}</div>`;
            statusMsg.textContent = 'Error loading file';
            statusMsg.className = 'cv-status-msg error';
            return;
        }

        cvFileContent = data.content;
        const lines = data.content.split('\n');
        lineCount.textContent = lines.length + ' lines';

        // Build code table with line numbers
        let html = '<table class="cv-code-table">';
        for (let i = 0; i < lines.length; i++) {
            const ln = i + 1;
            const isHighlight = (ln === lineNum);
            const rowClass = isHighlight ? ' cv-line-highlight' : '';
            const lineText = escHtml(lines[i]);
            html += `<tr class="${rowClass}" id="cv-ln-${ln}">`;
            html += `<td class="cv-line-num">${ln}</td>`;
            html += `<td class="cv-line-code">${lineText || ' '}</td>`;
            html += '</tr>';
        }
        html += '</table>';
        codeWrap.innerHTML = html;

        // Scroll to highlighted line
        requestAnimationFrame(() => {
            const hlRow = document.getElementById('cv-ln-' + lineNum);
            if (hlRow) {
                hlRow.scrollIntoView({ block: 'center' });
            }
        });

        statusMsg.textContent = 'Read-only mode — click Edit to modify';
        statusMsg.className = 'cv-status-msg';

    } catch(err) {
        codeWrap.innerHTML = `<div style="padding:40px;text-align:center;color:var(--critical-color)">⚠️ Network error: ${escHtml(err.message)}</div>`;
        statusMsg.textContent = 'Failed to load';
        statusMsg.className = 'cv-status-msg error';
    }
}

function closeCodeViewer() {
    document.getElementById('cv-overlay').classList.remove('active');
    document.body.style.overflow = '';
    cvIsEditMode = false;
}

function toggleEditMode() {
    const codeWrap = document.getElementById('cv-code-wrap');
    const editorWrap = document.getElementById('cv-editor-wrap');
    const editor = document.getElementById('cv-editor');
    const saveBtn = document.getElementById('cv-btn-save');
    const editBtn = document.getElementById('cv-btn-edit');
    const statusMsg = document.getElementById('cv-status-msg');

    cvIsEditMode = !cvIsEditMode;

    if (cvIsEditMode) {
        // Switch to editor
        codeWrap.style.display = 'none';
        editorWrap.classList.add('active');
        editor.value = cvFileContent;
        saveBtn.style.display = 'flex';
        editBtn.innerHTML = '👁️ View';
        statusMsg.textContent = 'Edit mode — make changes and click Save';
        statusMsg.className = 'cv-status-msg';
    } else {
        // Switch back to viewer
        editorWrap.classList.remove('active');
        codeWrap.style.display = '';
        saveBtn.style.display = 'none';
        editBtn.innerHTML = '✏️ Edit';
        statusMsg.textContent = 'Read-only mode';
        statusMsg.className = 'cv-status-msg';
    }
}

async function saveFileFromViewer() {
    const editor = document.getElementById('cv-editor');
    const statusMsg = document.getElementById('cv-status-msg');
    const content = editor.value;

    statusMsg.textContent = 'Saving...';
    statusMsg.className = 'cv-status-msg';

    const formData = new FormData();
    formData.append('action', 'save_file');
    formData.append('file', cvCurrentFile);
    formData.append('content', content);

    try {
        const resp = await fetch(window.location.href.split('?')[0], { method: 'POST', body: formData });
        const data = await resp.json();

        if (data.error) {
            statusMsg.textContent = '❌ ' + data.error;
            statusMsg.className = 'cv-status-msg error';
        } else {
            cvFileContent = content;
            statusMsg.textContent = '✅ Saved successfully (' + data.bytes + ' bytes)';
            statusMsg.className = 'cv-status-msg success';

            // Update line count
            document.getElementById('cv-line-count').textContent = content.split('\n').length + ' lines';
        }
    } catch(err) {
        statusMsg.textContent = '❌ Save failed: ' + err.message;
        statusMsg.className = 'cv-status-msg error';
    }
}

async function deleteFileFromViewer() {
    if (!confirm('⚠️ DELETE this file permanently?\n\n' + cvCurrentFile + '\n\nThis cannot be undone!')) return;

    const statusMsg = document.getElementById('cv-status-msg');
    statusMsg.textContent = 'Deleting...';

    const formData = new FormData();
    formData.append('action', 'delete_file');
    formData.append('file', cvCurrentFile);

    try {
        const resp = await fetch(window.location.href.split('?')[0], { method: 'POST', body: formData });
        const data = await resp.json();

        if (data.error) {
            statusMsg.textContent = '❌ ' + data.error;
            statusMsg.className = 'cv-status-msg error';
        } else {
            statusMsg.textContent = '🗑️ File deleted';
            statusMsg.className = 'cv-status-msg success';
            document.getElementById('cv-code-wrap').innerHTML = '<div style="padding:40px;text-align:center;color:var(--text-muted)">File has been deleted.</div>';
            document.getElementById('cv-editor-wrap').classList.remove('active');
            document.getElementById('cv-btn-edit').style.display = 'none';
            document.getElementById('cv-btn-save').style.display = 'none';
            document.getElementById('cv-btn-delete').style.display = 'none';
        }
    } catch(err) {
        statusMsg.textContent = '❌ Delete failed: ' + err.message;
        statusMsg.className = 'cv-status-msg error';
    }
}

// Keyboard shortcuts
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        closeCodeViewer();
    }
    // Ctrl+S to save in edit mode
    if (e.ctrlKey && e.key === 's' && cvIsEditMode && document.getElementById('cv-overlay').classList.contains('active')) {
        e.preventDefault();
        saveFileFromViewer();
    }
});

// Tab key in editor
document.getElementById('cv-editor').addEventListener('keydown', function(e) {
    if (e.key === 'Tab') {
        e.preventDefault();
        const start = this.selectionStart;
        const end = this.selectionEnd;
        this.value = this.value.substring(0, start) + '    ' + this.value.substring(end);
        this.selectionStart = this.selectionEnd = start + 4;
    }
});
</script>

</body>
</html>
