<?php

error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('max_execution_time', 900);
ini_set('memory_limit', '2048M');

define('SCORE_SAFE_THRESHOLD', 30);      
define('SCORE_SUSPICIOUS_THRESHOLD', 60); 
define('SCORE_MALICIOUS_THRESHOLD', 85);  
define('SCORE_CRITICAL_THRESHOLD', 100);    
define('ENTROPY_CRITICAL', 7.7);
define('ENTROPY_HIGH', 7.3);
define('MAX_FILE_SIZE', 15728640);

if (php_sapi_name() !== 'cli') {
    
    if (isset($_POST['action']) && $_POST['action'] === 'scan') {
        header('Content-Type: application/json');
        try {
            $path = $_POST['path'] ?? '.';
            
            if ($path === '.') {
                $fullPath = getcwd();
            } else {
                $fullPath = realpath($path);
                if (!$fullPath) {
                    $fullPath = $path;
                }
            }
            
            if (!is_dir($fullPath)) {
                throw new Exception('Invalid directory: ' . $path);
            }
            
            $results = scan_directory_multi_ext($fullPath);
            $results = apply_ultra_accurate_filtering($results);
            
            usort($results, function($a,$b){ 
                return $b['final_score'] <=> $a['final_score']; 
            });
            
            echo json_encode([
                'success' => true, 
                'data' => array_values($results),
                'stats' => calculate_statistics($results),
                'scanned_path' => $fullPath
            ]);
        } catch (Exception $e) {
            http_response_code(500);
            echo json_encode(['success' => false, 'error' => $e->getMessage()]);
        }
        exit;
    }
    
    if (isset($_POST['action']) && $_POST['action'] === 'view_file') {
        header('Content-Type: application/json');
        try {
            $filepath = $_POST['filepath'] ?? '';
            
            if (!file_exists($filepath) || !is_file($filepath)) {
                throw new Exception('File not found');
            }
            
            $content = @file_get_contents($filepath);
            if ($content === false) {
                throw new Exception('Cannot read file');
            }
            
            echo json_encode([
                'success' => true,
                'content' => $content,
                'size' => strlen($content),
                'filepath' => $filepath,
                'lines' => substr_count($content, "\n") + 1
            ]);
        } catch (Exception $e) {
            http_response_code(500);
            echo json_encode(['success' => false, 'error' => $e->getMessage()]);
        }
        exit;
    }
    
    if (isset($_POST['action']) && $_POST['action'] === 'save_file') {
        header('Content-Type: application/json');
        try {
            $filepath = $_POST['filepath'] ?? '';
            $content = $_POST['content'] ?? '';
            
            if (!file_exists($filepath)) {
                throw new Exception('File not found');
            }
            
            if (!is_writable($filepath)) {
                throw new Exception('Permission denied');
            }
            
            $backup = $filepath . '.backup.' . time();
            @copy($filepath, $backup);
            
            $result = file_put_contents($filepath, $content);
            
            if ($result === false) {
                throw new Exception('Failed to save file');
            }
            
            echo json_encode([
                'success' => true,
                'message' => 'File saved successfully',
                'backup' => $backup
            ]);
        } catch (Exception $e) {
            http_response_code(500);
            echo json_encode(['success' => false, 'error' => $e->getMessage()]);
        }
        exit;
    }
    
    if (isset($_POST['action']) && $_POST['action'] === 'delete_files') {
        header('Content-Type: application/json');
        try {
            $files = json_decode($_POST['files'] ?? '[]', true);
            
            if (!is_array($files) || empty($files)) {
                throw new Exception('No files provided');
            }
            
            $deleted = 0;
            $errors = [];
            
            foreach ($files as $file) {
                if (!file_exists($file)) {
                    $errors[] = basename($file) . ': not found';
                    continue;
                }
                
                if (!is_writable($file)) {
                    $errors[] = basename($file) . ': permission denied';
                    continue;
                }
                
                if (@unlink($file)) {
                    $deleted++;
                } else {
                    $errors[] = basename($file) . ': delete failed';
                }
            }
            
            echo json_encode([
                'success' => true,
                'deleted' => $deleted,
                'total' => count($files),
                'errors' => $errors
            ]);
        } catch (Exception $e) {
            http_response_code(500);
            echo json_encode(['success' => false, 'error' => $e->getMessage()]);
        }
        exit;
    }

    echo render_dashboard_ui();
    exit;
}

function scan_directory_multi_ext($path) {
    $results = [];
    $count = 0; 
    
    $php_extensions = ['php', 'php7', 'php56', 'php5', 'php4', 'php3', 'phtml', 'phps', 'pht', 'inc', 'suspected', 'txt', 'bak', 'old'];
    
    try {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST,
            RecursiveIteratorIterator::CATCH_GET_CHILD
        );
        
        foreach ($iterator as $fileinfo) {
            if ($fileinfo->isDir()) continue;
            
            $fullpath = $fileinfo->getPathname();
            $filename = $fileinfo->getFilename();
            $ext = strtolower($fileinfo->getExtension());
            $fsize = $fileinfo->getSize();
            
            $has_no_extension = false;
            if ($ext === '' || strpos($filename, '.') === false) {
                $has_no_extension = true;
            }

            if (!in_array($ext, $php_extensions) && !$has_no_extension) continue;
            if ($fsize > MAX_FILE_SIZE) continue;
            if ($fsize === 0) continue;
            
            if ($has_no_extension || in_array($ext, ['txt', 'bak', 'old'])) {
                $peek_content = @file_get_contents($fullpath, false, null, 0, 2048);
                if ($peek_content === false) continue;
                
                if (!preg_match('/<\?(?:php|=|\s)/i', $peek_content)) {
                    continue;
                }
            }
            
            $detection = detect_webshell_ultra_v4($fullpath, $fsize, $has_no_extension ? '(none)' : $ext);
            if ($detection !== null && $detection['raw_score'] > 0) {
                $results[] = $detection;
            }
            
            $count++;
            if ($count > 150000) break;
        }
    } catch (Exception $e) {

    }
    
    return $results;
}

function detect_webshell_ultra_v4($filepath, $filesize, $ext = '') {
    $content = @file_get_contents($filepath);
    if ($content === false) return null;
    
    $score = 0;
    $flags = [];
    $confidence = 'LOW';
    $layer_scores = [
        'layer1' => 0,
        'layer2' => 0, 
        'layer3' => 0,
        'layer4' => 0,
        'critical' => 0,
        'combo' => 0
    ];
    
    $entropy = calculate_file_entropy($content);
    
    $has_layer1 = false;
    $has_layer2 = false;
    $has_layer3 = false;
    $has_layer4 = false;

    if (preg_match('/hexdec\s*\(\s*\$[a-zA-Z0-9_]+\s*\[/i', $content)) {
        $has_layer1 = true;
        $layer_scores['layer1'] += 15;
        $flags[] = 'LAYER1:hexdec_array_access';
    }
    
    $basic_funcs = [
        'eval' => 20,
        'assert' => 18,
        'create_function' => 22,
        'system' => 15,
        'exec' => 15,
        'shell_exec' => 15,
        'passthru' => 15,
        'base64_decode' => 10,
        'gzinflate' => 12,
        'str_rot13' => 10
    ];
    
    foreach ($basic_funcs as $func => $points) {
        if (preg_match('/\b' . preg_quote($func, '/') . '\s*\(/i', $content)) {
            $layer_scores['layer1'] += $points;
            $flags[] = "LAYER1:func_$func";
        }
    }
    
    if (preg_match('/\$\w+\s*=\s*\[\s*(?:\s*["\'][\da-fA-F]{16,}["\'](?:\s*,\s*)?){2,}\s*\]/i', $content)) {
        $has_layer2 = true;
        $layer_scores['layer2'] += 45;
        $flags[] = 'LAYER2:encoded_func_array';
        $confidence = 'MEDIUM';
    }
    
    if (preg_match('/\$\w+\s*=\s*["\'][\da-fA-F]{100,}["\']/i', $content)) {
        $layer_scores['layer2'] += 35;
        $flags[] = 'LAYER2:long_hex_string';
    }
    
    $concat_patterns = [
        '/["\'][a-z_]{1,4}["\']\s*\.\s*["\'][a-z_]{1,4}["\']/i' => 20,
        '/(?:["\'][a-z_]{1,2}["\']\s*\.\s*){3,}/i' => 35,
        '/\$\w+\s*=\s*["\'][a-z_]{2,6}["\']\s*\.\s*["\'][a-z_]{2,6}["\']/i' => 25
    ];
    
    foreach ($concat_patterns as $pattern => $points) {
        if (preg_match_all($pattern, $content, $matches)) {
            $count = count($matches[0]);
            $layer_scores['layer2'] += min($points * $count, $points * 2);
            $flags[] = "LAYER2:string_concat:$count";
        }
    }
    
    if (preg_match('/\$\w+\s*\[\s*\d+\s*\]\s*\(/i', $content)) {
        $has_layer3 = true;
        $layer_scores['layer3'] += 65;
        $flags[] = 'LAYER3:dynamic_array_func_call';
        if ($confidence === 'LOW') $confidence = 'HIGH';
    }
    
    if (preg_match('/\$\{\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*\}/i', $content)) {
        $layer_scores['layer3'] += 40;
        $flags[] = 'LAYER3:variable_variable';
    }
    
    if (preg_match('/call_user_func(_array)?\s*\(/i', $content)) {
        $layer_scores['layer3'] += 45;
        $flags[] = 'LAYER3:call_user_func';
    }
    
    $indirect_patterns = [
        '/\$\w+\s*=\s*["\']system["\']\s*;.*\$\w+\s*\(/is' => 70,
        '/array_map\s*\(\s*["\'](?:system|exec|assert)["\']/i' => 75,
        '/array_filter\s*\([^)]*["\']assert["\']/i' => 70,
        '/array_walk\s*\([^)]*["\'](?:system|exec)["\']/i' => 70
    ];
    
    foreach ($indirect_patterns as $pattern => $points) {
        if (preg_match($pattern, $content)) {
            $layer_scores['layer3'] += $points;
            $flags[] = 'LAYER3:indirect_execution';
        }
    }
    
    if (preg_match('/\$_(POST|GET|REQUEST)\s*\[\s*[\'"]command[\'"]\s*\]/i', $content)) {
        $has_layer4 = true;
        $layer_scores['layer4'] += 100;
        $flags[] = 'LAYER4:command_param_input';
        $confidence = 'CRITICAL';
    }
    
    $cmd_params = ['cmd' => 80, 'exec' => 75, 'shell' => 85, 'system' => 80];
    foreach ($cmd_params as $param => $points) {
        if (preg_match('/\$_(POST|GET|REQUEST)\s*\[\s*[\'"]' . $param . '[\'"]\s*\]/i', $content)) {
            $layer_scores['layer4'] += $points;
            $flags[] = "LAYER4:param_$param";
            if ($confidence !== 'CRITICAL') $confidence = 'HIGH';
        }
    }
    
    if (preg_match('/eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(/i', $content)) {
        $layer_scores['critical'] += 150;
        $flags[] = 'CRITICAL:eval_decoder_combo';
        $confidence = 'CRITICAL';
    }
    
    if (preg_match('/assert\s*\(\s*(base64_decode|gzinflate|str_rot13)\s*\(/i', $content)) {
        $layer_scores['critical'] += 140;
        $flags[] = 'CRITICAL:assert_decoder_combo';
        $confidence = 'CRITICAL';
    }
    
    if (preg_match('/eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i', $content)) {
        $layer_scores['critical'] += 180;
        $flags[] = 'CRITICAL:eval_user_input';
        $confidence = 'CRITICAL';
    }
    
    if (preg_match('/(system|exec|shell_exec|passthru)\s*\(\s*\$_(GET|POST|REQUEST)/i', $content)) {
        $layer_scores['critical'] += 170;
        $flags[] = 'CRITICAL:system_user_input';
        $confidence = 'CRITICAL';
    }
    
    if (preg_match('/preg_replace\s*\([^)]*\/[a-z]*e[a-z]*[\'"]/i', $content)) {
        $layer_scores['critical'] += 160;
        $flags[] = 'CRITICAL:preg_replace_eval';
        $confidence = 'CRITICAL';
    }
    
    $webshell_sigs = [
        'c99shell', 'r57shell', 'wso shell', 'b374k', 'indoxploit',
        'FilesMan', 'WSO ', 'c99 ', 'r57 ', 'AnOnSeC',
        'Megawaty', 'Mini Shell', 'Shell Backdoor', 'Webshell'
    ];
    
    foreach ($webshell_sigs as $sig) {
        if (stripos($content, $sig) !== false) {
            $layer_scores['critical'] += 200;
            $flags[] = "CRITICAL:known_shell:$sig";
            $confidence = 'CRITICAL';
            break;
        }
    }
    
    $active_layers = 0;
    if ($has_layer1) $active_layers++;
    if ($has_layer2) $active_layers++;
    if ($has_layer3) $active_layers++;
    if ($has_layer4) $active_layers++;
    
    if ($has_layer1 && $has_layer2) {
        $layer_scores['combo'] += 30;
        $flags[] = 'COMBO:layer1+2';
    }
    
    if ($has_layer2 && $has_layer3) {
        $layer_scores['combo'] += 50;
        $flags[] = 'COMBO:layer2+3';
        if ($confidence === 'LOW') $confidence = 'HIGH';
    }
    
    if ($has_layer3 && $has_layer4) {
        $layer_scores['combo'] += 70;
        $flags[] = 'COMBO:layer3+4';
        $confidence = 'CRITICAL';
    }
    
    if ($active_layers >= 3) {
        $layer_scores['combo'] += 40;
        $flags[] = 'COMBO:triple_layer';
        if ($confidence !== 'CRITICAL') $confidence = 'HIGH';
    }
    
    if ($active_layers === 4) {
        $layer_scores['combo'] += 60;
        $flags[] = 'COMBO:full_chain';
        $confidence = 'CRITICAL';
    }
    
    if (preg_match('/[\'"][^\'"\n]{3,}[\'"]\s*\^\s*(?:chr\s*\(\s*\d+\s*\)[\s\.]*){3,}/i', $content)) {
        $score += 65;
        $flags[] = 'HIGH:chr_xor_obfuscation';
    }
    
    $append_count = preg_match_all('/\$\w+\s*\.=\s*["\'][A-Za-z0-9+\/=]{2,}["\']/i', $content);
    if ($append_count >= 10) {
        $score += 55;
        $flags[] = "HIGH:base64_append_build:$append_count";
    }
    
    if ($entropy > ENTROPY_CRITICAL) {
        $score += 40;
        $flags[] = 'SUSPICIOUS:entropy_critical:' . round($entropy, 2);
    } elseif ($entropy > ENTROPY_HIGH) {
        $score += 20;
        $flags[] = 'SUSPICIOUS:entropy_high:' . round($entropy, 2);
    }
    
    if ($ext === '(none)') {
        $score += 25;
        $flags[] = 'SUSPICIOUS:no_extension';
    }
    
    $weights = [
        'layer1' => 0.8,   
        'layer2' => 1.0,  
        'layer3' => 1.2,  
        'layer4' => 1.5,  
        'critical' => 2.0,  
        'combo' => 1.0    
    ];
    
    foreach ($layer_scores as $layer => $layer_score) {
        $score += $layer_score * $weights[$layer];
    }
    
    $score = min(255, round($score));
    
    $is_legitimate = false;
    
    if (preg_match_all('/\bnamespace\s+[A-Za-z0-9_\\\\]+\s*;/i', $content) >= 2 &&
        preg_match_all('/\bclass\s+[A-Za-z0-9_]+/i', $content) >= 3) {
        $is_legitimate = true;
    }
    
    if (preg_match_all('/\/\*\*[\s\S]*?\*\//i', $content) >= 5) {
        $is_legitimate = true;
    }
    
    if (preg_match('/ComposerAutoloaderInit|Plugin Name:|Theme Name:|@package\s+WordPress/i', $content)) {
        $is_legitimate = true;
    }
    
    if ($is_legitimate && $score < 100) {
        $score = max(0, $score - 40);
        $flags[] = 'CONTEXT:legitimate_structure';
    }
    
    if ($score >= SCORE_CRITICAL_THRESHOLD) {
        $confidence = 'CRITICAL';
    } elseif ($score >= SCORE_MALICIOUS_THRESHOLD) {
        if ($confidence === 'LOW') $confidence = 'HIGH';
    } elseif ($score >= SCORE_SUSPICIOUS_THRESHOLD) {
        if ($confidence === 'LOW') $confidence = 'MEDIUM';
    }
    
    return [
        'file' => $filepath,
        'raw_score' => $score,
        'layer_scores' => $layer_scores,
        'entropy' => $entropy,
        'flags' => $flags,
        'filesize' => $filesize,
        'confidence' => $confidence,
        'ext' => $ext,
        'content_snippet' => generate_code_snippet($content, 500)
    ];
}

function calculate_file_entropy($data) {
    if (empty($data)) return 0.0;
    $h = count_chars($data, 1);
    $len = strlen($data);
    $entropy = 0.0;
    foreach ($h as $v) {
        $p = $v / $len;
        $entropy -= $p * log($p, 2);
    }
    return $entropy;
}

function generate_code_snippet($content, $len = 500) {
    $content = preg_replace('/\s+/', ' ', $content);
    $content = trim($content);
    if (strlen($content) <= $len) return htmlspecialchars($content);
    return htmlspecialchars(substr($content, 0, $len)) . '...';
}

function apply_ultra_accurate_filtering($results) {
    $whitelist_paths = [
        '/vendor/', '/node_modules/', '/wp-includes/', '/wp-admin/',
        '/cache/', '/tmp/', '/temp/', '/storage/', '/logs/',
        '/.git/', '/tests/', '/test/', '/docs/', '/documentation/',
        '/laravel/', '/symfony/', '/zend/', '/yii/', '/codeigniter/'
    ];
    
    $whitelist_files = [
        'autoload.php', 'autoload_real.php', 'autoload_static.php',
        'wp-config.php', 'wp-settings.php', 'composer.json',
        'index.php', 'config.php', 'bootstrap.php'
    ];
    
    foreach ($results as &$r) {
        $path = $r['file'];
        $score = $r['raw_score'];
        
        foreach ($whitelist_paths as $wl) {
            if (stripos($path, $wl) !== false) {
                $score = max(0, $score - 50);
                $r['whitelisted'] = true;
                $r['flags'][] = 'CONTEXT:whitelisted_path';
                break;
            }
        }
        
        $basename = basename($path);
        foreach ($whitelist_files as $wf) {
            if (stripos($basename, $wf) !== false) {
                $score = max(0, $score - 40);
                $r['whitelisted_file'] = true;
                $r['flags'][] = 'CONTEXT:whitelisted_file';
                break;
            }
        }
        
        $final_score = max(0, min(255, intval(round($score))));
        $r['final_score'] = $final_score;
        
        if ($r['confidence'] !== 'CRITICAL') {
            if ($final_score >= SCORE_CRITICAL_THRESHOLD) {
                $r['confidence'] = 'CRITICAL';
            } elseif ($final_score >= SCORE_MALICIOUS_THRESHOLD) {
                $r['confidence'] = 'HIGH';
            } elseif ($final_score >= SCORE_SUSPICIOUS_THRESHOLD) {
                $r['confidence'] = 'MEDIUM';
            } elseif ($final_score >= SCORE_SAFE_THRESHOLD) {
                $r['confidence'] = 'LOW';
            }
        }
    }
    unset($r);
    
    return $results;
}

function calculate_statistics($results) {
    $stats = [
        'total' => count($results),
        'critical' => 0,
        'high' => 0,
        'suspicious' => 0,
        'safe' => 0,
        'no_extension' => 0
    ];
    
    foreach ($results as $r) {
        if (isset($r['ext']) && $r['ext'] === '(none)') {
            $stats['no_extension']++;
        }
        
        if ($r['confidence'] === 'CRITICAL') {
            $stats['critical']++;
        } elseif ($r['final_score'] >= SCORE_MALICIOUS_THRESHOLD) {
            $stats['high']++;
        } elseif ($r['final_score'] >= SCORE_SAFE_THRESHOLD) {
            $stats['suspicious']++;
        } else {
            $stats['safe']++;
        }
    }
    
    return $stats;
}

function render_dashboard_ui() {
    $home = htmlspecialchars(__DIR__, ENT_QUOTES);
    
    $html = <<<'HTMLDOC'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PEMBURU BAHLIL v.2.4 ENHANCED >>> SEO NAGAEMASBUMI</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Oxygen,Ubuntu,Cantarell,sans-serif;background:#0a0e14;color:#d4d4d4;padding:20px;line-height:1.6}
.container{max-width:1600px;margin:0 auto}
.header{background:linear-gradient(135deg,#1a1f2e 0%,#0f1419 100%);padding:24px;border-radius:12px;margin-bottom:24px;border:1px solid #1e2530}
.header h1{color:#00ff88;font-size:28px;margin-bottom:8px;font-weight:600}
.header p{color:#8b949e;font-size:14px}
.version-badge{background:#00ff88;color:#0a0e14;padding:4px 8px;border-radius:4px;font-size:11px;font-weight:bold;display:inline-block;margin-left:10px}
.scan-panel{background:#13171f;padding:20px;border-radius:10px;margin-bottom:20px;border:1px solid #1e2530}
.breadcrumb{background:#0d1117;padding:12px 16px;border-radius:8px;margin-bottom:16px;display:flex;align-items:center;flex-wrap:wrap;gap:8px;border:1px solid #30363d}
.breadcrumb-item{background:#1e2530;padding:6px 12px;border-radius:5px;cursor:pointer;transition:all 0.2s;font-size:13px;color:#8b949e}
.breadcrumb-item:hover{background:#00ff88;color:#0a0e14}
.breadcrumb-separator{color:#30363d;margin:0 4px}
.home-btn{background:#00ff88;color:#0a0e14;border:none;padding:6px 12px;border-radius:5px;cursor:pointer;font-weight:600;font-size:13px;transition:all 0.2s}
.home-btn:hover{background:#00dd77}
.input-group{display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap}
.input{background:#0d1117;border:1px solid #30363d;padding:12px 16px;border-radius:8px;color:#d4d4d4;font-size:14px;flex:1;min-width:300px}
.input:focus{outline:none;border-color:#00ff88}
.btn{background:#00ff88;color:#0a0e14;padding:12px 24px;border:none;border-radius:8px;cursor:pointer;font-weight:600;font-size:14px;transition:all 0.2s}
.btn:hover{background:#00dd77;transform:translateY(-1px)}
.btn:disabled{opacity:0.5;cursor:not-allowed;transform:none}
.btn-edit{background:#17a2b8;color:#fff;padding:6px 12px;border:none;border-radius:5px;cursor:pointer;font-size:11px;transition:all 0.2s;margin-right:4px}
.btn-edit:hover{background:#138496}
.btn-link{background:#6c757d;color:#fff;padding:6px 12px;border:none;border-radius:5px;cursor:pointer;font-size:11px;text-decoration:none;display:inline-block;transition:all 0.2s;margin-right:4px}
.btn-link:hover{background:#5a6268}
.btn-delete{background:#dc3545;color:#fff;padding:6px 12px;border:none;border-radius:5px;cursor:pointer;font-size:11px;transition:all 0.2s;margin-right:4px}
.btn-delete:hover{background:#c82333}
.btn-view{background:#30363d;color:#d4d4d4;padding:6px 12px;border:none;border-radius:5px;cursor:pointer;font-size:11px;transition:all 0.2s}
.btn-view:hover{background:#3d444d}
.progress-bar{height:4px;background:#1e2530;border-radius:4px;overflow:hidden;margin-top:12px;display:none}
.progress-fill{height:100%;background:linear-gradient(90deg,#00ff88,#00dd77);width:0;transition:width 0.3s ease}
.status{margin-top:12px;padding:12px;background:#0d1117;border-radius:6px;color:#8b949e;font-size:13px;min-height:20px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:16px;margin-bottom:20px}
.stat-card{background:#13171f;padding:20px;border-radius:10px;border:1px solid #1e2530;cursor:pointer;transition:all 0.2s}
.stat-card:hover{background:#1a2030;border-color:#00ff88;transform:translateY(-2px)}
.stat-card.active{border-color:#00ff88;background:#1a2030}
.stat-label{color:#8b949e;font-size:13px;margin-bottom:8px}
.stat-value{color:#00ff88;font-size:32px;font-weight:700;transition:all 0.2s}
.stat-card:hover .stat-value{transform:scale(1.05)}
.stat-value.critical{color:#ff0000}
.stat-value.high{color:#ff4444}
.stat-value.medium{color:#ff8800}
.stat-value.suspicious{color:#ffaa00}
.stat-value.safe{color:#00ff88}
.stat-value.noext{color:#9966ff}
.results-panel{background:#13171f;border-radius:10px;border:1px solid #1e2530;overflow:hidden;display:none}
.results-header{padding:16px 20px;background:#0d1117;border-bottom:1px solid #1e2530;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px}
.results-title{color:#d4d4d4;font-size:16px;font-weight:600}
.bulk-actions{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.select-all-label{display:flex;align-items:center;gap:8px;cursor:pointer;user-select:none;color:#8b949e;font-size:13px}
.select-all-label input[type="checkbox"]{width:18px;height:18px;cursor:pointer}
.btn-danger{background:#dc3545;color:#fff;padding:8px 16px;border:none;border-radius:6px;cursor:pointer;font-size:13px;transition:all 0.2s}
.btn-danger:hover{background:#c82333}
.filter-group{display:flex;gap:8px;flex-wrap:wrap}
.filter-select{background:#13171f;border:1px solid #30363d;padding:8px 12px;border-radius:6px;color:#d4d4d4;font-size:13px}
.results-table{width:100%;border-collapse:collapse}
.results-table thead{background:#0d1117}
.results-table th{padding:12px 16px;text-align:left;color:#8b949e;font-size:13px;font-weight:600;border-bottom:1px solid #1e2530}
.results-table td{padding:12px 16px;border-bottom:1px solid #1e2530;font-size:13px}
.results-table tbody tr{transition:background 0.2s}
.results-table tbody tr:hover{background:#0d1117}
.checkbox-cell{width:40px;text-align:center}
.checkbox-cell input[type="checkbox"]{width:18px;height:18px;cursor:pointer}
.file-path{color:#58a6ff;font-family:monospace;font-size:12px;word-break:break-all;display:block;margin-bottom:8px}
.badge{padding:4px 10px;border-radius:6px;font-size:11px;font-weight:600;text-transform:uppercase}
.badge.critical{background:#ff000030;color:#ff4444;border:1px solid #ff000050}
.badge.high{background:#ff444420;color:#ff6b6b;border:1px solid #ff444440}
.badge.medium{background:#ff880020;color:#ffaa66;border:1px solid #ff880040}
.badge.suspicious{background:#ffaa0020;color:#ffcc66;border:1px solid #ffaa0040}
.badge.safe{background:#00ff8820;color:#00ff88;border:1px solid #00ff8840}
.badge.low{background:#30363d;color:#8b949e;border:1px solid #30363d}
.badge.noext{background:#9966ff20;color:#bb99ff;border:1px solid #9966ff40}
.ext-badge{background:#1e2530;padding:2px 6px;border-radius:3px;font-size:10px;color:#8b949e}
.ext-badge.noext{background:#9966ff30;color:#bb99ff}
.detail-row{background:#0a0e14}
.detail-row td{padding:16px;border-bottom:1px solid #1e2530}
.detail-content{color:#8b949e;font-size:12px;line-height:1.8}
.flag-list{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
.flag{background:#1e2530;padding:4px 8px;border-radius:4px;font-size:11px;color:#8b949e;font-family:monospace}
.flag.critical{background:#ff444420;color:#ff6b6b}
.flag.high{background:#ff660020;color:#ff9966}
.flag.medium{background:#ff880020;color:#ffaa66}
.flag.low{background:#00ff8820;color:#88ffaa}
.snippet{background:#0d1117;padding:12px;border-radius:6px;margin-top:8px;font-family:monospace;font-size:11px;color:#8b949e;white-space:pre-wrap;word-break:break-all;max-height:200px;overflow-y:auto}
.empty-state{padding:60px 20px;text-align:center;color:#8b949e}
.modal{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.85);z-index:1000;align-items:center;justify-content:center;padding:20px}
.modal.active{display:flex}
.modal-content{background:#13171f;border-radius:10px;max-width:95%;max-height:90%;width:1200px;overflow:hidden;display:flex;flex-direction:column;border:1px solid #1e2530;box-shadow:0 20px 60px rgba(0,0,0,0.5)}
.modal-header{padding:16px 20px;background:#0d1117;border-bottom:1px solid #1e2530;display:flex;justify-content:space-between;align-items:center}
.modal-title{color:#00ff88;font-size:16px;font-weight:600;font-family:monospace;word-break:break-all}
.modal-close{background:#ff4444;color:#fff;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;font-weight:600;transition:all 0.2s}
.modal-close:hover{background:#ff6666}
.modal-body{padding:20px;overflow-y:auto;flex:1;background:#0a0e14}
.code-editor{width:100%;min-height:500px;background:#0d1117;padding:16px;border-radius:6px;font-family:'Courier New',Courier,monospace;font-size:13px;color:#d4d4d4;border:1px solid #1e2530;resize:vertical}
.code-viewer{background:#0d1117;padding:16px;border-radius:6px;font-family:'Courier New',Courier,monospace;font-size:13px;color:#d4d4d4;white-space:pre;overflow-x:auto;line-height:1.6;border:1px solid #1e2530}
.code-viewer .line-number{color:#8b949e;margin-right:16px;user-select:none}
.modal-actions{padding:16px 20px;background:#0d1117;border-top:1px solid #1e2530;display:flex;gap:10px;justify-content:flex-end}
.legend{background:#0d1117;padding:12px;border-radius:6px;margin-top:16px;display:flex;gap:16px;flex-wrap:wrap;align-items:center;font-size:12px}
.legend-item{display:flex;align-items:center;gap:6px}
.legend-color{width:12px;height:12px;border-radius:2px}
@media(max-width:768px){.input-group{flex-direction:column}.stats{grid-template-columns:1fr 1fr}.filter-group{width:100%}.filter-select{flex:1}.modal-content{max-width:100%;width:100%}.bulk-actions{width:100%;justify-content:space-between}}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>🔰 PEMBURU BAHLIL >>> SEO NAGAEMASBUMI <<< <span class="version-badge">v2.4 ENHANCED</span></h1>
    <p>Enhanced Multi-Layer Detection with Improved Scoring Algorithm</p>
    <div class="legend">
      <div class="legend-item">
        <div class="legend-color" style="background:#ff0000"></div>
        <span>Critical (100+)</span>
      </div>
      <div class="legend-item">
        <div class="legend-color" style="background:#ff4444"></div>
        <span>High (85-100)</span>
      </div>
      <div class="legend-item">
        <div class="legend-color" style="background:#ff8800"></div>
        <span>Medium (60-85)</span>
      </div>
      <div class="legend-item">
        <div class="legend-color" style="background:#ffaa00"></div>
        <span>Low (30-60)</span>
      </div>
      <div class="legend-item">
        <div class="legend-color" style="background:#00ff88"></div>
        <span>Safe (0-30)</span>
      </div>
      <div class="legend-item">
        <div class="legend-color" style="background:#9966ff"></div>
        <span>No Extension</span>
      </div>
    </div>
  </div>

  <div class="scan-panel">
    <div class="breadcrumb" id="breadcrumb">
      <button type="button" class="home-btn" onclick="goToHome()">🏠 Home</button>
      <span class="breadcrumb-separator">›</span>
      <div id="breadcrumbPath"></div>
    </div>

    <div class="input-group">
      <input class="input" id="scanPath" type="text" placeholder="Enter full path to scan">
      <button class="btn" id="scanBtn">🔍 Start Scan</button>
    </div>
    <div class="progress-bar" id="progressBar">
      <div class="progress-fill" id="progressFill"></div>
    </div>
    <div class="status" id="statusText">Ready to scan. Multi-layer detection with enhanced patterns active.</div>
  </div>

  <div class="stats" id="statsPanel" style="display:none">
    <div class="stat-card" data-filter="ALL" id="statCardTotal">
      <div class="stat-label">Total Files</div>
      <div class="stat-value" id="statTotal">0</div>
    </div>
    <div class="stat-card" data-filter="CRITICAL" id="statCardCritical">
      <div class="stat-label">Critical</div>
      <div class="stat-value critical" id="statCritical">0</div>
    </div>
    <div class="stat-card" data-filter="HIGH" id="statCardHigh">
      <div class="stat-label">High Risk</div>
      <div class="stat-value high" id="statHigh">0</div>
    </div>
    <div class="stat-card" data-filter="SUSPICIOUS" id="statCardSusp">
      <div class="stat-label">Suspicious</div>
      <div class="stat-value suspicious" id="statSusp">0</div>
    </div>
    <div class="stat-card" data-filter="LOW" id="statCardSafe">
      <div class="stat-label">Low/Safe</div>
      <div class="stat-value safe" id="statSafe">0</div>
    </div>
    <div class="stat-card" data-filter="NOEXT" id="statCardNoExt">
      <div class="stat-label">No Extension</div>
      <div class="stat-value noext" id="statNoExt">0</div>
    </div>
  </div>

  <div class="results-panel" id="resultsPanel">
    <div class="results-header">
      <div class="results-title">Scan Results</div>
      
      <div class="bulk-actions">
        <label class="select-all-label">
          <input type="checkbox" id="selectAll" onchange="toggleSelectAll()">
          <span>Select All</span>
        </label>
        <button class="btn-danger" onclick="deleteSelected()">🗑️ Delete Selected</button>
      </div>
      
      <div class="filter-group">
        <select class="filter-select" id="filterConfidence">
          <option value="ALL">All Levels</option>
          <option value="CRITICAL">Critical Only</option>
          <option value="HIGH">High Only</option>
          <option value="MEDIUM">Medium Only</option>
          <option value="LOW">Low Only</option>
          <option value="NOEXT">No Extension</option>
        </select>
        <select class="filter-select" id="filterExt">
          <option value="ALL">All Extensions</option>
          <option value="(none)">No Extension</option>
          <option value="php">PHP</option>
          <option value="phtml">PHTML</option>
          <option value="inc">INC</option>
          <option value="txt">TXT</option>
          <option value="suspected">SUSPECTED</option>
          <option value="bak">BAK</option>
          <option value="old">OLD</option>
        </select>
        <select class="filter-select" id="sortBy">
          <option value="score_desc">Score: High → Low</option>
          <option value="score_asc">Score: Low → High</option>
          <option value="file_asc">File: A → Z</option>
        </select>
      </div>
    </div>
    <table class="results-table">
      <thead>
        <tr>
          <th class="checkbox-cell">☑️</th>
          <th style="width:35%">File Path</th>
          <th>Ext</th>
          <th>Score</th>
          <th>Confidence</th>
          <th>Entropy</th>
          <th>Size</th>
          <th>Layers</th>
        </tr>
      </thead>
      <tbody id="resultsBody"></tbody>
    </table>
    <div class="empty-state" id="emptyState" style="display:none">
      No results match your filter criteria.
    </div>
  </div>
</div>

<div class="modal" id="editModal">
  <div class="modal-content">
    <div class="modal-header">
      <div class="modal-title" id="editModalTitle">Edit File</div>
      <button class="modal-close" onclick="closeEditModal()">✖ Close</button>
    </div>
    <div class="modal-body">
      <textarea class="code-editor" id="codeEditor"></textarea>
    </div>
    <div class="modal-actions">
      <button class="btn" onclick="saveFile()">💾 Save Changes</button>
      <button class="btn-danger" onclick="closeEditModal()">❌ Cancel</button>
    </div>
  </div>
</div>

<div class="modal" id="fileModal">
  <div class="modal-content">
    <div class="modal-header">
      <div class="modal-title" id="modalTitle">File Content</div>
      <button class="modal-close" id="modalClose">✖ Close</button>
    </div>
    <div class="modal-body">
      <div class="code-viewer" id="codeViewer">Loading...</div>
    </div>
  </div>
</div>

<script>
const BASE_DIR = '__HOME_DIR__';
const SCORE_SAFE = 30;
const SCORE_SUSPICIOUS = 60;
const SCORE_MALICIOUS = 85;
const SCORE_CRITICAL = 100;

let allResults = [];
let filteredResults = [];
let currentFilter = 'ALL';
let currentEditFile = '';

const el = id => document.getElementById(id);

window.addEventListener('DOMContentLoaded', function() {
  updateBreadcrumb(BASE_DIR);
  el('scanPath').value = BASE_DIR;
});

function updateBreadcrumb(path) {
  const breadcrumbPath = el('breadcrumbPath');
  breadcrumbPath.innerHTML = '';
  if (!path || path === BASE_DIR) return;
  const parts = path.replace(BASE_DIR, '').split('/').filter(p => p);
  let currentPath = BASE_DIR;
  parts.forEach((part, index) => {
    currentPath += '/' + part;
    const pathToUse = currentPath;
    const item = document.createElement('span');
    item.className = 'breadcrumb-item';
    item.textContent = part;
    item.onclick = function() {
      el('scanPath').value = pathToUse;
      updateBreadcrumb(pathToUse);
    };
    breadcrumbPath.appendChild(item);
    if (index < parts.length - 1) {
      const separator = document.createElement('span');
      separator.className = 'breadcrumb-separator';
      separator.textContent = '›';
      breadcrumbPath.appendChild(separator);
    }
  });
}

function goToHome() {
  el('scanPath').value = BASE_DIR;
  updateBreadcrumb(BASE_DIR);
}

el('scanPath').addEventListener('input', function(e) {
  updateBreadcrumb(e.target.value);
});

function toggleSelectAll() {
  const selectAll = el('selectAll');
  const checkboxes = document.querySelectorAll('.file-checkbox');
  checkboxes.forEach(cb => cb.checked = selectAll.checked);
}

function deleteSelected() {
  const checkboxes = document.querySelectorAll('.file-checkbox:checked');
  if (checkboxes.length === 0) {
    alert('Please select files to delete');
    return;
  }
  if (!confirm(`⚠️ PERMANENTLY delete ${checkboxes.length} file(s)?\n\nThis CANNOT be undone!`)) {
    return;
  }
  const filePaths = Array.from(checkboxes).map(cb => cb.dataset.path);
  performDelete(filePaths);
}

function deleteSingleFile(filepath) {
  if (!confirm(`⚠️ PERMANENTLY delete this file?\n\n${filepath}\n\nThis CANNOT be undone!`)) {
    return;
  }
  performDelete([filepath]);
}

async function performDelete(filePaths) {
  const fd = new FormData();
  fd.append('action', 'delete_files');
  fd.append('files', JSON.stringify(filePaths));
  try {
    const response = await fetch('', { method: 'POST', body: fd });
    const json = await response.json();
    if (json.success) {
      alert(`✅ Deleted ${json.deleted} of ${json.total} file(s)`);
      allResults = allResults.filter(r => !filePaths.includes(r.file));
      applyFilters();
      updateStats(allResults);
      el('selectAll').checked = false;
    } else {
      alert('❌ Error: ' + json.error);
    }
  } catch (error) {
    alert('❌ Error: ' + error.message);
  }
}

async function editFile(filepath) {
  currentEditFile = filepath;
  el('editModalTitle').textContent = 'Loading...';
  el('codeEditor').value = 'Loading...';
  el('editModal').classList.add('active');
  const fd = new FormData();
  fd.append('action', 'view_file');
  fd.append('filepath', filepath);
  try {
    const response = await fetch('', { method: 'POST', body: fd });
    const json = await response.json();
    if (!json.success) throw new Error(json.error);
    el('editModalTitle').textContent = filepath;
    el('codeEditor').value = json.content;
  } catch (error) {
    el('codeEditor').value = 'Error: ' + error.message;
    alert('❌ Error: ' + error.message);
  }
}

async function saveFile() {
  if (!currentEditFile) return;
  const content = el('codeEditor').value;
  if (!confirm('💾 Save changes?')) return;
  const fd = new FormData();
  fd.append('action', 'save_file');
  fd.append('filepath', currentEditFile);
  fd.append('content', content);
  try {
    const response = await fetch('', { method: 'POST', body: fd });
    const json = await response.json();
    if (json.success) {
      alert('✅ ' + json.message);
      closeEditModal();
    } else {
      alert('❌ Error: ' + json.error);
    }
  } catch (error) {
    alert('❌ Error: ' + error.message);
  }
}

function closeEditModal() {
  el('editModal').classList.remove('active');
  currentEditFile = '';
}

function setProgress(percent) {
  el('progressBar').style.display = 'block';
  el('progressFill').style.width = Math.min(100, Math.max(0, percent)) + '%';
}

function setStatus(text) {
  el('statusText').textContent = text;
}

function updateStats(results) {
  const stats = {
    total: results.length,
    critical: results.filter(r => r.confidence === 'CRITICAL').length,
    high: results.filter(r => r.final_score >= SCORE_MALICIOUS && r.confidence !== 'CRITICAL').length,
    suspicious: results.filter(r => r.final_score >= SCORE_SAFE && r.final_score < SCORE_MALICIOUS && r.confidence !== 'CRITICAL').length,
    safe: results.filter(r => r.final_score < SCORE_SAFE && r.confidence !== 'CRITICAL').length,
    noext: results.filter(r => r.ext === '(none)').length
  };
  el('statTotal').textContent = stats.total;
  el('statCritical').textContent = stats.critical;
  el('statHigh').textContent = stats.high;
  el('statSusp').textContent = stats.suspicious;
  el('statSafe').textContent = stats.safe;
  el('statNoExt').textContent = stats.noext;
  el('statsPanel').style.display = 'grid';
}

function setActiveStatCard(filter) {
  document.querySelectorAll('.stat-card').forEach(card => card.classList.remove('active'));
  const cardMap = {
    'ALL': 'statCardTotal',
    'CRITICAL': 'statCardCritical',
    'HIGH': 'statCardHigh',
    'SUSPICIOUS': 'statCardSusp',
    'MEDIUM': 'statCardSusp',
    'LOW': 'statCardSafe',
    'NOEXT': 'statCardNoExt'
  };
  if (cardMap[filter]) {
    el(cardMap[filter]).classList.add('active');
  }
}

function renderResults(results) {
  const tbody = el('resultsBody');
  tbody.innerHTML = '';
  if (results.length === 0) {
    el('emptyState').style.display = 'block';
    return;
  }
  el('emptyState').style.display = 'none';
  results.forEach((item, idx) => {
    const tr = document.createElement('tr');
    tr.dataset.path = item.file;
    const fileUrl = getFileUrlJS(item.file);
    const extClass = item.ext === '(none)' ? 'noext' : '';
    const extDisplay = item.ext || 'php';
    
    // Show layer detection summary
    let layerInfo = '';
    if (item.layer_scores) {
      const activeLayers = [];
      if (item.layer_scores.layer1 > 0) activeLayers.push('L1');
      if (item.layer_scores.layer2 > 0) activeLayers.push('L2');
      if (item.layer_scores.layer3 > 0) activeLayers.push('L3');
      if (item.layer_scores.layer4 > 0) activeLayers.push('L4');
      if (item.layer_scores.critical > 0) activeLayers.push('CR');
      layerInfo = activeLayers.join('+');
    }
    
    tr.innerHTML = `
      <td class="checkbox-cell">
        <input type="checkbox" class="file-checkbox" data-path="${escapeHtml(item.file)}">
      </td>
      <td>
        <div class="file-path">${escapeHtml(item.file)}</div>
        <button class="btn-edit" onclick="editFile('${escapeHtml(item.file).replace(/'/g, "\\'")}')">✏️ Edit</button>
        <a href="${escapeHtml(fileUrl)}" target="_blank" class="btn-link">🔗 Link</a>
        <button class="btn-delete" onclick="deleteSingleFile('${escapeHtml(item.file).replace(/'/g, "\\'")}')">🗑️ Delete</button>
        <button class="btn-view" onclick="viewFile('${escapeHtml(item.file).replace(/'/g, "\\'")}')">👁️ View</button>
      </td>
      <td><span class="ext-badge ${extClass}">${escapeHtml(extDisplay)}</span></td>
      <td><strong>${item.final_score}</strong></td>
      <td><span class="badge ${item.confidence.toLowerCase()}">${item.confidence}</span></td>
      <td>${item.entropy.toFixed(2)}</td>
      <td>${formatBytes(item.filesize)}</td>
      <td><small>${layerInfo}</small></td>
    `;
    const detailTr = document.createElement('tr');
    detailTr.className = 'detail-row';
    detailTr.id = 'detail-' + idx;
    detailTr.style.display = 'none';
    let flagsHtml = '';
    if (item.flags && item.flags.length > 0) {
      flagsHtml = '<div class="flag-list">' + 
        item.flags.map(f => {
          let flagClass = '';
          if (f.includes('CRITICAL')) flagClass = 'critical';
          else if (f.includes('HIGH')) flagClass = 'high';
          else if (f.includes('MEDIUM')) flagClass = 'medium';
          else if (f.includes('LOW')) flagClass = 'low';
          return `<span class="flag ${flagClass}">${escapeHtml(f)}</span>`;
        }).join('') + 
        '</div>';
    }
    let snippetHtml = '';
    if (item.content_snippet) {
      snippetHtml = `<div class="snippet">${escapeHtml(item.content_snippet)}</div>`;
    }
    
    // Show layer scores breakdown
    let layerBreakdown = '';
    if (item.layer_scores) {
      layerBreakdown = `
        <br><strong>Layer Scores:</strong> 
        L1: ${item.layer_scores.layer1 || 0} | 
        L2: ${item.layer_scores.layer2 || 0} | 
        L3: ${item.layer_scores.layer3 || 0} | 
        L4: ${item.layer_scores.layer4 || 0} | 
        Critical: ${item.layer_scores.critical || 0} | 
        Combo: ${item.layer_scores.combo || 0}
      `;
    }
    
    detailTr.innerHTML = `
      <td colspan="8">
        <div class="detail-content">
          <strong>Detection Flags:</strong>
          ${flagsHtml || '<em>No flags</em>'}
          <br><br>
          <strong>Code Snippet:</strong>
          ${snippetHtml || '<em>No snippet</em>'}
          <br><br>
          <strong>Raw Score:</strong> ${item.raw_score} | 
          <strong>Extension:</strong> ${item.ext || 'php'} |
          <strong>Entropy:</strong> ${item.entropy.toFixed(3)} | 
          <strong>File Size:</strong> ${formatBytes(item.filesize)}
          ${layerBreakdown}
        </div>
      </td>
    `;
    tr.addEventListener('click', (e) => {
      if (e.target.tagName === 'BUTTON' || e.target.tagName === 'A' || e.target.tagName === 'INPUT') return;
      const detail = document.getElementById('detail-' + idx);
      detail.style.display = detail.style.display === 'none' ? 'table-row' : 'none';
    });
    tbody.appendChild(tr);
    tbody.appendChild(detailTr);
  });
}

async function viewFile(filepath) {
  const modal = el('fileModal');
  const modalTitle = el('modalTitle');
  const codeViewer = el('codeViewer');
  modalTitle.textContent = 'Loading...';
  codeViewer.textContent = 'Loading...';
  modal.classList.add('active');
  try {
    const fd = new FormData();
    fd.append('action', 'view_file');
    fd.append('filepath', filepath);
    const response = await fetch('', { method: 'POST', body: fd });
    if (!response.ok) throw new Error('HTTP ' + response.status);
    const json = await response.json();
    if (!json.success) throw new Error(json.error);
    modalTitle.textContent = filepath;
    const lines = json.content.split('\n');
    const numberedContent = lines.map((line, i) => {
      const lineNum = String(i + 1).padStart(4, ' ');
      return `<span class="line-number">${lineNum}</span>${escapeHtml(line)}`;
    }).join('\n');
    codeViewer.innerHTML = numberedContent;
  } catch (error) {
    modalTitle.textContent = 'Error';
    codeViewer.textContent = 'Error: ' + error.message;
  }
}

function getFileUrlJS(filepath) {
  const parts = filepath.split('/public_html/');
  if (parts.length > 1) {
    return window.location.protocol + '//' + window.location.hostname + '/' + parts[1];
  }
  return '#';
}

function applyFilters() {
  const confidence = el('filterConfidence').value;
  const extFilter = el('filterExt').value;
  const sortBy = el('sortBy').value;
  currentFilter = confidence;
  setActiveStatCard(confidence);
  filteredResults = allResults.filter(item => {
    if (extFilter !== 'ALL') {
      if (item.ext !== extFilter) return false;
    }
    if (confidence === 'ALL') return true;
    if (confidence === 'CRITICAL') {
      return item.confidence === 'CRITICAL';
    } else if (confidence === 'HIGH') {
      return item.final_score >= SCORE_MALICIOUS && item.confidence !== 'CRITICAL';
    } else if (confidence === 'MEDIUM' || confidence === 'SUSPICIOUS') {
      return item.final_score >= SCORE_SAFE && item.final_score < SCORE_MALICIOUS && item.confidence !== 'CRITICAL';
    } else if (confidence === 'LOW') {
      return item.final_score < SCORE_SAFE && item.confidence !== 'CRITICAL';
    } else if (confidence === 'NOEXT') {
      return item.ext === '(none)';
    }
    return true;
  });
  if (sortBy === 'score_desc') {
    filteredResults.sort((a, b) => b.final_score - a.final_score);
  } else if (sortBy === 'score_asc') {
    filteredResults.sort((a, b) => a.final_score - b.final_score);
  } else if (sortBy === 'file_asc') {
    filteredResults.sort((a, b) => a.file.localeCompare(b.file));
  }
  renderResults(filteredResults);
}

document.querySelectorAll('.stat-card').forEach(card => {
  card.addEventListener('click', () => {
    const filter = card.getAttribute('data-filter');
    el('filterConfidence').value = filter;
    applyFilters();
  });
});

el('scanBtn').addEventListener('click', async () => {
  const path = el('scanPath').value.trim();
  if (!path) {
    setStatus('⚠️ Please enter a path');
    return;
  }
  const btn = el('scanBtn');
  btn.disabled = true;
  el('resultsPanel').style.display = 'none';
  el('statsPanel').style.display = 'none';
  setStatus('Initializing scan...');
  setProgress(5);
  try {
    const fd = new FormData();
    fd.append('action', 'scan');
    fd.append('path', path);
    setStatus('Scanning: ' + path);
    setProgress(20);
    const response = await fetch('', { method: 'POST', body: fd });
    if (!response.ok) throw new Error('HTTP ' + response.status);
    setProgress(60);
    const json = await response.json();
    if (!json.success) throw new Error(json.error);
    setProgress(80);
    allResults = json.data || [];
    filteredResults = allResults.slice();
    setProgress(100);
    setStatus(`Found ${allResults.length} suspicious files (${json.stats.no_extension || 0} without extension)`);
    updateStats(allResults);
    applyFilters();
    el('resultsPanel').style.display = 'block';
    setTimeout(() => {
      setStatus(`✓ Scan complete: ${json.stats.critical} critical, ${json.stats.high} high, ${json.stats.suspicious} suspicious, ${json.stats.safe} safe`);
    }, 500);
  } catch (error) {
    setStatus('⚠️ Error: ' + error.message);
    setProgress(0);
  } finally {
    btn.disabled = false;
  }
});

el('filterConfidence').addEventListener('change', applyFilters);
el('filterExt').addEventListener('change', applyFilters);
el('sortBy').addEventListener('change', applyFilters);

el('modalClose').addEventListener('click', () => {
  el('fileModal').classList.remove('active');
});

el('fileModal').addEventListener('click', (e) => {
  if (e.target === el('fileModal')) {
    el('fileModal').classList.remove('active');
  }
});

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}
</script>
</body>
</html>
HTMLDOC;

    $html = str_replace('__HOME_DIR__', $home, $html);
    return $html;
}
?>
