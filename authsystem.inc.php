<?php
// error reporting (for testing)
ini_set('display_errors', 1); error_reporting(E_ALL);

// Read DB settings
$dbdata = json_decode(file_get_contents('/etc/kairo/auth_db.json'), true);
if (!is_array($dbdata)) { trigger_error('DB configuration not found', E_USER_ERROR); }

// Extended DOM document class
require_once('../kairo/include/cbsm/util/document.php-class');

bindtextdomain('kairo_auth', 'en'); // XXX: Should negotiate locale.
bind_textdomain_codeset('kairo_auth', 'utf-8');

// include our OAuth2 Server object
require_once(__DIR__.'/server.inc.php');
?>
