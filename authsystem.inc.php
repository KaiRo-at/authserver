<?php
// error reporting (for testing)
ini_set('display_errors', 1); error_reporting(E_ALL);

// Read DB settings
$dbdata = json_decode(file_get_contents('/etc/kairo/auth_db.json'), true);
if (!is_array($dbdata)) { trigger_error('DB configuration not found', E_USER_ERROR); }

$pwd_options = array('cost' => 10);

// Extended DOM document class
require_once('../kairo/include/cbsm/util/document.php-class');

bindtextdomain('kairo_auth', 'en'); // XXX: Should negotiate locale.
bind_textdomain_codeset('kairo_auth', 'utf-8');

// Connect to our MySQL DB
$db = new PDO($dbdata['dsn'], $dbdata['username'], $dbdata['password']);

/* Creating the DB tables:
CREATE TABLE `auth_sessions` ( `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT , `sesskey` VARCHAR(150) NOT NULL DEFAULT '' , `user` MEDIUMINT UNSIGNED NULL DEFAULT NULL , `logged_in` BOOLEAN NOT NULL DEFAULT FALSE , `time_created` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP , `time_expire` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP , PRIMARY KEY (`id`), INDEX (`sesskey`), INDEX (`time_expire`));
CREATE TABLE `auth_users` ( `id` MEDIUMINT UNSIGNED NOT NULL AUTO_INCREMENT , `email` VARCHAR(255) NOT NULL , `pwdhash` VARCHAR(255) NOT NULL , `status` ENUM('unverified','ok') NOT NULL DEFAULT 'unverified' , `verify_hash` VARCHAR(150) NULL DEFAULT NULL , PRIMARY KEY (`id`), UNIQUE (`email`));
*/

// include our OAuth2 Server object
require_once(__DIR__.'/server.inc.php');
?>
