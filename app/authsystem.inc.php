<?php
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
  Some resources for how to store passwords:
  - https://blog.mozilla.org/webdev/2012/06/08/lets-talk-about-password-storage/
  - https://wiki.mozilla.org/WebAppSec/Secure_Coding_Guidelines
  oauth-server-php: https://bshaffer.github.io/oauth2-server-php-docs/cookbook
*/

// error reporting (for testing)
ini_set('display_errors', 1); error_reporting(E_ALL);

// Read DB settings
$dbdata = json_decode(file_get_contents('/etc/kairo/auth_db.json'), true);
if (!is_array($dbdata)) { trigger_error('DB configuration not found', E_USER_ERROR); }
$settings = json_decode(file_get_contents('/etc/kairo/auth_settings.json'), true);
if (!is_array($settings)) { trigger_error('Auth settings not found', E_USER_ERROR); }

// Extended DOM document class
require_once('../kairo-utils/document.php-class');
// Class for sending emails
require_once('../kairo-utils/email.php-class');
// Class for sending emails
require_once(__DIR__.'/authutils.php-class');

// Connect to our MySQL DB
$db = new PDO($dbdata['dsn'], $dbdata['username'], $dbdata['password']);
// Instantiate auth utils.
$utils = new AuthUtils($settings, $db);

// This is an array of locale tags in browser style mapping to unix system locale codes to use with gettext.
$supported_locales = array(
    'en-US' => 'en_US',
    'de' => 'de_DE',
);

$textdomain = 'kairo_auth';
$textlocale = $utils->negotiateLocale(array_keys($supported_locales));
putenv('LC_ALL='.$supported_locales[$textlocale]);
$selectedlocale = setlocale(LC_ALL, $supported_locales[$textlocale]);
bindtextdomain($textdomain, '../locale');
bind_textdomain_codeset($textdomain, 'utf-8');
textdomain($textdomain);

/* Creating the DB tables:
CREATE TABLE `auth_sessions` (
 `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT ,
 `sesskey` VARCHAR(150) NOT NULL DEFAULT '' ,
 `user` MEDIUMINT UNSIGNED NULL DEFAULT NULL ,
 `logged_in` BOOLEAN NOT NULL DEFAULT FALSE ,
 `time_created` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ,
 `time_expire` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ,
 `saved_redirect` VARCHAR(255) NOT NULL DEFAULT '' ,
 PRIMARY KEY (`id`),
 INDEX (`sesskey`),
 INDEX (`time_expire`)
);
CREATE TABLE `auth_users` (
 `id` MEDIUMINT UNSIGNED NOT NULL AUTO_INCREMENT ,
 `email` VARCHAR(255) NOT NULL ,
 `pwdhash` VARCHAR(255) NOT NULL ,
 `status` ENUM('unverified','ok') NOT NULL DEFAULT 'unverified' ,
 `verify_hash` VARCHAR(150) NULL DEFAULT NULL ,
 `group_id` MEDIUMINT UNSIGNED DEFAULT '0' ,
 PRIMARY KEY (`id`),
 UNIQUE (`email`)
);
CREATE TABLE `auth_log` (
 `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT ,
 `code` VARCHAR(100) NOT NULL ,
 `info` TEXT NULL DEFAULT NULL ,
 `ip_addr` VARCHAR(50) NULL DEFAULT NULL ,
 `time_logged` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ,
 PRIMARY KEY (`id`),
 INDEX (`time_logged`)
);
*/

// include our OAuth2 Server object
require_once(__DIR__.'/server.inc.php');
?>
