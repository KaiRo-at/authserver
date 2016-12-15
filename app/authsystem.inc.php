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

// Extended DOM document class
require_once(__DIR__.'/../php-utility-classes/classes/document.php-class');
// Class for sending emails
require_once(__DIR__.'/../php-utility-classes/classes/email.php-class');
// Composer-provided libraries (oauth2-server-php, doctrine DBAL)
require_once(__DIR__.'/../vendor/autoload.php');
// Authentication utilities
require_once(__DIR__.'/authutils.php-class');
// Instantiate server utils.
try {
  $utils = new AuthUtils();
  $db = $utils->db;
  $settings = $utils->settings;
}
catch (Exception $e) {
  $utils = null;
  print('Failed to set up utilities: '.$e->getMessage());
  exit(1);
}

$utils->setUpL10n();

// Sanitize settings.
$settings['piwik_enabled'] = (@$settings['piwik_enabled']) ? true : false;
$settings['piwik_site_id'] = intval(@$settings['piwik_site_id']);
$settings['piwik_url'] = strlen(@$settings['piwik_url']) ? $settings['piwik_url'] : '/piwik/';
$settings['piwik_tracker_path'] = strlen(@$settings['piwik_tracker_path']) ? $settings['piwik_tracker_path'] : '../vendor/piwik/piwik-php-tracker/';

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

// Set up our OAuth2 Server object
$server = $utils->getOAuthServer();
?>
