<?php
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

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

// Set up our OAuth2 Server object
$server = $utils->getOAuthServer();
?>
