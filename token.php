<?php
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

// Simple server based on https://bshaffer.github.io/oauth2-server-php-docs/cookbook

// Include the common auth system files (including the OAuth2 Server object).
require_once(__DIR__.'/authsystem.inc.php');

// Handle a request for an OAuth2.0 Access Token and send the response to the client
$server->handleTokenRequest(OAuth2\Request::createFromGlobals())->send();

?>
