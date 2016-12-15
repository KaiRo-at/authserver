<?php
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

// Simple server based on https://bshaffer.github.io/oauth2-server-php-docs/cookbook

// $dbata needs to be set and be an associative array with the members 'dsn', 'username', and 'password'.

// $dsn is the Data Source Name for your database, for exmaple "mysql:dbname=my_oauth2_db;host=localhost"
$oauth2_storage = new OAuth2\Storage\Pdo($dbdata);

// Set configuration
$oauth2_config = array(
  'require_exact_redirect_uri' => false,
  'always_issue_new_refresh_token' => true, // Needs to be handed below as well as there it's not constructed from within the server object.
  'refresh_token_lifetime' => 90*24*3600,
);

// Pass a storage object or array of storage objects to the OAuth2 server class
$server = new OAuth2\Server($oauth2_storage, $oauth2_config);

// Add the "Client Credentials" grant type (it is the simplest of the grant types)
//$server->addGrantType(new OAuth2\GrantType\ClientCredentials($storage));

// Add the "Authorization Code" grant type (this is where the oauth magic happens)
$server->addGrantType(new OAuth2\GrantType\AuthorizationCode($oauth2_storage));

// Add the "Refresh Token" grant type (required to get longer-living resource access by generating new access tokens)
$server->addGrantType(new OAuth2\GrantType\RefreshToken($oauth2_storage, array('always_issue_new_refresh_token' => true)));

?>
