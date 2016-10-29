<?php
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

// Called e.g. as /api?access_token=...&whatever_api_parameters
// access_token can be handed via GET or POST or an 'Authorization: Bearer' header.
// Response is always JSON.

// Include the common auth system files (including the OAuth2 Server object).
require_once(__DIR__.'/authsystem.inc.php');

$errors = $utils->checkForSecureConnection();

if (!count($errors)) {
  // Handle a request to a resource and authenticate the access token
  $token_OK = $server->verifyResourceRequest(OAuth2\Request::createFromGlobals());
  if (!$token_OK) {
    $server->getResponse()->send();
    exit();
  }
  $token = $server->getAccessTokenData(OAuth2\Request::createFromGlobals());
  // API request successful, return requested resource.
  if (array_key_exists('email', $_GET)) {
    if ($token['scope'] == 'email') {
      if (intval(@$token['user_id'])) {
        $result = $db->prepare('SELECT `id`,`email` FROM `auth_users` WHERE `id` = :userid;');
        $result->execute(array(':userid' => $token['user_id']));
        $user = $result->fetch(PDO::FETCH_ASSOC);
        if (!$user['id']) {
          $utils->log('user_token_failure', 'token: '.$token['access_token']);
          print(json_encode(array('error' => 'unknown_user',
                                  'error_description' => 'The user the access token is connected to was not recognized.')));
        }
        else {
          print(json_encode(array('success' => true, 'email' => $user['email'])));
        }
      }
      else {
        print(json_encode(array('error' => 'no_user',
                                'error_description' => 'The access token is not connected to a user.')));
      }
    }
    else {
      print(json_encode(array('error' => 'insufficient_scope',
                              'error_description' => 'The scope of the token you used in this API request is insufficient to access this resource.')));
    }
  }
  elseif (array_key_exists('newclient', $_GET)) {
    if ($token['scope'] == 'clientreg') {
      if (intval(@$token['user_id'])) {
        $result = $db->prepare('SELECT `id`,`email` FROM `auth_users` WHERE `id` = :userid;');
        $result->execute(array(':userid' => $token['user_id']));
        $user = $result->fetch(PDO::FETCH_ASSOC);
        if (!$user['id']) {
          $utils->log('user_token_failure', 'token: '.$token['access_token']);
          print(json_encode(array('error' => 'unknown_user',
                                  'error_description' => 'The user the access token is connected to was not recognized.')));
        }
        else {
          if (in_array($user['email'], $utils->client_reg_email_whitelist)) {
            if (strlen(@$_GET['client_id']) >= 5) {
              $result = $db->prepare('SELECT `client_id`,`user_id` FROM `oauth_clients` WHERE `client_id` = :clientid;');
              $result->execute(array(':clientid' => $_GET['client_id']));
              $client = $result->fetch(PDO::FETCH_ASSOC);
              if (!$client['client_id']) {
                // Set new client ID.
                $clientsecret = $utils->createClientSecret();
                $result = $db->prepare('INSERT INTO `oauth_clients` (`client_id`, `client_secret`, `redirect_uri`, `scope`, `user_id`) VALUES (:clientid, :secret, :rediruri, :scope, :userid);');
                if ($result->execute(array(':clientid' => $_GET['client_id'],
                                           ':secret' => $clientsecret,
                                           ':rediruri' => (strlen(@$_GET['redirect_uri']) ? $_GET['redirect_uri'] : ''),
                                           ':scope' => (strlen(@$_GET['scope']) ? $_GET['scope'] : ''),
                                           ':userid' => $user['id']))) {
                  print(json_encode(array('success' => true, 'client_secret' => $clientsecret)));
                }
                else {
                  $utils->log('client_save_failure', 'client: '.$client['client_id']);
                  print(json_encode(array('error' => 'unexpected_save_failure',
                                          'error_description' => 'Unexpectedly failed to save new client information.')));
                }
              }
              elseif ($client['user_id'] == $user['id']) {
                // The client ID was set by this user, set new secret and return.
                $clientsecret = $utils->createClientSecret();
                $result = $db->prepare('UPDATE `oauth_clients` SET `client_secret` = :secret WHERE `client_id` = :clientid;');
                if (!$result->execute(array(':secret' => $clientsecret,':clientid' => $client['client_id']))) {
                  $utils->log('client_save_failure', 'client: '.$client['client_id'].', new secret - '.$result->errorInfo()[2]);
                  print(json_encode(array('error' => 'unexpected_save_failure',
                                          'error_description' => 'Unexpectedly failed to save new secret.')));
                }
                else {
                  if (strlen(@$_GET['redirect_uri'])) {
                    $result = $db->prepare('UPDATE `oauth_clients` SET `redirect_uri` = :rediruri WHERE `client_id` = :clientid;');
                    if (!$result->execute(array(':rediruri' => $_GET['redirect_uri'],':clientid' => $client['client_id']))) {
                      $utils->log('client_save_failure', 'client: '.$client['client_id'].', new redirect_uri: '.$_GET['redirect_uri'].' - '.$result->errorInfo()[2]);
                    }
                  }
                  if (strlen(@$_GET['scope'])) {
                    $result = $db->prepare('UPDATE `oauth_clients` SET `scope` = :scope WHERE `client_id` = :clientid;');
                    if (!$result->execute(array(':scope' => $_GET['scope'],':clientid' => $client['client_id']))) {
                      $utils->log('client_save_failure', 'client: '.$client['client_id'].', new scope: '.$_GET['scope'].' - '.$result->errorInfo()[2]);
                    }
                  }
                  print(json_encode(array('success' => true, 'client_secret' => $clientsecret)));
                }
              }
              else {
                print(json_encode(array('error' => 'client_id_used',
                                        'error_description' => 'This client ID is in use by a different user.')));
              }
            }
            else {
              print(json_encode(array('error' => 'invalid_client_id_',
                                      'error_description' => 'A client ID of at least 5 characters needs to be supplied.')));
            }
          }
          else {
            print(json_encode(array('error' => 'insufficient_privileges',
                                    'error_description' => 'This user is not allowed to register new clients.')));
          }
        }
      }
      else {
        print(json_encode(array('error' => 'no_user',
                                'error_description' => 'The access token is not connected to a user.')));
      }
    }
    else {
      print(json_encode(array('error' => 'insufficient_scope',
                              'error_description' => 'The scope of the token you used in this API request is insufficient to access this resource.')));
    }
  }
  else {
    print(json_encode(array('error' => 'invalid_resource',
                            'error_description' => 'The resource requested from the API is unknown.')));
  }
}
else {
  print(json_encode(array('error' => 'insecure_connection',
                          'error_description' => 'Your connection is insecure. The API can only be accessed on secure connections.')));
}
?>
