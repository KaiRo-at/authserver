<?php
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

// Include the common auth system files (including the OAuth2 Server object).
require_once(__DIR__.'/authsystem.inc.php');

$errors = array();

// Start HTML document as a DOM object.
extract(ExtendedDocument::initHTML5()); // sets $document, $html, $head, $title, $body
$document->formatOutput = true; // we want a nice output

$style = $head->appendElement('link');
$style->setAttribute('rel', 'stylesheet');
$style->setAttribute('href', 'authsystem.css');
$head->appendJSFile('authsystem.js');
$title->appendText('KaiRo.at Authentication Server');
$h1 = $body->appendElement('h1', 'KaiRo.at Authentication Server');

$running_on_localhost = preg_match('/^((.+\.)?localhost|127\.0\.0\.\d+)$/', $_SERVER['SERVER_NAME']);
if (($_SERVER['SERVER_PORT'] != 443) && !$running_on_localhost) {
  $errors[] = _('You are not accessing this site on a secure connection, so authentication doesn\'t work.');
}

$para = $body->appendElement('p', _('This login system does not work without JavaScript. Please activate JavaScript for this site to log in.'));
$para->setAttribute('id', 'jswarning');
$para->setAttribute('class', 'warn');

if (!count($errors)) {
  $session = null;
  $user = array('id' => 0, 'email' => '');
  $db->exec("SET time_zone='+00:00';"); // Execute directly on PDO object, set session to UTC to make our gmdate() values match correctly.
  if (strlen(@$_COOKIE['sessionkey'])) {
    // Fetch the session - or at least try to.
    $result = $db->prepare('SELECT * FROM `auth_sessions` WHERE `sesskey` = :sesskey AND `time_expire` > :expire;');
    $result->execute(array(':sesskey' => $_COOKIE['sessionkey'], ':expire' => gmdate('Y-m-d H:i:s')));
    $row = $result->fetch(PDO::FETCH_ASSOC);
    if ($row) {
      $session = $row;

      if (strlen(@$_POST['email'])) {
        if (!preg_match('/^[^@]+@[^@]+\.[^@]+$/', $_POST['email'])) {
          $errors[] = _('The email address is invalid.');
        }
        else {
          $result = $db->prepare('SELECT `id`, `pwdhash`, `email`, `status`, `verify_hash` FROM `auth_users` WHERE `email` = :email;');
          $result->execute(array(':email' => $_POST['email']));
          $user = $result->fetch(PDO::FETCH_ASSOC);
          if ($user['id']) {
            // existing user, check password
            if (($user['status'] == 'ok') && password_verify(@$_POST['pwd'], $user['pwdhash'])) {
              // Check if a newer hashing algorithm is available
              // or the cost has changed
              if (password_needs_rehash($user['pwdhash'], PASSWORD_DEFAULT, $pwd_options)) {
                // If so, create a new hash, and replace the old one
                $newHash = password_hash($_POST['pwd'], PASSWORD_DEFAULT, $pwd_options);
                $result = $db->prepare('UPDATE `auth_users` SET `pwdhash` = :pwdhash WHERE `id` = :userid;');
                $result->execute(array(':pwdhash' => $newHash, ':userid' => $user['id']));
              }

              // Log user in - update session key for that, see https://wiki.mozilla.org/WebAppSec/Secure_Coding_Guidelines#Login
              $sesskey = bin2hex(openssl_random_pseudo_bytes(512/8)); // Get 512 bits of randomness (128 byte hex string).
              setcookie('sessionkey', $sesskey, 0, "", "", !$running_on_localhost, true); // Last two params are secure and httponly, secure is not set on localhost.
              $result = $db->prepare('UPDATE `auth_sessions` SET `sesskey` = :sesskey, `user` = :userid, `time_expire` = :expire WHERE `id` = :sessid;');
              $result->execute(array(':sesskey' => $sesskey, ':userid' => $user['id'], ':expire' => gmdate('Y-m-d H:i:s', strtotime('+1 day')), ':sessid' => $session['id']));
            }
            else {
              $errors[] = _('This password is invalid or your email is not verified yet. Did you type them correctly?');
            }
          }
          else {
            // new user, check password, then create user and send verification
            $new_password = strval(@$_POST['pwd']);
            if ($new_password != trim($new_password)) {
              $errors[] = _('Password must not start or end with a whitespace character like a space.');
            }
            if (strlen($new_password) < 8) { $errors[] = sprintf(_('Password too short (min. %s characters).'), 8); }
            if (strlen($new_password) > 70) { $errors[] = sprintf(_('Password too long (max. %s characters).'), 70); }
            if (strtolower($new_password) == strtolower($_POST['email']))  {
              $errors[] = _('The passwort can not be equal to your email.');
            }
            if ((strlen($new_password) < 15) && (preg_match('/^[a-zA-Z]*$/', $new_password))) {
              $errors[] = sprintf(_('Your password must use letters other than normal characters or contain least 15 characters.'), 15);
            }
            if (strlen(count_chars($new_password, 3)) < 5) {
              $errors[] = sprintf(_('Password does have to contain at least %s different characters.'), 5);
            }
            if (!count($errors)) {
              // Put user into the DB
              $newHash = password_hash($_POST['pwd'], PASSWORD_DEFAULT, $pwd_options);
              $vhash = bin2hex(openssl_random_pseudo_bytes(512/8)); // Get 512 bits of randomness (128 byte hex string).
              $result = $db->prepare('INSERT INTO `auth_users` (`email`, `pwdhash`, `status`, `verify_hash`) VALUES (:email, :pwdhash, \'unverified\', :vhash);');
              $result->execute(array(':email' => $_POST['email'], ':pwdhash' => $newHash, ':vhash' => $vhash));
              $user = array('id' => $db->lastInsertId(),
                            'email' => $_POST['email'],
                            'pwdhash' => $newHash,
                            'status' => 'unverified',
                            'verify_hash' => $vhash);
              // Send email for verification and show message to point to it.
            }
          }
        }
      }
    }
  }
  if (is_null($session)) {
    // Create new session and set cookie.
    $sesskey = bin2hex(openssl_random_pseudo_bytes(512/8)); // Get 512 bits of randomness (128 byte hex string).
    setcookie('sessionkey', $sesskey, 0, "", "", !$running_on_localhost, true); // Last two params are secure and httponly, secure is not set on localhost.
    $result = $db->prepare('INSERT INTO `auth_sessions` (`sesskey`, `time_expire`) VALUES (:sesskey, :expire);');
    $result->execute(array(':sesskey' => $sesskey, ':expire' => gmdate('Y-m-d H:i:s', strtotime('+5 minutes'))));
    // After insert, actually fetch the session row from the DB so we have all values.
    $result = $db->prepare('SELECT * FROM auth_sessions WHERE `sesskey` = :sesskey AND `time_expire` > :expire;');
    $result->execute(array(':sesskey' => $sesskey, ':expire' => gmdate('Y-m-d H:i:s')));
    $row = $result->fetch(PDO::FETCH_ASSOC);
    if ($row) {
      $session = $row;
    }
  }
}

if (!count($errors)) {

  if ($session['logged_in']) {
    $div = $body->appendElement('div', $user['email']);
    $div->setAttribute('class', 'loginheader');
    $div = $body->appendElement('div');
    $div->setAttribute('class', 'loginlinks');
    $link = $div->appendLink('?logout', _('Log out'));
    $link->setAttribute('title', _('Log out user of the system'));
  }
  else { // not logged in
    $form = $body->appendForm('#', 'POST', 'loginform');
    $form->setAttribute('id', 'loginform');
    $form->setAttribute('class', 'loginarea hidden');
    $ulist = $form->appendElement('ul');
    $ulist->setAttribute('class', 'flat login');
    $litem = $ulist->appendElement('li');
    $inptxt = $litem->appendInputEmail('email', 30, 20, 'login_email', (intval($user['id'])?$user['email']:''));
    $inptxt->setAttribute('autocomplete', 'email');
    $inptxt->setAttribute('required', '');
    $inptxt->setAttribute('placeholder', _('Email'));
    $inptxt->setAttribute('class', 'login');
    $litem = $ulist->appendElement('li');
    $inptxt = $litem->appendInputPassword('pwd', 20, 20, 'login_pwd', '');
    $inptxt->setAttribute('placeholder', _('Password'));
    $inptxt->setAttribute('class', 'login');
    $litem = $ulist->appendElement('li');
    $cbox = $litem->appendInputCheckbox('remember', 'login_remember', 'true', false);
    $cbox->setAttribute('class', 'logincheck');
    $label = $litem->appendLabel('login_remember', _('Remember me'));
    $label->setAttribute('id', 'rememprompt');
    $label->setAttribute('class', 'loginprompt');
    $litem = $ulist->appendElement('li');
    $submit = $litem->appendInputSubmit(_('Log in'));
    $submit->setAttribute('class', 'loginbutton');
  }
}

if (count($errors)) {
  $body->appendElement('p', ((count($errors) <= 1)
                            ?_('The following error was detected')
                            :_('The following errors were detected')).':');
  $list = $body->appendElement('ul');
  $list->setAttribute('class', 'flat warn');
  foreach ($errors as $msg) {
    $item = $list->appendElement('li', $msg);
  }
}

// Send HTML to client.
print($document->saveHTML());
?>
