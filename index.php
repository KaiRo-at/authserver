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
  $pagetype = 'default';
  $db->exec("SET time_zone='+00:00';"); // Execute directly on PDO object, set session to UTC to make our gmdate() values match correctly.
  if (strlen(@$_COOKIE['sessionkey'])) {
    // Fetch the session - or at least try to.
    $result = $db->prepare('SELECT * FROM `auth_sessions` WHERE `sesskey` = :sesskey AND `time_expire` > :expire;');
    $result->execute(array(':sesskey' => $_COOKIE['sessionkey'], ':expire' => gmdate('Y-m-d H:i:s')));
    $row = $result->fetch(PDO::FETCH_ASSOC);
    if ($row) {
      $session = $row;

      if (array_key_exists('logout', $_GET)) {
        $result = $db->prepare('UPDATE `auth_sessions` SET `logged_in` = FALSE WHERE `id` = :sessid;');
        if (!$result->execute(array(':sessid' => $session['id']))) {
          // XXXlog: Unexpected logout failure!
          $errors[] = _('The email address is invalid.');
        }
        $session['logged_in'] = 0;
      }
      elseif (array_key_exists('email', $_POST)) {
        if (!preg_match('/^[^@]+@[^@]+\.[^@]+$/', $_POST['email'])) {
          $errors[] = _('The email address is invalid.');
        }
        else {
          $result = $db->prepare('SELECT `id`, `pwdhash`, `email`, `status`, `verify_hash` FROM `auth_users` WHERE `email` = :email;');
          $result->execute(array(':email' => $_POST['email']));
          $user = $result->fetch(PDO::FETCH_ASSOC);
          if ($user['id'] && array_key_exists('pwd', $_POST)) {
            // existing user, check password
            if (($user['status'] == 'ok') && password_verify(@$_POST['pwd'], $user['pwdhash'])) {
              // Check if a newer hashing algorithm is available
              // or the cost has changed
              if (password_needs_rehash($user['pwdhash'], PASSWORD_DEFAULT, $pwd_options)) {
                // If so, create a new hash, and replace the old one
                $newHash = password_hash($_POST['pwd'], PASSWORD_DEFAULT, $pwd_options);
                $result = $db->prepare('UPDATE `auth_users` SET `pwdhash` = :pwdhash WHERE `id` = :userid;');
                if (!$result->execute(array(':pwdhash' => $newHash, ':userid' => $user['id']))) {
                  // XXXlog: Failed to update user hash!
                }
              }

              // Log user in - update session key for that, see https://wiki.mozilla.org/WebAppSec/Secure_Coding_Guidelines#Login
              $sesskey = bin2hex(openssl_random_pseudo_bytes(512/8)); // Get 512 bits of randomness (128 byte hex string).
              setcookie('sessionkey', $sesskey, 0, "", "", !$running_on_localhost, true); // Last two params are secure and httponly, secure is not set on localhost.
              // If the session has a user set, create a new one - otherwise take existing session entry.
              if (intval($session['user'])) {
                $result = $db->prepare('INSERT INTO `auth_sessions` (`sesskey`, `time_expire`, `user`, `logged_in`) VALUES (:sesskey, :expire, :userid, TRUE);');
                $result->execute(array(':sesskey' => $sesskey, ':userid' => $user['id'], ':expire' => gmdate('Y-m-d H:i:s', strtotime('+1 day'))));
                // After insert, actually fetch the session row from the DB so we have all values.
                $result = $db->prepare('SELECT * FROM auth_sessions WHERE `sesskey` = :sesskey AND `time_expire` > :expire;');
                $result->execute(array(':sesskey' => $sesskey, ':expire' => gmdate('Y-m-d H:i:s')));
                $row = $result->fetch(PDO::FETCH_ASSOC);
                if ($row) {
                  $session = $row;
                }
                else {
                  // XXXlog: unexpected failure to create session!
                  $errors[] = _('The session system is not working. Please <a href="https://www.kairo.at/contact">contact KaiRo.at</a> and tell the team about this.');
                }
              }
              else {
                $result = $db->prepare('UPDATE `auth_sessions` SET `sesskey` = :sesskey, `user` = :userid, `logged_in` = TRUE, `time_expire` = :expire WHERE `id` = :sessid;');
                if (!$result->execute(array(':sesskey' => $sesskey, ':userid' => $user['id'], ':expire' => gmdate('Y-m-d H:i:s', strtotime('+1 day')), ':sessid' => $session['id']))) {
                  // XXXlog: Unexpected login failure!
                  $errors[] = _('Login failed unexpectedly. Please <a href="https://www.kairo.at/contact">contact KaiRo.at</a> and tell the team about this.');
                }
              }
            }
            else {
              $errors[] = _('This password is invalid or your email is not verified yet. Did you type them correctly?');
            }
          }
          else {
            // new user: check password, create user and send verification; existing users: re-send verification or send password change instructions
            if (array_key_exists('pwd', $_POST)) {
              $new_password = strval($_POST['pwd']);
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
            }
            if (!count($errors)) {
              // Put user into the DB
              if (!$user['id']) {
                $newHash = password_hash($_POST['pwd'], PASSWORD_DEFAULT, $pwd_options);
                $vcode = bin2hex(openssl_random_pseudo_bytes(512/8)); // Get 512 bits of randomness (128 byte hex string).
                $result = $db->prepare('INSERT INTO `auth_users` (`email`, `pwdhash`, `status`, `verify_hash`) VALUES (:email, :pwdhash, \'unverified\', :vcode);');
                if (!$result->execute(array(':email' => $_POST['email'], ':pwdhash' => $newHash, ':vcode' => $vcode))) {
                  // XXXlog: User insertion failure!
                  $errors[] = _('Could not add user. Please <a href="https://www.kairo.at/contact">contact KaiRo.at</a> and tell the team about this.');
                }
                $user = array('id' => $db->lastInsertId(),
                              'email' => $_POST['email'],
                              'pwdhash' => $newHash,
                              'status' => 'unverified',
                              'verify_hash' => $vcode);
              }
              if ($user['status'] == 'unverified') {
                // Send email for verification and show message to point to it.
                $mail = new email();
                $mail->setCharset('utf-8');
                $mail->addHeader('X-KAIRO-AUTH', 'email_verification');
                $mail->addRecipient($user['email']);
                $mail->setSender('noreply@auth.kairo.at', _('KaiRo.at Authentication Service'));
                $mail->setSubject('Email Verification for KaiRo.at Authentication');
                $mail->addMailText(_('Welcome!')."\n\n");
                $mail->addMailText(sprintf(_('This email address, %s, has been used for registration on "%s".'),
                                          $user['email'], _('KaiRo.at Authentication Service'))."\n\n");
                $mail->addMailText(_('Please confirm that registration by clicking the following link (or calling it up in your browser):')."\n");
                $mail->addMailText(($running_on_localhost?'http':'https').'://'.$_SERVER['SERVER_NAME'].strstr($_SERVER['REQUEST_URI'], '?', true)
                                  .'?email='.rawurlencode($user['email']).'&verification_code='.rawurlencode($user['verify_hash'])."\n\n");
                $mail->addMailText(_('With this confirmation, you accept that we handle your data for the purpose of logging you into other websites when you request that.')."\n");
                $mail->addMailText(_('Those websites will get to know your email address but not your password, which we store securely.')."\n");
                $mail->addMailText(_('If you do not call this confirmation link within 72 hours, your data will be deleted from our database.')."\n\n");
                $mail->addMailText(sprintf(_('The %s team'), 'KaiRo.at'));
                //$mail->setDebugAddress("robert@localhost");
                $mailsent = $mail->send();
                if ($mailsent) {
                  $pagetype = 'verification_sent';
                }
                else {
                  $errors[] = _('The confirmation email could not be sent to you. Please <a href="https://www.kairo.at/contact">contact KaiRo.at</a> and tell the team about this.');
                }
              }
              else {
                // Send email with instructions for resetting the password.
              }
            }
          }
        }
      }
      elseif (array_key_exists('reset', $_GET)) {
        if ($session['logged_in']) {
          $pagetype = 'resetpwd';
        }
        else {
          // Display form for entering email.
          $pagetype = 'resetstart';
        }
      }
      elseif (array_key_exists('verification_code', $_GET)) {
        $result = $db->prepare('SELECT `id`,`email` FROM `auth_users` WHERE `email` = :email AND `status` = \'unverified\' AND `verify_hash` = :vcode;');
        $result->execute(array(':email' => @$_GET['email'], ':vcode' => $_GET['verification_code']));
        $user = $result->fetch(PDO::FETCH_ASSOC);
        if ($user['id']) {
          $result = $db->prepare('UPDATE `auth_users` SET `verify_hash` = \'\', `status` = \'ok\' WHERE `id` = :userid;');
          if (!$result->execute(array(':userid' => $user['id']))) {
            // XXXlog: unexpected failure to save verification!
            $errors[] = _('Could not save confirmation. Please <a href="https://www.kairo.at/contact">contact KaiRo.at</a> and tell the team about this.');
          }
          $pagetype = 'verification_done';
        }
        else {
          $errors[] = _('The confirmation link you called is not valid. Possibly it has expired and you need to try registering again.');
        }
      }
      elseif (intval($session['user'])) {
        $result = $db->prepare('SELECT `id`,`email` FROM `auth_users` WHERE `id` = :userid;');
        $result->execute(array(':userid' => $session['user']));
        $user = $result->fetch(PDO::FETCH_ASSOC);
        if (!$user['id']) {
          // XXXlog: unexpected failure to fetch user data!
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
    else {
      // XXXlog: unexpected failure to create session!
      $errors[] = _('The session system is not working. Please <a href="https://www.kairo.at/contact">contact KaiRo.at</a> and tell the team about this.');
    }
  }
}

if (!count($errors)) {
  if ($pagetype == 'verification_sent') {
    $para = $body->appendElement('p', sprintf(_('An email for confirmation has been sent to %s. Please follow the link provided there to complete the process.'), $user['email']));
    $para->setAttribute('class', 'verifyinfo pending');
  }
  elseif ($pagetype == 'resetstart') {
    $para = $body->appendElement('p', _('If you forgot your password or didn\'t receive the registration confirmation, please enter your email here.'));
    $para->setAttribute('class', '');
    $form = $body->appendForm('?reset', 'POST', 'resetform');
    $form->setAttribute('id', 'loginform');
    $form->setAttribute('class', 'loginarea hidden');
    $ulist = $form->appendElement('ul');
    $ulist->setAttribute('class', 'flat login');
    $litem = $ulist->appendElement('li');
    $inptxt = $litem->appendInputEmail('email', 30, 20, 'login_email');
    $inptxt->setAttribute('autocomplete', 'email');
    $inptxt->setAttribute('required', '');
    $inptxt->setAttribute('placeholder', _('Email'));
    $litem = $ulist->appendElement('li');
    $submit = $litem->appendInputSubmit(_('Send instructions to email'));
  }
  elseif ($pagetype == 'resetpwd') {
    $para = $body->appendElement('p', _('You can set a new password here.'));
    $para->setAttribute('class', '');
    $form = $body->appendForm('?reset', 'POST', 'newpwdform');
    $form->setAttribute('id', 'loginform');
    $form->setAttribute('class', 'loginarea hidden');
    $ulist = $form->appendElement('ul');
    $ulist->setAttribute('class', 'flat login');
    $litem = $ulist->appendElement('li');
    $inptxt = $litem->appendInputPassword('pwd', 20, 20, 'login_pwd', '');
    $inptxt->setAttribute('required', '');
    $inptxt->setAttribute('placeholder', _('Password'));
    $inptxt->setAttribute('class', 'login');
    $litem = $ulist->appendElement('li');
    $submit = $litem->appendInputSubmit(_('Save password'));
  }
  elseif ($session['logged_in']) {
    $div = $body->appendElement('div', $user['email']);
    $div->setAttribute('class', 'loginheader');
    $div = $body->appendElement('div');
    $div->setAttribute('class', 'loginlinks');
    $ulist = $div->appendElement('ul');
    $ulist->setAttribute('class', 'flat');
    $litem = $ulist->appendElement('li');
    $link = $litem->appendLink('?logout', _('Log out'));
    $litem = $ulist->appendElement('li');
    $litem->appendLink('?reset', _('Set new password'));
  }
  else { // not logged in
    if ($pagetype == 'verification_done') {
      $para = $body->appendElement('p', _('Hooray! Your email was successfully confirmed! You can log in now.'));
      $para->setAttribute('class', 'verifyinfo done');
    }
    $form = $body->appendForm('?', 'POST', 'loginform');
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
    $inptxt->setAttribute('required', '');
    $inptxt->setAttribute('placeholder', _('Password'));
    $inptxt->setAttribute('class', 'login');
    $litem = $ulist->appendElement('li');
    $litem->appendLink('?reset', _('Forgot password?'));
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
  $body->appendButton(_('Back'), 'history.back();');
}

// Send HTML to client.
print($document->saveHTML());
?>
