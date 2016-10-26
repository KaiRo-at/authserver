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
        elseif (verifyTimeCode(@$_POST['tcode'], $session)) {
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
              $sesskey = createSessionKey();
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
                  // XXXlog: Unexpected failure to create session!
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
              // If a verify_hash if set on a verified user, a password reset had been requested. As a login works right now, cancel that reset request by deleting the hash.
              if (strlen(@$user['verify_hash'])) {
                $result = $db->prepare('UPDATE `auth_users` SET `verify_hash` = \'\' WHERE `id` = :userid;');
                if (!$result->execute(array(':userid' => $user['id']))) {
                  // XXXlog: verify_hash could not be emptied!
                }
                else {
                  $user['verify_hash'] = '';
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
              $errors += checkPasswordConstraints(strval($_POST['pwd']), $_POST['email']);
            }
            if (!count($errors)) {
              // Put user into the DB
              if (!$user['id']) {
                $newHash = password_hash($_POST['pwd'], PASSWORD_DEFAULT, $pwd_options);
                $vcode = createVerificationCode();
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
                // Password reset requested with "Password forgotten?" function.
                $vcode = createVerificationCode();
                $result = $db->prepare('UPDATE `auth_users` SET `verify_hash` = :vcode WHERE `id` = :userid;');
                if (!$result->execute(array(':vcode' => $vcode, ':userid' => $user['id']))) {
                  // XXXlog: User insertion failure!
                  $errors[] = _('Could not initiate reset request. Please <a href="https://www.kairo.at/contact">contact KaiRo.at</a> and tell the team about this.');
                }
                else {
                  $resetcode = $vcode.dechex($user['id'] + $session['id']).'_'.createTimeCode($session, null, 60);
                  // Send email with instructions for resetting the password.
                  $mail = new email();
                  $mail->setCharset('utf-8');
                  $mail->addHeader('X-KAIRO-AUTH', 'password_reset');
                  $mail->addRecipient($user['email']);
                  $mail->setSender('noreply@auth.kairo.at', _('KaiRo.at Authentication Service'));
                  $mail->setSubject('How to reset your password for KaiRo.at Authentication');
                  $mail->addMailText(_('Hi,')."\n\n");
                  $mail->addMailText(sprintf(_('A request for setting a new password for this email address, %s, has been submitted on "%s".'),
                                            $user['email'], _('KaiRo.at Authentication Service'))."\n\n");
                  $mail->addMailText(_('You can set a new password by clicking the following link (or calling it up in your browser):')."\n");
                  $mail->addMailText(($running_on_localhost?'http':'https').'://'.$_SERVER['SERVER_NAME'].strstr($_SERVER['REQUEST_URI'], '?', true)
                                    .'?email='.rawurlencode($user['email']).'&reset_code='.rawurlencode($resetcode)."\n\n");
                  $mail->addMailText(_('If you do not call this confirmation link within 1 hour, this link expires and the existing password is being kept in place.')."\n\n");
                  $mail->addMailText(sprintf(_('The %s team'), 'KaiRo.at'));
                  //$mail->setDebugAddress("robert@localhost");
                  $mailsent = $mail->send();
                  if ($mailsent) {
                    $pagetype = 'resetmail_sent';
                  }
                  else {
                    $errors[] = _('The email with password reset instructions could not be sent to you. Please <a href="https://www.kairo.at/contact">contact KaiRo.at</a> and tell the team about this.');
                  }
                }
              }
            }
          }
        }
        else {
          $errors[] = _('The form you used was not valid. Possibly it has expired and you need to initiate the action again.');
        }
      }
      elseif (array_key_exists('reset', $_GET)) {
        if ($session['logged_in']) {
          $result = $db->prepare('SELECT `id`,`email` FROM `auth_users` WHERE `id` = :userid;');
          $result->execute(array(':userid' => $session['user']));
          $user = $result->fetch(PDO::FETCH_ASSOC);
          if (!$user['id']) {
            // XXXlog: Unexpected failure to fetch user data!
          }
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
            // XXXlog: Unexpected failure to save verification!
            $errors[] = _('Could not save confirmation. Please <a href="https://www.kairo.at/contact">contact KaiRo.at</a> and tell the team about this.');
          }
          $pagetype = 'verification_done';
        }
        else {
          $errors[] = _('The confirmation link you called is not valid. Possibly it has expired and you need to try registering again.');
        }
      }
      elseif (array_key_exists('reset_code', $_GET)) {
        $reset_fail = true;
        $result = $db->prepare('SELECT `id`,`email`,`verify_hash` FROM `auth_users` WHERE `email` = :email');
        $result->execute(array(':email' => @$_GET['email']));
        $user = $result->fetch(PDO::FETCH_ASSOC);
        if ($user['id']) {
          // Deconstruct reset code and verify it.
          if (preg_match('/^([0-9a-f]{'.strlen($user['verify_hash']).'})([0-9a-f]+)_(\d+\.\d+)$/', $_GET['reset_code'], $regs)) {
            $tcode_sessid = hexdec($regs[2]) - $user['id'];
            $result = $db->prepare('SELECT `id`,`sesskey` FROM `auth_sessions` WHERE `id` = :sessid;');
            $result->execute(array(':sessid' => $tcode_sessid));
            $row = $result->fetch(PDO::FETCH_ASSOC);
            if ($row) {
              $tcode_session = $row;
              if (($regs[1] == $user['verify_hash']) &&
                  verifyTimeCode($regs[3], $session, 60)) {
                // Set a new verify_hash for the actual password reset.
                $user['verify_hash'] = createVerificationCode();
                $result = $db->prepare('UPDATE `auth_users` SET `verify_hash` = :vcode WHERE `id` = :userid;');
                if (!$result->execute(array(':vcode' => $user['verify_hash'], ':userid' => $user['id']))) {
                  // XXXlog: Unexpected failure to reset verify_hash!
                }
                $result = $db->prepare('UPDATE `auth_sessions` SET `user` = :userid WHERE `id` = :sessid;');
                if (!$result->execute(array(':userid' => $user['id'], ':sessid' => $session['id']))) {
                  // XXXlog: Unexpected failure to update session!
                }
                $pagetype = 'resetpwd';
                $reset_fail = false;
              }
            }
          }
        }
        if ($reset_fail) {
          $errors[] = _('The password reset link you called is not valid. Possibly it has expired and you need to call the "Password forgotten?" function again.');
        }
      }
      elseif (intval($session['user'])) {
        $result = $db->prepare('SELECT `id`,`email`,`verify_hash` FROM `auth_users` WHERE `id` = :userid;');
        $result->execute(array(':userid' => $session['user']));
        $user = $result->fetch(PDO::FETCH_ASSOC);
        if (!$user['id']) {
          // XXXlog: Unexpected failure to fetch user data!
        }
        // Password reset requested.
        if (array_key_exists('pwd', $_POST) && array_key_exists('reset', $_POST) && array_key_exists('tcode', $_POST)) {
          // If not logged in, a password reset needs to have the proper vcode set.
          if (!$session['logged_in'] && (!strlen(@$_POST['vcode']) || ($_POST['vcode'] != $user['verify_hash']))) {
            $errors[] = _('Password reset failed. The reset form you used was not valid. Possibly it has expired and you need to initiate the password reset again.');
          }
          // If not logged in, a password reset also needs to have the proper email set.
          if (!$session['logged_in'] && !count($errors) && (@$_POST['email_hidden'] != $user['email'])) {
            $errors[] = _('Password reset failed. The reset form you used was not valid. Possibly it has expired and you need to initiate the password reset again.');
          }
          // Check validity of time code.
          if (!count($errors) && !verifyTimeCode($_POST['tcode'], $session)) {
            $errors[] = _('Password reset failed. The reset form you used was not valid. Possibly it has expired and you need to initiate the password reset again.');
          }
          $errors += checkPasswordConstraints(strval($_POST['pwd']), $user['email']);
          if (!count($errors)) {
            $newHash = password_hash($_POST['pwd'], PASSWORD_DEFAULT, $pwd_options);
            $result = $db->prepare('UPDATE `auth_users` SET `pwdhash` = :pwdhash, `verify_hash` = \'\' WHERE `id` = :userid;');
            if (!$result->execute(array(':pwdhash' => $newHash, ':userid' => $session['user']))) {
              // XXXlog: Password reset failure!
              $errors[] = _('Password reset failed. Please <a href="https://www.kairo.at/contact">contact KaiRo.at</a> and tell the team about this.');
            }
            else {
              $pagetype = 'reset_done';
            }
          }
        }
      }
    }
  }
  if (is_null($session)) {
    // Create new session and set cookie.
    $sesskey = createSessionKey();
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
      // XXXlog: Unexpected failure to create session!
      $errors[] = _('The session system is not working. Please <a href="https://www.kairo.at/contact">contact KaiRo.at</a> and tell the team about this.');
    }
  }
}

if (!count($errors)) {
  if ($pagetype == 'verification_sent') {
    $para = $body->appendElement('p', sprintf(_('An email for confirmation has been sent to %s. Please follow the link provided there to complete the process.'), $user['email']));
    $para->setAttribute('class', 'verifyinfo pending');
  }
  elseif ($pagetype == 'resetmail_sent') {
    $para = $body->appendElement('p',
        _('An email has been sent to the requested account with further information. If you do not receive an email then please confirm you have entered the same email address used during account registration.'));
    $para->setAttribute('class', 'resetinfo pending');
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
    $litem->appendInputHidden('tcode', createTimeCode($session));
    $submit = $litem->appendInputSubmit(_('Send instructions to email'));
  }
  elseif ($pagetype == 'resetpwd') {
    $para = $body->appendElement('p', sprintf(_('You can set a new password for %s here.'), $user['email']));
    $para->setAttribute('class', '');
    $form = $body->appendForm('?', 'POST', 'newpwdform');
    $form->setAttribute('id', 'loginform');
    $form->setAttribute('class', 'loginarea hidden');
    $ulist = $form->appendElement('ul');
    $ulist->setAttribute('class', 'flat login');
    $litem = $ulist->appendElement('li');
    $litem->setAttribute('class', 'donotshow');
    $inptxt = $litem->appendInputEmail('email_hidden', 30, 20, 'login_email', $user['email']);
    $inptxt->setAttribute('autocomplete', 'email');
    $inptxt->setAttribute('placeholder', _('Email'));
    $litem = $ulist->appendElement('li');
    $inptxt = $litem->appendInputPassword('pwd', 20, 20, 'login_pwd', '');
    $inptxt->setAttribute('required', '');
    $inptxt->setAttribute('placeholder', _('Password'));
    $inptxt->setAttribute('class', 'login');
    $litem = $ulist->appendElement('li');
    $litem->appendInputHidden('reset', '');
    $litem->appendInputHidden('tcode', createTimeCode($session));
    if (!$session['logged_in'] && strlen(@$user['verify_hash'])) {
      $litem->appendInputHidden('vcode', $user['verify_hash']);
    }
    $submit = $litem->appendInputSubmit(_('Save password'));
  }
  elseif ($session['logged_in']) {
    if ($pagetype == 'reset_done') {
      $para = $body->appendElement('p', _('Your password has successfully been reset.'));
      $para->setAttribute('class', 'resetinfo done');
    }
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
    elseif ($pagetype == 'reset_done') {
      $para = $body->appendElement('p', _('Your password has successfully been reset. You can log in now with the new password.'));
      $para->setAttribute('class', 'resetinfo done');
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
    $litem->appendInputHidden('tcode', createTimeCode($session));
    $submit = $litem->appendInputSubmit(_('Log in / Register'));
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

// ********** helper functions **********

function checkPasswordConstraints($new_password, $user_email) {
  $errors = array();
  if ($new_password != trim($new_password)) {
    $errors[] = _('Password must not start or end with a whitespace character like a space.');
  }
  if (strlen($new_password) < 8) { $errors[] = sprintf(_('Password too short (min. %s characters).'), 8); }
  if (strlen($new_password) > 70) { $errors[] = sprintf(_('Password too long (max. %s characters).'), 70); }
  if ((strtolower($new_password) == strtolower($user_email)) ||
      in_array(strtolower($new_password), preg_split("/[@\.]+/", strtolower($user_email)))) {
    $errors[] = _('The passwort can not be equal to your email or any part of it.');
  }
  if ((strlen($new_password) < 15) && (preg_match('/^[a-zA-Z]+$/', $new_password))) {
    $errors[] = sprintf(_('Your password must use characters other than normal letters or contain least %s characters.'), 15);
  }
  if (preg_match('/^\d+$/', $new_password)) {
    $errors[] = sprintf(_('Your password cannot consist only of numbers.'), 15);
  }
  if (strlen(count_chars($new_password, 3)) < 5) {
    $errors[] = sprintf(_('Password does have to contain at least %s different characters.'), 5);
  }
  return $errors;
}

function createSessionKey() {
  return bin2hex(openssl_random_pseudo_bytes(512 / 8)); // Get 512 bits of randomness (128 byte hex string).
}

function createVerificationCode() {
  return bin2hex(openssl_random_pseudo_bytes(512 / 8)); // Get 512 bits of randomness (128 byte hex string).
}

function createTimeCode($session, $offset = null, $validity_minutes = 10) {
  // Matches TOTP algorithms, see https://en.wikipedia.org/wiki/Time-based_One-time_Password_Algorithm
  $valid_seconds = intval($validity_minutes) * 60;
  if ($valid_seconds < 60) { $valid_seconds = 60; }
  $code_digits = 8;
  $time = time();
  $rest = is_null($offset)?($time % $valid_seconds):intval($offset); // T0, will be sent as part of code to make it valid for the full duration.
  $counter = floor(($time - $rest) / $valid_seconds);
  $hmac = mhash(MHASH_SHA1, $counter, $session['id'].$session['sesskey']);
  $offset = hexdec(substr(bin2hex(substr($hmac, -1)), -1)); // Get the last 4 bits as a number.
  $totp = hexdec(bin2hex(substr($hmac, $offset, 4))) & 0x7FFFFFFF; // Take 4 bytes at the offset, discard highest bit.
  $totp_value = sprintf('%0'.$code_digits.'d', substr($totp, -$code_digits));
  return $rest.'.'.$totp_value;
}

function verifyTimeCode($timecode_to_verify, $session, $validity_minutes = 10) {
  if (preg_match('/^(\d+)\.\d+$/', $timecode_to_verify, $regs)) {
    return ($timecode_to_verify === createTimeCode($session, $regs[1], $validity_minutes));
  }
  return false;
}

?>
