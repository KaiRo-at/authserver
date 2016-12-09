<?php
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

// Include the common auth system files (including the OAuth2 Server object).
require_once(__DIR__.'/authsystem.inc.php');

$errors = $utils->checkForSecureConnection();
$utils->sendSecurityHeaders();

// Initialize the HTML document with our basic elements.
extract($utils->initHTMLDocument('KaiRo.at Authentication Server')); // sets $document, $html, $head, $title, $body

if (!count($errors)) {
  $session = $utils->initSession(); // Read session or create new session and set cookie.
  $user = array('id' => 0, 'email' => '');
  $pagetype = 'default';
  if (is_null($session)) {
    $errors[] = _('The session system is not working.').' '._('Please <a href="https://www.kairo.at/contact">contact KaiRo.at</a> and tell the team about this.');
  }
  elseif (array_key_exists('logout', $_GET)) {
    $result = $db->prepare('UPDATE `auth_sessions` SET `logged_in` = FALSE WHERE `id` = :sessid;');
    if (!$result->execute(array(':sessid' => $session['id']))) {
      $utils->log('logout_failure', 'session: '.$session['id']);
      $errors[] = _('Unexpected error while logging out.');
    }
    $session['logged_in'] = 0;
  }
  elseif (array_key_exists('email', $_POST)) {
    if (!preg_match('/^[^@]+@[^@]+\.[^@]+$/', $_POST['email'])) {
      $errors[] = _('The email address is invalid.');
    }
    elseif ($utils->verifyTimeCode(@$_POST['tcode'], $session)) {
      $result = $db->prepare('SELECT `id`, `pwdhash`, `email`, `status`, `verify_hash`,`group_id` FROM `auth_users` WHERE `email` = :email;');
      $result->execute(array(':email' => $_POST['email']));
      $user = $result->fetch(PDO::FETCH_ASSOC);
      // If we need to add the email to a group, note here which user's group we should be added to - otherwise, set to 0.
      $addgroup = (array_key_exists('grouptoexisting', $_POST) && intval($session['user']) && ($session['user'] != @$user['id'])) ? $session['user'] : 0;
      if ($user['id'] && array_key_exists('pwd', $_POST)) {
        // existing user, check password
        if (($user['status'] == 'ok') && $utils->pwdVerify(@$_POST['pwd'], $user)) {
          // Check if a newer hashing algorithm is available
          // or the cost has changed
          if ($utils->pwdNeedsRehash($user)) {
            // If so, create a new hash, and replace the old one
            $newHash = $utils->pwdHash($_POST['pwd']);
            $result = $db->prepare('UPDATE `auth_users` SET `pwdhash` = :pwdhash WHERE `id` = :userid;');
            if (!$result->execute(array(':pwdhash' => $newHash, ':userid' => $user['id']))) {
              $utils->log('user_hash_save_failure', 'user: '.$user['id']);
            }
            else {
              $utils->log('pwd_rehash_success', 'user: '.$user['id']);
            }
          }

          // Log user in - update session key for that, see https://wiki.mozilla.org/WebAppSec/Secure_Coding_Guidelines#Login
          $utils->log('login', 'user: '.$user['id']);
          $prev_session = $session;
          $session = $utils->getLoginSession($user['id'], $session);
          // If a verify_hash if set on a verified user, a password reset had been requested. As a login works right now, cancel that reset request by deleting the hash.
          if (strlen(@$user['verify_hash'])) {
            $result = $db->prepare('UPDATE `auth_users` SET `verify_hash` = \'\' WHERE `id` = :userid;');
            if (!$result->execute(array(':userid' => $user['id']))) {
              $utils->log('empty_vhash_failure', 'user: '.$user['id']);
            }
            else {
              $user['verify_hash'] = '';
            }
          }
          $utils->doRedirectIfSet($prev_session);
        }
        else {
          $errors[] = _('This password is invalid or your email is not verified yet. Did you type them correctly?');
        }
      }
      else {
        // new user: check password, create user and send verification; existing users: re-send verification or send password change instructions
        if (array_key_exists('pwd', $_POST)) {
          $errors += $utils->checkPasswordConstraints(strval($_POST['pwd']), $_POST['email']);
        }
        if (!count($errors)) {
          // Put user into the DB
          if (!$user['id']) {
            $newHash = $utils->pwdHash($_POST['pwd']);
            $vcode = $utils->createVerificationCode();
            $result = $db->prepare('INSERT INTO `auth_users` (`email`, `pwdhash`, `status`, `verify_hash`) VALUES (:email, :pwdhash, \'unverified\', :vcode);');
            if (!$result->execute(array(':email' => $_POST['email'], ':pwdhash' => $newHash, ':vcode' => $vcode))) {
              $utils->log('user_insert_failure', 'email: '.$_POST['email'].' - '.$result->errorInfo()[2]);
              $errors[] = _('Could not add user.').' '._('Please <a href="https://www.kairo.at/contact">contact KaiRo.at</a> and tell the team about this.');
            }
            $user = array('id' => $db->lastInsertId(),
                          'email' => $_POST['email'],
                          'pwdhash' => $newHash,
                          'status' => 'unverified',
                          'verify_hash' => $vcode);
            $utils->log('new_user', 'user: '.$user['id'].', email: '.$user['email']);
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
            $mail->addMailText($utils->getDomainBaseURL().strstr($_SERVER['REQUEST_URI'], '?', true)
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
              $utils->log('verify_mail_failure', 'user: '.$user['id'].', email: '.$user['email']);
              $errors[] = _('The confirmation email could not be sent to you.').' '._('Please <a href="https://www.kairo.at/contact">contact KaiRo.at</a> and tell the team about this.');
            }
          }
          else {
            // Password reset requested with "Password forgotten?" function.
            $vcode = $utils->createVerificationCode();
            $result = $db->prepare('UPDATE `auth_users` SET `verify_hash` = :vcode WHERE `id` = :userid;');
            if (!$result->execute(array(':vcode' => $vcode, ':userid' => $user['id']))) {
              $utils->log('vhash_set_failure', 'user: '.$user['id']);
              $errors[] = _('Could not initiate reset request.').' '._('Please <a href="https://www.kairo.at/contact">contact KaiRo.at</a> and tell the team about this.');
            }
            else {
              $utils->log('pwd_reset_request', 'user: '.$user['id'].', email: '.$user['email']);
              $resetcode = $vcode.dechex($user['id'] + $session['id']).'_'.$utils->createTimeCode($session, null, 60);
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
              $mail->addMailText($utils->getDomainBaseURL().strstr($_SERVER['REQUEST_URI'], '?', true)
                                .'?email='.rawurlencode($user['email']).'&reset_code='.rawurlencode($resetcode)."\n\n");
              $mail->addMailText(_('If you do not call this confirmation link within 1 hour, this link expires and the existing password is being kept in place.')."\n\n");
              $mail->addMailText(sprintf(_('The %s team'), 'KaiRo.at'));
              //$mail->setDebugAddress("robert@localhost");
              $mailsent = $mail->send();
              if ($mailsent) {
                $pagetype = 'resetmail_sent';
              }
              else {
                $utils->log('pwd_reset_mail_failure', 'user: '.$user['id'].', email: '.$user['email']);
                $errors[] = _('The email with password reset instructions could not be sent to you.').' '._('Please <a href="https://www.kairo.at/contact">contact KaiRo.at</a> and tell the team about this.');
              }
            }
          }
        }
      }
      if (!count($errors) && ($addgroup > 0)) {
        // We should add the login email to the group of that existing user.
        $result = $db->prepare('SELECT `group_id` FROM `auth_users` WHERE `id` = :userid;');
        $result->execute(array(':userid' => $addgroup));
        $grpuser = $result->fetch(PDO::FETCH_ASSOC);
        if (!intval($grpuser['group_id'])) {
          // If that user doesn't have a group, put him into a group with his own user ID.
          $result = $db->prepare('UPDATE `auth_users` SET `group_id` = :groupid WHERE `id` = :userid;');
          if (!$result->execute(array(':groupid' => $addgroup, ':userid' => $addgroup))) {
            $utils->log('group_save_failure', 'user: '.$addgroup);
          }
          else {
            $utils->log('new grouping', 'user: '.$addgroup.', group: '.$addgroup);
          }
        }
        // Save grouping for the new or logged-in user.
        $result = $db->prepare('UPDATE `auth_users` SET `group_id` = :groupid WHERE `id` = :userid;');
        if (!$result->execute(array(':groupid' => $addgroup, ':userid' => $user['id']))) {
          $utils->log('group_save_failure', 'user: '.$user['id']);
        }
        else {
          $utils->log('new grouping', 'user: '.$user['id'].', group: '.$addgroup);
          $user['group_id'] = $addgroup;
        }
      }
    }
    else {
      $errors[] = _('The form you used was not valid. Possibly it has expired and you need to initiate the action again, or you have disabled cookies for this site.');
    }
  }
  elseif (array_key_exists('reset', $_GET)) {
    if ($session['logged_in']) {
      $result = $db->prepare('SELECT `id`,`email` FROM `auth_users` WHERE `id` = :userid;');
      $result->execute(array(':userid' => $session['user']));
      $user = $result->fetch(PDO::FETCH_ASSOC);
      if (!$user['id']) {
        $utils->log('reset_user_read_failure', 'user: '.$session['user']);
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
        $utils->log('verification_save_failure', 'user: '.$user['id']);
        $errors[] = _('Could not save confirmation.').' '._('Please <a href="https://www.kairo.at/contact">contact KaiRo.at</a> and tell the team about this.');
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
              $utils->verifyTimeCode($regs[3], $session, 60)) {
            // Set a new verify_hash for the actual password reset.
            $user['verify_hash'] = $utils->createVerificationCode();
            $result = $db->prepare('UPDATE `auth_users` SET `verify_hash` = :vcode WHERE `id` = :userid;');
            if (!$result->execute(array(':vcode' => $user['verify_hash'], ':userid' => $user['id']))) {
              $utils->log('vhash_reset_failure', 'user: '.$user['id']);
            }
            $result = $db->prepare('UPDATE `auth_sessions` SET `user` = :userid WHERE `id` = :sessid;');
            if (!$result->execute(array(':userid' => $user['id'], ':sessid' => $session['id']))) {
              $utils->log('reset_session_set_user_failure', 'session: '.$session['id']);
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
  elseif (array_key_exists('clients', $_GET)) {
    $result = $db->prepare('SELECT `id`,`email` FROM `auth_users` WHERE `id` = :userid;');
    $result->execute(array(':userid' => $session['user']));
    $user = $result->fetch(PDO::FETCH_ASSOC);
    if ($session['logged_in'] && $user['id']) {
      if (array_key_exists('client_id', $_POST) && (strlen($_POST['client_id']) >= 5)) {
        $clientid = $_POST['client_id'];
        $clientsecret = $utils->createClientSecret();
        $rediruri = strval(@$_POST['redirect_uri']);
        $scope = strval(@$_POST['scope']);
        $result = $db->prepare('INSERT INTO `oauth_clients` (`client_id`, `client_secret`, `redirect_uri`, `scope`, `user_id`) VALUES (:clientid, :secret, :rediruri, :scope, :userid);');
        if (!$result->execute(array(':clientid' => $clientid,
                                    ':secret' => $clientsecret,
                                    ':rediruri' => $rediruri,
                                    ':scope' => $scope,
                                    ':userid' => $user['id']))) {
          $utils->log('client_save_failure', 'client: '.$clientid);
          $errors[] = _('Unexpectedly failed to save new client information.').' '._('Please <a href="https://www.kairo.at/contact">contact KaiRo.at</a> and tell the team about this.');
        }
      }
      if (!count($errors)) {
        // List clients
        $result = $db->prepare('SELECT `client_id`,`client_secret`,`redirect_uri`,`scope` FROM `oauth_clients` WHERE `user_id` = :userid;');
        $result->execute(array(':userid' => $user['id']));
        $clients = $result->fetchAll(PDO::FETCH_ASSOC);
        if (!$clients) { $clients = array(); }
        $pagetype = 'clientlist';
      }
    }
    else {
      $errors[] = _('This function is only available if you are logged in.');
    }
  }
  elseif (intval($session['user'])) {
    $result = $db->prepare('SELECT `id`,`email`,`verify_hash`,`group_id` FROM `auth_users` WHERE `id` = :userid;');
    $result->execute(array(':userid' => $session['user']));
    $user = $result->fetch(PDO::FETCH_ASSOC);
    if (!$user['id']) {
      $utils->log('user_read_failure', 'user: '.$session['user']);
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
      if (!count($errors) && !$utils->verifyTimeCode($_POST['tcode'], $session)) {
        $errors[] = _('Password reset failed. The reset form you used was not valid. Possibly it has expired and you need to initiate the password reset again.');
      }
      $errors += $utils->checkPasswordConstraints(strval($_POST['pwd']), $user['email']);
      if (!count($errors)) {
        $newHash = $utils->pwdHash($_POST['pwd']);
        $result = $db->prepare('UPDATE `auth_users` SET `pwdhash` = :pwdhash, `verify_hash` = \'\' WHERE `id` = :userid;');
        if (!$result->execute(array(':pwdhash' => $newHash, ':userid' => $session['user']))) {
          $utils->log('pwd_reset_failure', 'user: '.$session['user']);
          $errors[] = _('Password reset failed.').' '._('Please <a href="https://www.kairo.at/contact">contact KaiRo.at</a> and tell the team about this.');
        }
        else {
          $pagetype = 'reset_done';
        }
      }
    }
    else {
      $utils->doRedirectIfSet($session);
    }
  }
}

if (!count($errors)) {
  if ($pagetype == 'verification_sent') {
    $para = $body->appendElement('p', sprintf(_('An email for confirmation has been sent to %s. Please follow the link provided there to complete the process.'), $user['email']));
    $para->setAttribute('class', 'verifyinfo pending');
    $para = $body->appendElement('p', _('Reload this page after you confirm to continue.'));
    $para->setAttribute('class', 'verifyinfo pending');
    $para = $body->appendElement('p');
    $para->setAttribute('class', 'verifyinfo pending');
    $link = $para->appendLink('./', _('Reload'));
  }
  elseif ($pagetype == 'resetmail_sent') {
    $para = $body->appendElement('p',
        _('An email has been sent to the requested account with further information. If you do not receive an email then please confirm you have entered the same email address used during account registration.'));
    $para->setAttribute('class', 'resetinfo pending');
    $para = $body->appendElement('p');
    $para->setAttribute('class', 'resetinfo pending small');
    $link = $para->appendLink('./', _('Back to top'));
  }
  elseif ($pagetype == 'resetstart') {
    $para = $body->appendElement('p', _('If you forgot your password or didn\'t receive the registration confirmation, please enter your email here.'));
    $para->setAttribute('class', '');
    $form = $body->appendForm('./?reset', 'POST', 'resetform');
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
    $litem->appendInputHidden('tcode', $utils->createTimeCode($session));
    $submit = $litem->appendInputSubmit(_('Send instructions to email'));
    $para = $form->appendElement('p');
    $para->setAttribute('class', 'toplink small');
    $link = $para->appendLink('./', _('Cancel'));
  }
  elseif ($pagetype == 'resetpwd') {
    $para = $body->appendElement('p', sprintf(_('You can set a new password for %s here.'), $user['email']));
    $para->setAttribute('class', 'newpwdinfo');
    $form = $body->appendForm('./', 'POST', 'newpwdform');
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
    $litem->appendInputHidden('tcode', $utils->createTimeCode($session));
    if (!$session['logged_in'] && strlen(@$user['verify_hash'])) {
      $litem->appendInputHidden('vcode', $user['verify_hash']);
    }
    $submit = $litem->appendInputSubmit(_('Save password'));
    $para = $form->appendElement('p');
    $para->setAttribute('class', 'toplink small');
    $link = $para->appendLink('./', _('Cancel'));
  }
  elseif ($pagetype == 'clientlist') {
    $scopes = array('clientreg', 'email');
    $form = $body->appendForm('?clients', 'POST', 'newclientform');
    $form->setAttribute('id', 'clientform');
    $tbl = $form->appendElement('table');
    $tbl->setAttribute('class', 'clientlist border');
    $thead = $tbl->appendElement('thead');
    $trow = $thead->appendElement('tr');
    $trow->appendElement('th', _('Client ID'));
    $trow->appendElement('th', _('Client Secrect'));
    $trow->appendElement('th', _('Redirect URI'));
    $trow->appendElement('th', _('Scope'));
    $trow->appendElement('th');
    $tbody = $tbl->appendElement('tbody');
    foreach ($clients as $client) {
      $trow = $tbody->appendElement('tr');
      $trow->appendElement('td', $client['client_id']);
      $trow->appendElement('td', $client['client_secret']);
      $trow->appendElement('td', $client['redirect_uri']);
      $trow->appendElement('td', $client['scope']);
      $trow->appendElement('td'); // Future: Delete link?
    }
    // Form fields for adding a new one.
    $tfoot = $tbl->appendElement('tfoot');
    $trow = $tfoot->appendElement('tr');
    $cell = $trow->appendElement('td');
    $inptxt = $cell->appendInputText('client_id', 80, 25, 'client_id');
    $cell = $trow->appendElement('td'); // Empty, as secret will be generated.
    $cell = $trow->appendElement('td');
    $inptxt = $cell->appendInputText('redirect_uri', 500, 50, 'redirect_uri');
    $cell = $trow->appendElement('td');
    $select = $cell->appendElementSelect('scope');
    foreach ($scopes as $scope) {
      $select->appendElementOption($scope, $scope);
    }
    //$inptxt = $cell->appendInputText('scope', 100, 20, 'scope');
    $cell = $trow->appendElement('td');
    $submit = $cell->appendInputSubmit(_('Create'));
    $para = $form->appendElement('p');
    $para->setAttribute('class', 'toplink');
    $link = $para->appendLink('./', _('Back to top'));
  }
  elseif ($session['logged_in'] && (!array_key_exists('addemail', $_GET))) {
    if ($pagetype == 'reset_done') {
      $para = $body->appendElement('p', _('Your password has successfully been reset.'));
      $para->setAttribute('class', 'resetinfo done');
    }
    $div = $body->appendElement('div', $user['email']);
    $div->setAttribute('class', 'loginheader');
    $groupmails = $utils->getGroupedEmails($user['group_id'], $user['email']);
    if (count($groupmails)) {
      $para = $div->appendElement('p', _('Grouped with: ').implode(', ', $groupmails));
      $para->setAttribute('class', 'small groupmails');
    }
    $div = $body->appendElement('div');
    $div->setAttribute('class', 'loginlinks');
    $ulist = $div->appendElement('ul');
    $ulist->setAttribute('class', 'flat');
    $litem = $ulist->appendElement('li');
    $link = $litem->appendLink('./?logout', _('Log out'));
    $litem = $ulist->appendElement('li');
    $link = $litem->appendLink('./?addemail', _('Add another email address'));
    if (in_array($user['email'], $utils->client_reg_email_whitelist)) {
      $litem = $ulist->appendElement('li');
      $link = $litem->appendLink('./?clients', _('Manage OAuth2 clients'));
    }
    $litem = $ulist->appendElement('li');
    $litem->appendLink('./?reset', _('Set new password'));
  }
  else { // not logged in
    $addfields = array();
    if ($pagetype == 'verification_done') {
      $para = $body->appendElement('p', _('Hooray! Your email was successfully confirmed! You can log in now.'));
      $para->setAttribute('class', 'verifyinfo done');
    }
    elseif ($pagetype == 'reset_done') {
      $para = $body->appendElement('p', _('Your password has successfully been reset. You can log in now with the new password.'));
      $para->setAttribute('class', 'resetinfo done');
    }
    elseif (array_key_exists('addemail', $_GET)) {
      $para = $body->appendElement('p', sprintf(_('Add another email grouped with %s by either logging in with it or specifying the email and a new password to use.'), $user['email']));
      $para->setAttribute('class', 'addemailinfo');
      $addfields['grouptoexisting'] = '1';
    }
    $utils->appendLoginForm($body, $session, $user, $addfields);
  }
}

if (count($errors)) {
  $body->appendElement('p', ((count($errors) <= 1)
                            ?_('The following error was detected')
                            :_('The following errors were detected')).':');
  $list = $body->appendElement('ul');
  $list->setAttribute('class', 'flat warn');
  foreach ($errors as $msg) {
    $item = $list->appendElement('li');
    $item->appendHTMLMarkup($msg);
  }
  $body->appendButton(_('Back'), 'history.back();');
}

// Send HTML to client.
print($document->saveHTML());
?>
