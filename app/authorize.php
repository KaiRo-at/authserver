<?php
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

// Called e.g. as /authorize?response_type=code&client_id=testclient&state=f00bar&scope=email&redirect_uri=http%3A%2F%2Ffake.example.com%2F
// This either redirects to the redirect URL with errors or success added as GET parameters,
// or sends a HTML page asking for login / permission to scope (email is always granted in this system but not always for OAuth2 generically)
// or sends errors as a JSON document (hopefully shouldn't but seen that in testing).

// Include the common auth system files (including the OAuth2 Server object).
require_once(__DIR__.'/authsystem.inc.php');

$errors = $utils->checkForSecureConnection();
$utils->sendSecurityHeaders();

// Initialize the HTML document with our basic elements.
extract($utils->initHTMLDocument(sprintf(_('Authorization Request | %s'), $utils->settings['operator_name']),
                                 sprintf(_('%s Authentication Server'), $utils->settings['operator_name']))); // sets $document, $html, $head, $title, $body

if (!count($errors)) {
  $session = $utils->initSession(); // Read session or create new session and set cookie.
  if ($session['logged_in'] && (@$_GET['logout'] == 1)) {
    $result = $db->prepare('UPDATE `auth_sessions` SET `logged_in` = FALSE WHERE `id` = :sessid;');
    if (!$result->execute(array(':sessid' => $session['id']))) {
      $utils->log('logout_failure', 'session: '.$session['id']);
      $errors[] = _('Unexpected error while logging out.');
    }
    $session['logged_in'] = 0;
  }
  if (intval($session['user'])) {
    $result = $db->prepare('SELECT `id`,`email`,`verify_hash`,`group_id` FROM `auth_users` WHERE `id` = :userid;');
    $result->execute(array(':userid' => $session['user']));
    $user = $result->fetch(PDO::FETCH_ASSOC);
    if (!$user['id']) {
      $utils->log('user_read_failure', 'user: '.$session['user']);
    }
  }
  else {
    $user = array('id' => 0, 'email' => '');
  }
  if (is_null($session)) {
    $errors[] = _('The session system is not working.').' '
                .sprintf(_('Please <a href="%s">contact %s</a> and tell the team about this.'), $utils->settings['operator_contact_url'], $utils->settings['operator_name']);
  }
  elseif ($session['logged_in']) {
    // We are logged in, process authorization request.
    $request = OAuth2\Request::createFromGlobals();
    $response = new OAuth2\Response();

    // Validate the authorize request.
    if (!$server->validateAuthorizeRequest($request, $response)) {
      $response->send();
      exit();
    }

    $is_authorized = !array_key_exists('authorized', $_POST) ? null : (@$_POST['authorized'] === 'yes');

    if (is_null($is_authorized) && (@$request->query['scope'] != 'email')) {
      // Display an authorization form (unless the scope is email, which we handle as a login request below).
      $para = $body->appendElement('p', sprintf(_('Hi %s!'), $user['email']));
      $para->setAttribute('class', 'userwelcome');

      $form = $body->appendForm('', 'POST', 'authform');
      $form->setAttribute('id', 'authform');
      $domain_name = parse_url($request->query['redirect_uri'], PHP_URL_HOST);
      if (!strlen($domain_name)) { $domain_name = $request->query['client_id']; }
      $form->appendElement('p', sprintf(_('Do you authorize %s to access %s?'), $domain_name, $request->query['scope']));
      $authinput = $form->appendInputHidden('authorized', 'yes');
      $authinput->setAttribute('id', 'isauthorized');
      $submit = $form->appendInputSubmit(_('Yes'));
      $form->appendText(' ');
      $button = $form->appendButton(_('No'));
      $button->setAttribute('id', 'cancelauth');
    }
    elseif (@$request->query['scope'] == 'email') {
      // Display an interstitial page for a login  when we have email scope (verified email for logging in).
      $domain_name = parse_url($request->query['redirect_uri'], PHP_URL_HOST);
      if (!strlen($domain_name)) { $domain_name = $request->query['client_id']; }
      // If the referrer is from the auth system and we have a different domain to redirect to,
      // we can safely assume we just logged in with that email and skip the interstitial page.
      $refer_domain = parse_url($_SERVER['HTTP_REFERER'], PHP_URL_HOST);
      if (is_null($is_authorized) && ($refer_domain == $_SERVER['SERVER_NAME']) && ($refer_domain != $domain_name) &&
          (dirname($_SERVER['REQUEST_URI']) == dirname(parse_url($_SERVER['HTTP_REFERER'], PHP_URL_PATH)))) {
        $is_authorized = true;
      }
      if (is_null($is_authorized)) {
        $para = $body->appendElement('p', sprintf(_('Sign in to %s using…'), $domain_name));
        $para->setAttribute('class', 'signinwelcome');
        $form = $body->appendForm('', 'POST', 'authform');
        $form->setAttribute('id', 'authform');
        $form->setAttribute('class', 'loginarea');
        $ulist = $form->appendElement('ul');
        $ulist->setAttribute('class', 'flat emaillist');
        $emails = $utils->getGroupedEmails($user['group_id']);
        if (!count($emails)) { $emails = array($user['email']); }
        foreach ($emails as $email) {
          $litem = $ulist->appendElement('li');
          $litem->appendInputRadio('user_email', 'uemail_'.md5($email), $email, $email == $user['email']);
          $litem->appendLabel('uemail_'.md5($email), $email);
        }
        $para = $form->appendElement('p');
        $para->setAttribute('class', 'small otheremaillinks');
        $link = $para->appendLink('#', _('Add another email address'));
        $link->setAttribute('id', 'addanotheremail'); // Makes the JS put the right functionality onto the link.
        $para->appendText(' ');
        $link = $para->appendLink('#', _('This is not me'));
        $link->setAttribute('id', 'isnotme'); // Makes the JS put the right functionality onto the link.
        $authinput = $form->appendInputHidden('authorized', 'yes');
        $authinput->setAttribute('id', 'isauthorized');
        $submit = $form->appendInputSubmit(_('Sign in'));
        $para = $form->appendElement('p');
        $para->setAttribute('class', 'small');
        $link = $para->appendLink('#', _('Cancel'));
        $link->setAttribute('id', 'cancelauth'); // Makes the JS put the right functionality onto the link.
        $utils->setRedirect($session, $_SERVER['REQUEST_URI']);
      }
    }
    if (!is_null($is_authorized)) {
      // Switch to different user if we selected a different email within the group.
      if (strlen(@$_POST['user_email']) && ($_POST['user_email'] != $user['email'])) {
        $result = $db->prepare('SELECT `id`, `pwdhash`, `email`, `status`, `verify_hash`,`group_id` FROM `auth_users` WHERE `group_id` = :groupid AND `email` = :email;');
        $result->execute(array(':groupid' => $user['group_id'], ':email' => $_POST['user_email']));
        $newuser = $result->fetch(PDO::FETCH_ASSOC);
        if ($newuser) {
          $user = $newuser;
          $session = $utils->getLoginSession($user['id'], $session);
        }
      }
      if ($settings['piwik_enabled']) {
        // If we do not send out an HTML file, we need to do the Piwik tracking ourselves.
        require_once($settings['piwik_tracker_path'].'PiwikTracker.php');
        PiwikTracker::$URL = ((strpos($settings['piwik_url'], '://') === false) ? 'http://localhost' : '' ).$settings['piwik_url'];
        $piwikTracker = new PiwikTracker($idSite = $settings['piwik_site_id']);
        $piwikTracker->doTrackPageView('Handle Authorize Request');
      }
      // Handle authorize request, forwarding code in GET parameters if the user has authorized your client.
      $server->handleAuthorizeRequest($request, $response, $is_authorized, $user['id']);
      /* For testing only
      if ($is_authorized) {
        // this is only here so that you get to see your code in the cURL request. Otherwise, we'd redirect back to the client
        $code = substr($response->getHttpHeader('Location'), strpos($response->getHttpHeader('Location'), 'code=')+5, 40);
        exit("SUCCESS! Authorization Code: $code");
      }
      */
      $utils->resetRedirect($session);
      $response->send();
      exit();
    }
  }
  else {
    // Display login/register form.
    $para = $body->appendElement('p', _('You need to log in or register to continue.'));
    $para->setAttribute('class', 'logininfo');
    $utils->appendLoginForm($body, $session, $user);
    $utils->setRedirect($session, str_replace('&logout=1', '', $_SERVER['REQUEST_URI'])); // Make sure to strip a logout to not get into a loop.
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
