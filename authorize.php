<?php
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

// Called e.g. as /authorize?response_type=code&client_id=testclient&state=f00bar&scope=email&redirect_uri=http%3A%2F%2Ffake.example.com%2F
// This either redirects to the redirect URL with errors or success added as GET parameters,
// or sends a HTML page asking for login / permission to scope (email is always granted in this system but not always for OAuth2 generically)
// or sends errors as a JSOn document (hopefully shouldn't but seen that in testing).

// Include the common auth system files (including the OAuth2 Server object).
require_once(__DIR__.'/authsystem.inc.php');

// Start HTML document as a DOM object.
extract(ExtendedDocument::initHTML5()); // sets $document, $html, $head, $title, $body
$document->formatOutput = true; // we want a nice output
$style = $head->appendElement('link');
$style->setAttribute('rel', 'stylesheet');
$style->setAttribute('href', 'authsystem.css');
$head->appendJSFile('authsystem.js');
$title->appendText('Authorization Request | KaiRo.at');
$h1 = $body->appendElement('h1', 'KaiRo.at Authentication Server');

$errors = $utils->checkForSecureConnection();

$para = $body->appendElement('p', _('This login system does not work without JavaScript. Please activate JavaScript for this site to log in.'));
$para->setAttribute('id', 'jswarning');
$para->setAttribute('class', 'warn');

if (!count($errors)) {
  $session = $utils->initSession(); // Read session or create new session and set cookie.
  if (intval($session['user'])) {
    $result = $db->prepare('SELECT `id`,`email`,`verify_hash` FROM `auth_users` WHERE `id` = :userid;');
    $result->execute(array(':userid' => $session['user']));
    $user = $result->fetch(PDO::FETCH_ASSOC);
    if (!$user['id']) {
      $utils->log('user_read_failure', 'user: '.$session['user']);
    }
  }
  else {
    $user = array('id' => 0, 'email' => '');
  }
  $pagetype = 'default';
  if (is_null($session)) {
    $errors[] = _('The session system is not working. Please <a href="https://www.kairo.at/contact">contact KaiRo.at</a> and tell the team about this.');
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

    // Display an authorization form.
    if (empty($_POST)) {
      $para = $body->appendElement('p', sprintf(_('Hi %s!'), $user['email']));
      $para->setAttribute('class', 'userwelcome');

      $form = $body->appendForm('', 'POST', 'authform');
      $form->setAttribute('id', 'authform');
      $form->appendElement('p', sprintf(_('Do you authorize %s to access %s?'), $request->query['client_id'], $request->query['scope']));
      $submit = $form->appendInputSubmit(_('yes'));
      $submit->setAttribute('name', 'authorized');
      $form->appendText(' ');
      $submit = $form->appendInputSubmit(_('no'));
      $submit->setAttribute('name', 'authorized');
    }
    else {
      // Handle authorize request, forwarding code in GET parameters if the user has authorized your client.
      $is_authorized = ($_POST['authorized'] === 'yes');
      $server->handleAuthorizeRequest($request, $response, $is_authorized);
      /* For testing only
      if ($is_authorized) {
        // this is only here so that you get to see your code in the cURL request. Otherwise, we'd redirect back to the client
        $code = substr($response->getHttpHeader('Location'), strpos($response->getHttpHeader('Location'), 'code=')+5, 40);
        exit("SUCCESS! Authorization Code: $code");
      }
      */
      $response->send();
      exit();
    }
  }
  else {
    // Display login/register form.
    $para = $body->appendElement('p', _('You need to log in or register to continue.'));
    $para->setAttribute('class', 'logininfo');
    $utils->appendLoginForm($body, $session, $user);
    // Save the request in the session so we can get back to fulfilling it.
    $result = $db->prepare('UPDATE `auth_sessions` SET `saved_redirect` = :redir WHERE `id` = :sessid;');
    if (!$result->execute(array(':redir' => $_SERVER['REQUEST_URI'], ':sessid' => $session['id']))) {
      $utils->log('redir_save_failure', 'session: '.$session['id'].', redirect: '.$_SERVER['REQUEST_URI']);
    }
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
