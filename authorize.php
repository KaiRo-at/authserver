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

$errors = $utils->checkForSecureConnection();

$request = OAuth2\Request::createFromGlobals();
$response = new OAuth2\Response();

// Validate the authorize request.
if (!$server->validateAuthorizeRequest($request, $response)) {
  $response->send();
  exit();
}

// Display an authorization form.
if (empty($_POST)) {
  // Start HTML document as a DOM object.
  extract(ExtendedDocument::initHTML5()); // sets $document, $html, $head, $title, $body
  $document->formatOutput = true; // we want a nice output
  $style = $head->appendElement('link');
  $style->setAttribute('rel', 'stylesheet');
  $style->setAttribute('href', 'authsystem.css');
  $head->appendJSFile('authsystem.js');
  $title->appendText('Authorization Request | KaiRo.at');
  $h1 = $body->appendElement('h1', 'KaiRo.at Authentication Server');

  $para = $body->appendElement('p', _('This login system does not work without JavaScript. Please activate JavaScript for this site to log in.'));
  $para->setAttribute('id', 'jswarning');
  $para->setAttribute('class', 'warn');

  $form = $body->appendForm('', 'POST', 'authform');
  $form->setAttribute('id', 'authform');
  $form->appendElement('p', sprintf(_('Do you authorize %s to access %s?'), $request->query['client_id'], $request->query['scope']));
  $submit = $form->appendInputSubmit(_('yes'));
  $submit->setAttribute('name', 'authorized');
  $form->appendText(' ');
  $submit = $form->appendInputSubmit(_('no'));
  $submit->setAttribute('name', 'authorized');
  // Send HTML to client.
  print($document->saveHTML());
  exit();
}

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
?>
