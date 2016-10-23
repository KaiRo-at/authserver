<?php
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

// Include the common auth system files (including the OAuth2 Server object).
require_once(__DIR__.'/authsystem.inc.php');

// Start HTML document as a DOM object.
extract(ExtendedDocument::initHTML5()); // sets $document, $html, $head, $title, $body
$document->formatOutput = true; // we want a nice output

$style = $head->appendElement('link');
$style->setAttribute('rel', 'stylesheet');
$style->setAttribute('href', 'authsystem.css');

$title->appendText('KaiRo.at Authentication Server');
$h1 = $body->appendElement('h1', 'KaiRo.at Authentication Server');

$logged_in = false;
$user_id = 0;
$user_email = '';

if ($logged_in) {
  $div = $body->appendElement('div', $user_email);
  $div->setAttribute('class', 'loginheader');
  $div = $body->appendElement('div');
  $div->setAttribute('class', 'loginlinks');
  $link = $div->appendLink('?logout', _('Log out'));
  $link->setAttribute('title', _('Log out user of the system'));
}
else { // not logged in
  $form = $body->appendForm('#', 'POST', 'loginform');
  $form->setAttribute('class', 'loginarea');
  $label = $form->appendLabel('login_email', _('Email').':');
  $label->setAttribute('id', 'emailprompt');
  $label->setAttribute('class', 'loginprompt');
  $inptxt = $form->appendInputText('form[email]', 30, 20, 'login_email', (intval($user_id)?$user_email:''));
  $inptxt->setAttribute('class', 'login');
  $form->appendElement('br');
  $label = $form->appendLabel('login_pwd', _('Password').':');
  $label->setAttribute('id', 'pwdprompt');
  $label->setAttribute('class', 'loginprompt');
  $inptxt = $form->appendInputPassword('form[pwd]', 20, 20, 'login_pwd', '');
  $inptxt->setAttribute('class', 'login');
  $form->appendElement('br');
  $cbox = $form->appendInputCheckbox('form[remember]', 'login_remember', 'true', false);
  $cbox->setAttribute('class', 'logincheck');
  $label = $form->appendLabel('login_remember', _('Remember me'));
  $label->setAttribute('id', 'rememprompt');
  $label->setAttribute('class', 'loginprompt');
  $form->appendElement('br');
  $submit = $form->appendInputSubmit(_('Log in'));
  $submit->setAttribute('class', 'loginbutton');
}

// Send HTML to client.
print($document->saveHTML());
?>
