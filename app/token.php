<?php
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

// Called with e.g. curl .../token -d 'grant_type=authorization_code&client_id=testclient&client_secret=testpass&code=&state=f00bar&redirect_uri=http%3A%2F%2Ffake.example.com%2F'
// Response is always JSON.

// Include the common auth system files (including the OAuth2 Server object).
require_once(__DIR__.'/authsystem.inc.php');
if ($settings['piwik_enabled']) {
  // We do not send out an HTML file, so we need to do the Piwik tracking ourselves.
  require_once($settings['piwik_tracker_path'].'PiwikTracker.php');
  PiwikTracker::$URL = ((strpos($settings['piwik_url'], '://') === false) ? 'http://localhost' : '' ).$settings['piwik_url'];
  $piwikTracker = new PiwikTracker($idSite = $settings['piwik_site_id']);
  $piwikTracker->doTrackPageView('Token Request');
}

$errors = $utils->checkForSecureConnection();

if (!count($errors)) {
  // Handle a request for an OAuth2.0 Access Token and send the response to the client
  $server->handleTokenRequest(OAuth2\Request::createFromGlobals())->send();
}
else {
  print(json_encode(array('error' => 'insecure_connection',
                          'error_description' => 'Your connection is insecure. Token requests can only be made on secure connections.')));
}
?>
