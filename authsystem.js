/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

window.onload = function() {
  var jsWarning = document.getElementById("jswarning");
  if (jsWarning) {
    document.getElementById("jswarning").classList.add("hidden");
  }
  var loginForm = document.getElementById("loginform");
  if (loginForm) {
    loginForm.classList.remove("hidden");
  }
}
