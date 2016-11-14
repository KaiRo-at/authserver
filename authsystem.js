/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

window.onload = function() {
  var jsWarning = document.getElementById("jswarning");
  if (jsWarning) {
    if (jsWarning.classList) {
      jsWarning.classList.add("hidden");
    }
    else {
      // IE9 or older (sigh)
      jsWarning.setAttribute("class", "warn hidden");
    }
  }
  var loginForm = document.getElementById("loginform");
  if (loginForm) {
    if (loginForm.classList) {
      loginForm.classList.remove("hidden");
    }
    else {
      // IE9 or older (sigh)
      loginForm.setAttribute("class", "loginarea");
    }
  }
}
