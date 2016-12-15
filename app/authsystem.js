/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

// Call initElements at the earliest possible stage after parsing the document.
if (window.addEventListener) { window.addEventListener("DOMContentLoaded", initElements, false); }
else { window.onload = initElements; }

function initElements() {
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
  var cancelAuth = document.getElementById("cancelauth");
  if (cancelAuth) {
    cancelAuth.onclick = function() {
      document.getElementById("isauthorized").value = "no";
      document.getElementById("authform").submit();
    }
  }
  var addAnotherEmail = document.getElementById("addanotheremail");
  if (addAnotherEmail) {
    addAnotherEmail.onclick = function() {
      location.href = "./?addemail";
    }
  }
  var isNotMe = document.getElementById("isnotme");
  if (isNotMe) {
    isNotMe.onclick = function() {
      location.href = location.href + "&logout=1";
    }
  }
}
