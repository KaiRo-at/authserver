// Piwik code - licensed under Public Domain.
  var _paq = _paq || [];
  _paq.push(['trackPageView']);
  _paq.push(['enableLinkTracking']);
  (function() {
    var d=document, g=d.createElement('script'), s=d.getElementsByTagName('script')[0];
    // dataset does not work with IE10 or lower, so work around it with .getAttribute() :(
    var u=(s.parentNode.dataset?s.parentNode.dataset.piwikurl:s.parentNode.getAttribute('data-piwikurl'));
    _paq.push(['setTrackerUrl', u+'piwik.php']);
    _paq.push(['setSiteId', (s.parentNode.dataset?s.parentNode.dataset.piwiksite:s.parentNode.getAttribute('data-piwiksite'))]);
    g.type='text/javascript'; g.async=true; g.defer=true; g.src=u+'piwik.js'; s.parentNode.insertBefore(g,s);
  })();
// End Piwik code
