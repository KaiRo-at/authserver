// Piwik code - licensed under Public Domain.
  var _paq = _paq || [];
  _paq.push(['trackPageView']);
  _paq.push(['enableLinkTracking']);
  (function() {
    var d=document, g=d.createElement('script'), s=d.getElementsByTagName('script')[0];
    // dataset does not work with IE10 or lower :(
    var u=s.parentNode.dataset.piwikurl;
    _paq.push(['setTrackerUrl', u+'piwik.php']);
    _paq.push(['setSiteId', s.parentNode.dataset.piwiksite]);
    g.type='text/javascript'; g.async=true; g.defer=true; g.src=u+'piwik.js'; s.parentNode.insertBefore(g,s);
  })();
// End Piwik code
