/* Local analytics stub for the Bharat Bazaar fixture.
 *
 * Served from this application's own origin, and referenced by a page only once
 * analytics consent has been recorded. It contacts nothing: there is no vendor
 * snippet, no tag manager, no pixel and no beacon anywhere in this application, so
 * there is nothing that could fire before a visitor has chosen.
 *
 * The counting that matters happens on the server, inside the request that rendered
 * the page, and only after the same consent has been read back from the consent
 * record. This file exists so that the browser side of an opt in is visible rather
 * than implied.
 */
(function () {
  "use strict";

  var seen = 0;

  function noteInteraction(kind) {
    // Held in memory for the life of the page and then discarded. Nothing is put in
    // browser storage and nothing is transmitted anywhere.
    seen += 1;
    if (window.console && window.console.debug) {
      window.console.debug("[analytics stub] local only, no request sent:", kind, seen);
    }
  }

  document.addEventListener("click", function (event) {
    var target = event.target;
    if (target && target.tagName === "A") {
      noteInteraction("link");
    }
  });

  noteInteraction("page");
})();
