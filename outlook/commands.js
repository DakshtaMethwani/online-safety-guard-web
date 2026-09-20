/* Online Safety Guard - Outlook function file.
 * Declared by the manifest's <FunctionFile>. The add-in declares no function
 * commands yet (the ribbon button opens the task pane), so this only keeps the
 * host happy and provides a place for future UI-less commands.
 */
(function () {
  "use strict";

  function ready() {
    // Associate future function commands here, e.g.:
    //   Office.actions.associate("AnalyzeMessage", analyzeMessage);
  }

  if (typeof Office !== "undefined" && Office.onReady) {
    Office.onReady(function () { ready(); });
  } else if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", ready);
  } else {
    ready();
  }
})();
