// Lightweight, privacy-first usage analytics (Aptabase).
//
// This is a tiny first-party implementation of the Aptabase ingestion
// protocol (https://aptabase.com) so we don't have to ship a third-party
// script or a build step. It sends only anonymous *usage* data:
//
//   - No cookies, no localStorage, no persistent identifiers.
//   - The session id lives only in memory and is regenerated after an hour of
//     inactivity, so visitors are never linked across visits or over time.
//   - We never send anything that identifies a person. (Aptabase derives
//     coarse country/OS/browser from the request on the server side; that is
//     not personal data and needs no consent banner under GDPR.)
//
// Because nothing is stored on the visitor's device and no individual is
// identified, this needs no cookie/consent banner.

(function () {
  const APP_KEY = "A-SH-5537273296";
  const HOST = "https://metrics.snowskeleton.net";
  const API_URL = HOST + "/api/v0/event";
  const SDK_VERSION = "digplusplus-web@1.0.0";
  const SESSION_TIMEOUT_S = 60 * 60; // 1h of inactivity starts a fresh session

  let sessionId = newSessionId();
  let lastTouched = Date.now();

  function newSessionId() {
    const epoch = Math.floor(Date.now() / 1000).toString();
    const rand = Math.floor(Math.random() * 1e8)
      .toString()
      .padStart(8, "0");
    return epoch + rand;
  }

  function currentSession() {
    const now = Date.now();
    if ((now - lastTouched) / 1000 > SESSION_TIMEOUT_S) {
      sessionId = newSessionId();
    }
    lastTouched = now;
    return sessionId;
  }

  function locale() {
    if (typeof navigator === "undefined") return "";
    if (navigator.languages && navigator.languages.length) return navigator.languages[0];
    return navigator.language || "";
  }

  function isDebug() {
    return location.hostname === "localhost" || location.hostname === "127.0.0.1";
  }

  // Fire-and-forget. Analytics must never surface an error to the user or
  // interfere with a lookup, so failures are swallowed silently.
  window.track = function track(eventName, props) {
    let body;
    try {
      body = JSON.stringify({
        timestamp: new Date().toISOString(),
        sessionId: currentSession(),
        eventName: eventName,
        systemProps: {
          locale: locale(),
          isDebug: isDebug(),
          appVersion: "",
          sdkVersion: SDK_VERSION,
        },
        props: props || undefined,
      });
    } catch (err) {
      return;
    }

    try {
      fetch(API_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json", "App-Key": APP_KEY },
        credentials: "omit",
        keepalive: true,
        body: body,
      }).catch(function () {});
    } catch (err) {
      /* ignore */
    }
  };
})();
