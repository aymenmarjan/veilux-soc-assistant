/**
 * Minimal cross-browser shim.
 * Firefox and Safari already expose a native, promise-based `browser` global.
 * Chromium browsers (Chrome, Edge, Brave, Opera, Vivaldi) only expose `chrome`,
 * but their `chrome.*` methods already return a Promise when the callback is
 * omitted, so a plain alias is enough to make the rest of the extension code
 * (written against `browser.*`) work everywhere without duplicating logic.
 */
if (typeof globalThis.browser === 'undefined') {
  globalThis.browser = globalThis.chrome;
}
