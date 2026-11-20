/* Where the local backend (server.py) runs, and how to call it. Set in
   Settings → Backend: the address is stored as backendUrl, and the optional
   access token (needed when the backend was started with VEILUX_TOKEN) as
   backendToken. Every request to the backend goes through fetch() below. */
globalThis.VeiluxBackend = (() => {
  // server.py listens here unless started with --host/--port.
  const DEFAULT = 'http://localhost:8000';

  // Accepts "localhost:8100" or a full address; returns "" when it is not a usable HTTP(S) address.
  function normalize(value) {
    const raw = String(value || '').trim();
    if (!raw) return '';
    try {
      const url = new URL(raw.includes('://') ? raw : 'http://' + raw);
      if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) return '';
      return (url.origin + url.pathname).replace(/\/+$/, '');
    } catch (_) { return ''; }
  }

  async function base() {
    try {
      const { backendUrl } = await browser.storage.local.get('backendUrl');
      return normalize(backendUrl) || DEFAULT;
    } catch (_) { return DEFAULT; }
  }

  async function url(path = '') { return (await base()) + path; }

  async function token() {
    try {
      const { backendToken } = await browser.storage.local.get('backendToken');
      return String(backendToken || '').trim();
    } catch (_) { return ''; }
  }

  // Sends the access token in its own header, and only to the backend.
  function withToken(init, key) {
    if (!key) return init;
    const headers = new Headers(init.headers || {});
    headers.set('X-Veilux-Token', key);
    return { ...init, headers };
  }

  async function request(path, init = {}) {
    return fetch(await url(path), withToken(init, await token()));
  }

  return { DEFAULT, normalize, base, url, token, withToken, fetch: request };
})();
