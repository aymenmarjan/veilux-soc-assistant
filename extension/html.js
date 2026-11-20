/* Puts markup that VEILUX builds into an extension page.

   Every value that comes from logs, AI answers, settings or outside services
   is escaped (escapeHtml) before it is placed in that markup. The markup is
   parsed with DOMParser in a separate, inert document and its nodes are moved
   in: nothing in it runs, and extension pages forbid inline scripts and
   event attributes in any case. */
globalThis.setHTML = function setHTML(element, html) {
  const parsed = new DOMParser().parseFromString('<!doctype html><body>' + String(html), 'text/html');
  element.replaceChildren(...parsed.body.childNodes);
};
