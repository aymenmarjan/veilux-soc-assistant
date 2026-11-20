// Extension APIs for a real DOM in a separate same-origin browser window.
// Production highlighter/controller code is evaluated unchanged. Record tab
// dispatches so wrong-tab tests prove no values were sent to that page.
({ script, source, fallback }) => {
  window.reviewDispatches = [];
  window.reviewTab = { id: 71, url: source.url, title: 'Captured security logs', active: true };
  window.reviewActiveTab = reviewTab;
  const sourceWindow = window.reviewSourceWindow;
  const frames = [sourceWindow, ...Array.from(sourceWindow.document.querySelectorAll('iframe'), frame => frame.contentWindow)];
  const connections = [], ports = [];
  frames.forEach((frame, i) => {
    if (fallback) frame.Highlight = undefined;
    connections[i] = [];
    frame.browser = { runtime: { onConnect: { addListener(fn) { connections[i].push(fn); } } } };
  });
  browser.tabs.query = async () => reviewActiveTab ? [reviewActiveTab] : [];
  browser.tabs.get = async id => { if (id !== reviewTab.id) throw new Error('Closed'); return reviewTab; };
  browser.tabs.connect = (tabId, options) => {
    reviewDispatches.push({ action: 'connect', tabId });
    const make = () => ({ listeners: [], disconnected: [], name: options.name,
      onMessage: { addListener(fn) { this.owner.listeners.push(fn); } },
      onDisconnect: { addListener(fn) { this.owner.disconnected.push(fn); } } });
    const popup = make(), content = make();
    for (const port of [popup, content]) { port.onMessage.owner = port; port.onDisconnect.owner = port; }
    let closed = false;
    popup.postMessage = message => { if (closed) throw new Error('Disconnected'); content.listeners.forEach(fn => fn(message)); };
    content.postMessage = message => { if (!closed) popup.listeners.forEach(fn => fn(message)); };
    popup.disconnect = content.disconnect = () => {
      if (closed) return;
      closed = true; popup.disconnected.forEach(fn => fn()); content.disconnected.forEach(fn => fn());
    };
    connections[options.frameId].forEach(fn => fn(content));
    ports.push(popup);
    return popup;
  };
  browser.scripting = { executeScript: async options => {
    reviewDispatches.push({ action: 'inject', tabId: options.target.tabId });
    return frames.map((frame, frameId) => ({ frameId, result: frame.eval(script) }));
  } };
  window.addEventListener('pagehide', () => ports.forEach(port => port.disconnect()));
}
