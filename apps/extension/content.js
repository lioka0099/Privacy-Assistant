chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === 'PING_CONTENT') {
    sendResponse({ ok: true, source: 'content' });
  }
});
