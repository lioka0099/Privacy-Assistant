chrome.runtime.onInstalled.addListener(() => {
  console.log('Privacy Assistant installed');
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === 'PING') {
    sendResponse({ ok: true, source: 'background' });
  }
});
