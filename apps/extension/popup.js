chrome.runtime.sendMessage({ type: 'PING' }, (response) => {
  if (chrome.runtime.lastError) {
    console.warn('Background ping failed:', chrome.runtime.lastError.message);
    return;
  }
  console.log('Background ping response:', response);
});
