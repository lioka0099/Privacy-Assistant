chrome.runtime.sendMessage({ type: "RUN_ANALYSIS" }, (response) => {
  if (chrome.runtime.lastError) {
    console.warn("Analysis request failed:", chrome.runtime.lastError.message);
    return;
  }
  console.log("Analysis response:", response);
});
