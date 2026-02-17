import { MESSAGE_TYPES, createRequestId } from "./messages.js";

const requestId = createRequestId("popup");

chrome.runtime.sendMessage({ type: MESSAGE_TYPES.RUN_ANALYSIS, requestId }, (response) => {
  if (chrome.runtime.lastError) {
    console.warn("Analysis request failed:", chrome.runtime.lastError.message);
    return;
  }

  if (response?.requestId !== requestId) {
    console.warn("Request correlation mismatch", { requestId, response });
    return;
  }

  console.log("Analysis response:", response);
});
