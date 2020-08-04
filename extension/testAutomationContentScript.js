var port = chrome.runtime.connect()

window.addEventListener("message", function(event) {
  if (event.source != window)
    return;

  port.postMessage(event.data) 
}, false)
