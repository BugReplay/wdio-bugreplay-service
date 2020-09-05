
window.addEventListener("message", function(event) {
  if (event.source != window)
    return;

  chrome.runtime.sendMessage(event.data) 
}, false)

