
window.addEventListener("message", function(event) {
  if (event.source != window)
    return;

  chrome.runtime.sendMessage(event.data) 
}, false)

chrome.runtime.onMessage.addListener(function(message) {
  if(message.type === "REDUX_UPDATE") {
    window.postMessage(message, "*")
  }
})
