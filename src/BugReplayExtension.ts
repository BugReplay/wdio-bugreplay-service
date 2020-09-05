import WebdriverIO from 'webdriverio'
//declare var browser: WebdriverIO.BrowserObject;
//declare var driver: WebdriverIO.BrowserObject;
//declare var $: (selector: string | Function) => Promise<WebdriverIO.Element>;

function sleep(ms: number) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

const BugReplayExtension = {
  dispatch(payload: any) {
    browser.execute((payload: any) => {
      window.postMessage({
        type: 'REDUX_DISPATCH',
        payload: payload
      }, '*');
    }, payload)
  },

  async auth(apiKey: string) {
    // For now the extension requires that you are on a real page before it can initialize
    browser.url('https://bugreplay.com')
    this.dispatch({
      type: 'SET_API_KEY',
      payload: apiKey,
    })
  },
  
  async startRecording() {
    this.dispatch({
      type: 'POPUP_CONNECT'
    })
    await browser.execute(() => {
      document.title = "Record This Window"
    })
    await sleep(500)
    this.dispatch({ type: 'CLICK_START_RECORDING_SCREEN' })
  },

  async stopRecording() {
    this.dispatch({ type: 'CLICK_STOP_RECORDING' })
  },

  async saveReport(title = "Automated Bug Report", description = "Automated Bug Report") {
    await sleep(500)
    this.dispatch({ 
      type: 'UPDATE_REPORT', 
      payload: {
        updates: {
          title,
        }
      },
    })
    await sleep(500)
    this.dispatch({ 
      type: 'UPDATE_REPORT', 
      payload: {
        updates: {
          description,
        }
      },
    })
    await sleep(500)
    this.dispatch({ type: 'CLICK_SUBMIT_REPORT' })
    await sleep(3000)
  }
}

export default BugReplayExtension
