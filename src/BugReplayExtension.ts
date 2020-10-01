import WebdriverIO from 'webdriverio'
//declare var browser: WebdriverIO.BrowserObject;
//declare var driver: WebdriverIO.BrowserObject;
//declare var $: (selector: string | Function) => Promise<WebdriverIO.Element>;

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
    this.dispatch({ type: 'CLICK_START_RECORDING_SCREEN' })
  },

  async stopRecording() {
    await browser.executeAsync((done: any) => {
      window.addEventListener("message", (event) => {
        if(event?.data?.payload?.nextState?.recording?.stopped) {
          // Don't finish until the browser has stopped recording
          done(true)
        }
      })
      window.postMessage({
        type: 'REDUX_DISPATCH',
        payload: { type: 'CLICK_STOP_RECORDING' }
      }, '*');
    })
  },

  async saveReport(title = "Automated Bug Report", description = "Automated Bug Report") {
    await browser.executeAsync((title, description, done: any) => {
      window.addEventListener("message", (event) => {
        console.log(event)
        if(!event?.data?.payload?.nextState?.report?.started &&
           event?.data?.payload?.nextState?.reports?.processing?.length === 0
          ) {
          // Don't finish until the report is submitted and processed
          done(true)
        }
      })
      window.postMessage({
        type: 'REDUX_DISPATCH',
        payload: { 
          type: 'UPDATE_REPORT', 
          payload: {
            updates: {
              title,
              description,
            }
          },
        }
      }, '*');
      window.postMessage({
        type: 'REDUX_DISPATCH',
        payload: { 
          type: 'CLICK_SUBMIT_REPORT', 
        }
      }, '*');
    }, title, description)
  },

  async cancelReport() {
    this.dispatch({ type: 'CANCEL_REPORT' })
  }
}

export default BugReplayExtension
