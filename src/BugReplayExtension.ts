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
  async auth(email: string, password: string) {
    await browser.url("https://dev-app.bugreplay.com");
    const emailField = await $('#email')
    await emailField.setValue(email)
    const passwordField = await $('#password')
    await passwordField.setValue(password)
    const submitButton = await $('button[type=submit]')
    await submitButton.click()
    await browser.pause(1000)
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
