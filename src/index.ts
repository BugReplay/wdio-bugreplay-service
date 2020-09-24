import BugReplayExtension from './BugReplayExtension'

type BugReplayServiceOptions = {
  apiKey: string,
  saveSuccessfulTests: false
}

type BugReplayServiceAttributes = {
  apiKey: string
  saveSuccessfulTests: false
}

export default class BugReplayService {
  options: BugReplayServiceAttributes;
  constructor(options: BugReplayServiceOptions) {
    this.options = options
  }
  async before() {
    await BugReplayExtension.auth(this.options.apiKey)
  }
  async beforeTest() {
    await BugReplayExtension.startRecording()
  }
  async afterTest(test: any, context:any, result:any) {
    const time = (new Date()).toISOString() 
    await BugReplayExtension.stopRecording()
    if(result.passed && !this.options.saveSuccessfulTests) {
      await BugReplayExtension.cancelReport()
    } else {
      await BugReplayExtension.saveReport(`WDIO - ${test.parent} - ${test.title} - ${time}`)
    }
  }
}
