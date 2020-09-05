import BugReplayExtension from './BugReplayExtension'

type BugReplayServiceOptions = {
  apiKey: string
}

type BugReplayServiceAttributes = {
  apiKey: string
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
  async afterTest(test: any, context:any) {
    const time = (new Date()).toISOString() 
    await BugReplayExtension.stopRecording()
    await BugReplayExtension.saveReport(`WDIO - ${test.parent} - ${test.title} - ${time}`)
  }
}
