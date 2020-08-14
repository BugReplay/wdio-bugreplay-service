import BugReplayExtension from './BugReplayExtension'

type BugReplayServiceOptions = {
  email: string,
  password: string
}

type BugReplayServiceAttributes = {
  email: string,
  password: string
}

export default class BugReplayService {
  options: BugReplayServiceAttributes;
  constructor(options: BugReplayServiceOptions) {
    this.options = options
  }
  async before() {
    await BugReplayExtension.auth(this.options.email, this.options.password)
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
