import BugReplayExtension from './BugReplayExtension'

type BugReplayServiceOptions = {
  email: string,
  password: string
}

export default class BugReplayService {
  constructor(options: BugReplayServiceOptions) {
    this.options = options
  }
  async before() {
    await BugReplayExtension.auth(options.email, options.password)
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
