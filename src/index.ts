import BugReplayExtension from './BugReplayExtension'

type BugReplayServiceOptions = {
  apiKey: string,
  saveSuccessfulTests: false
  project_id: number
}

type BugReplayServiceAttributes = {
  apiKey: string
  saveSuccessfulTests: false
  project_id: number
}

function getTestHierarchy(test:any):string[] {
  if(test.parent) {
    return [...getTestHierarchy(test.parent), test.title]
  } else {
    if(test.title && test.title !== '') {
      return [test.title]
    } else {
      return []
    }
  }
}

export default class BugReplayService {
  options: BugReplayServiceAttributes;
  testRunId: string;
  constructor(options: BugReplayServiceOptions) {
    this.testRunId = process.env.TEST_RUN_ID || new Date().toISOString()
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
    const { passed } = result
    const { project_id } = this.options;
    const hierarchy = getTestHierarchy(test.ctx.test)
    await BugReplayExtension.stopRecording()
    if(result.passed && !this.options.saveSuccessfulTests) {
      await BugReplayExtension.cancelReport()
    } else {
      const reportAttributes: any = {
        test_hierarchy: hierarchy.join(' > '),
        test_passed: passed,
        test_run_id: this.testRunId
      }
      if(project_id) {
          reportAttributes.project_id = project_id
      }
      await BugReplayExtension.saveReport(`WDIO - ${test.parent} - ${test.title} - ${time}`, reportAttributes)
    }
  }
}
