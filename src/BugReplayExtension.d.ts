declare const BugReplayExtension: {
    dispatch(payload: any): void;
    auth(email: string, password: string): void;
    startRecording(): void;
    stopRecording(): void;
    saveReport(title?: string, description?: string): void;
};
export default BugReplayExtension;
