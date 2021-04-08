"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var BugReplayExtension = {
    dispatch: function (payload) {
        browser.execute(function (payload, log) {
            var listener = window.addEventListener("message", function (e) {
                log(e.data);
            });
            window.postMessage({
                type: 'REDUX_DISPATCH',
                payload: payload
            }, '*');
        }, payload, console.log);
    },
    auth: function (email, password) {
        browser.url("https://app.bugreplay.com");
        Promise.all([
            $('#email').then(function (e) { return e.setValue(email); }),
            $('#password').then(function (e) { return e.setValue(password); })
        ]).then(function () {
            return $('button[type=submit]').then(function (e) { return e.click(); });
        });
    },
    startRecording: function () {
        this.dispatch({
            type: 'POPUP_CONNECT'
        });
        browser.pause(500);
        browser.execute(function () {
            document.title = "Record This Window";
        });
        browser.pause(500);
        this.dispatch({ type: 'CLICK_START_RECORDING_SCREEN' });
        browser.pause(1000);
    },
    stopRecording: function () {
        browser.pause(1000);
        this.dispatch({ type: 'CLICK_STOP_RECORDING_SCREEN' });
        browser.pause(5000);
    },
    saveReport: function (title, description) {
        if (title === void 0) { title = "Automated Bug Report"; }
        if (description === void 0) { description = "Automated Bug Report"; }
        this.dispatch({
            type: 'UPDATE_REPORT',
            payload: {
                updates: {
                    title: title,
                }
            },
        });
        browser.pause(1000);
        this.dispatch({
            type: 'UPDATE_REPORT',
            payload: {
                updates: {
                    description: description,
                }
            },
        });
        browser.pause(1000);
        this.dispatch({ type: 'CLICK_SUBMIT_REPORT' });
        browser.pause(3000);
        browser.debug();
    }
};
exports.default = BugReplayExtension;
//# sourceMappingURL=BugReplayExtension.js.map