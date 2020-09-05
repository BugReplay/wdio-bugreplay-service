(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
/*
  This script runs from within an otherwise blank web page hosted by bugreplay.
  We do this because navigator.mediaDevices.getUserMedia never resolves in the background script.
  Messages, including each frame of the video, are then sent back to the background script.
*/
console.log('CONTENT SCRIPT RUNNING...');
function runContentScript(browser, navigator, MediaRecorder, document, FileReader) {
    let stream;
    let videoRecorder;
    let isStopped = false;
    let recordMicPromise;
    let recordMic;
    let countdownTimer;
    // If screen-sharing permissions are turned off for the page, then navigator.mediaDevices.getUserMedia will .catch with a NotAllowedError
    // very quickly. So, we keep track of how much time elapsed between navigator.mediaDevices.getUserMedia being called and a NotAllowedError
    // being thrown to determine whether the user had time to choose media themselves.
    let userHadTimeToChooseMediaThemselves = false;
    function listener(message) {
        if (message.type === 'FIREFOX_VIDEO_RECORDING_STOP') {
            stop();
        }
    }
    function stop() {
        if (isStopped)
            return;
        isStopped = true;
        if (stream) {
            stream.getTracks().forEach(track => track.stop());
        }
        if (videoRecorder) {
            videoRecorder.stop();
        }
        browser.runtime.onMessage.removeListener(listener);
    }
    function withStream(s) {
        try {
            stream = s;
            if (recordMic) {
                videoRecorder = new MediaRecorder(stream, {
                    mimeType: 'video/webm;codecs=vp8,opus',
                });
            }
            else {
                videoRecorder = new MediaRecorder(stream, {
                    mimeType: 'video/webm;codecs=vp8',
                });
            }
            videoRecorder.onstart = function () {
                if (document.getElementById('message')) {
                    document.getElementById('message').innerHTML =
                        'Please leave this window open during the recording. It will close automatically when the recording has finished';
                }
                else {
                    document.body.innerHTML =
                        '<p>Please leave this window open during the recording. It will close automatically when the recording has finished.</p>';
                }
                browser.runtime.sendMessage({ type: 'FIREFOX_VIDEO_RECORDING_START' });
            };
            videoRecorder.ondataavailable = function (frame) {
                const data = frame.data;
                const hasData = !!data && !!data.size;
                if (!hasData && isStopped) {
                    return browser.runtime.sendMessage({
                        type: 'FIREFOX_VIDEO_RECORDING_SUCCESS',
                    });
                }
                if (hasData) {
                    const now = Date.now();
                    const reader = new FileReader();
                    reader.addEventListener('loadend', function () {
                        const result = reader.result;
                        browser.runtime.sendMessage({
                            type: 'FIREFOX_VIDEO_RECORDING_FRAME',
                            data: result.substr(result.lastIndexOf(',') + 1),
                            timestamp: now,
                        });
                        if (isStopped) {
                            browser.runtime.sendMessage({
                                type: 'FIREFOX_VIDEO_RECORDING_SUCCESS',
                            });
                        }
                    });
                    reader.readAsDataURL(data);
                }
            };
            videoRecorder.onerror = videoRecorder.onwarning = function (error) {
                console.error(error);
                browser.runtime.sendMessage({
                    type: 'FIREFOX_VIDEO_RECORDING_FAILURE',
                    error: error.message,
                });
                stop();
            };
            videoRecorder.start(1000);
        }
        catch (error) {
            console.error(error);
        }
    }
    browser.runtime.onMessage.addListener(listener);
    if (document.getElementById('error-link')) {
        document.getElementById('error-link').addEventListener('click', function () {
            document.getElementById('error-detail').style.display = 'block';
        });
    }
    if (document.getElementById('message')) {
        document.getElementById('message').innerHTML =
            'Please select a window to record';
    }
    else {
        document.body.innerHTML = '<p>Please select a window to record</p>';
    }
    if (window.location.search.split('audio=')[1] &&
        window.location.search.split('audio=')[1].split('&')[0] == 'true') {
        recordMic = true;
    }
    if (window.location.search.split('countdown=')[1] &&
        window.location.search.split('countdown=')[1].split('&')[0] == 'true') {
        countdownTimer = true;
    }
    navigator.mediaDevices
        .getUserMedia({
        audio: recordMic,
        video: {
            mediaSource: 'window',
        },
    })
        .then(function (mediaStream) {
        if (countdownTimer) {
            browser.runtime.sendMessage({
                type: 'FIREFOX_VIDEO_RECORDING_COUNTDOWN_START',
            });
            setTimeout(function () {
                withStream(mediaStream);
            }, 3000);
        }
        else {
            withStream(mediaStream);
        }
    })
        .catch(function (error) {
        console.error(error);
        // The recording didn't fail if the user cancelled it so we classify this separately
        if (error.name === 'NotAllowedError' || error.name === 'NotFoundError') {
            if (document.getElementById('message')) {
                document.getElementById('message').innerHTML =
                    "Sorry, an error occured when screensharing. Please see <a href='https://bugreplay.zendesk.com/hc/en-us/articles/360039701694-How-to-Enable-the-Screen-Sharing-Permission-on-Firefox'>this article</a> for how to resolve this issue.";
            }
            return browser.runtime.sendMessage({
                type: userHadTimeToChooseMediaThemselves
                    ? 'FIREFOX_VIDEO_RECORDING_NOT_ALLOWED'
                    : 'FIREFOX_VIDEO_RECORDING_NOT_ALLOWED_PREVIOUSLY',
            });
        }
        if (document.getElementById('message')) {
            document.getElementById('message').innerHTML =
                'Sorry, an error occured when screensharing.';
        }
        if (document.getElementById('error-detail')) {
            document.getElementById('error-detail').innerHTML = error.message;
        }
        stop();
        browser.runtime.sendMessage({
            type: 'FIREFOX_VIDEO_RECORDING_FAILURE',
            error: error.message,
        });
    });
    setTimeout(() => {
        userHadTimeToChooseMediaThemselves = true;
    }, 100);
}
exports.runContentScript = runContentScript;
if (typeof window !== 'undefined') {
    runContentScript(browser, navigator, MediaRecorder, document, FileReader);
}

},{}]},{},[1]);
