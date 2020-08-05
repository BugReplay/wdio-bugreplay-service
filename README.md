# BugReplay WebDriver.IO Service
The BugReplay WDIO service records screencasts of your automated tests including timesynced JavaScript Console and Network logs
## Installation
Install the package

    npm install wdio-bugreplay-service --save-dev

## Configuration
You will need to sign up for an account at https://bugreplay.com

In wdio.conf.js, you will need to add both the bugreplay service as well as add the configure the BugReplay automation extension to be added to chrome:

    // wdio.conf.js
    export.config = {
        // ...
        capabilities: [{
          // ...
          browserName: 'chrome',
          'goog:chromeOptions': {
            args: [
              '--load-extension=node_modules/wdio-bugreplay-service/extension/',
              '--auto-select-desktop-capture-source=Record This Window'
            ]
          },
        }
        // ...
        services: [
            ['bugreplay', {
                email: 'yourbugreplayemail@something.com',
                password: 'yourbugreplaypassword'080
            }]
        ],
        // ...
    };

After this configuration your tests will automatically be recorded to video, uploaded to BugReplay, and ready for playback alongside the timesynced JS console and network traffic logs.

## Limitations
This currently only works for chromedriver. We're looking to expand to other browsers in the future.
