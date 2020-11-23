# BugReplay WebDriver.IO Service
The BugReplay WDIO service records screencasts of your automated tests including timesynced JavaScript Console and Network logs
## Installation
Install the package

    npm install wdio-bugreplay-service --save-dev

## Configuration
You will need to sign up for an account at https://bugreplay.com. After that you will need to login and get an API key by clicking the Hamburger Menu, click My Settings, and then Show API Key. You'll use this in the configuration file.

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
                apiKey: 'YOUR_BUGREPLAY_API_KEY_GOES_HERE',
                saveSuccessfulTests: true // the default is false
            }]
        ],
        // ...
    };

After this configuration your tests will automatically be recorded to video, uploaded to BugReplay, and ready for playback alongside the timesynced JS console and network traffic logs.

## Limitations
This currently only works for chromedriver and edgedriver. We're looking to expand to other browsers in the future.

## Working with MS Edge (Chromium)
We've had the best luck using the [selenium-standalone-service](https://webdriver.io/docs/selenium-standalone-service.html) 
for running on MS Edge.

The configuration looks the same except instead of browserName: 'chrome' you'd have browserName: 'MicrosoftEdge'.
Instead of goog:chromeOptions you'd have ms:edgeOptions.
