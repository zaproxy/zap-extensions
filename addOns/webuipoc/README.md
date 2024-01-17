# ZAP Web UI PoC

This add-on supports web based UI PoCs for ZAP.

It had been created for the proposed ZAP [GSoC 2024 Web Based UI](https://www.zaproxy.org/docs/gsoc/2024/#web-based-ui) project.

It is not available on the ZAP Marketplace - to use it you will need to:

1. Set up a development environment as per the [ZAP Developer Guide](https://www.zaproxy.org/docs/developer/)
1. Run the following command in the `zap-extensions` project: `./gradlew :addOns:webuipoc:copyZapAddOn`
1. Start ZAP using the following command in the `zaproxy` project: `./gradlew run`

If you point your browser at `http://localhost:1337` your should then see the "ZAP Web UI PoC Server" main page.

The main page lists all of the PoCs currently available:

* [example](docs/example) : the official basic example

Add your PoC to the end of the above list.

## Contributions

We expect GSoC candidates to contribute to ZAP prior to submitting their proposals.

ZAP is mostly implemented in Java. There are 2 sub-projects implemented in JavaScript and TypeScript but these are both complex projects that are not ideal for new contributors.

This add-on allows GSoC candidates to contribute to ZAP using modern web app technologies and without knowing any Java.

As a GSoC candidate who would like to work on the Web Based UI project you should implement a PoC and submit it via a pull request.

We understand that you may not want to share all of your hard work as this may help others.
We would still like you to contribute a basic PoC but we are very happy for you to share a more complete Poc with us privately.

## Creating Your PoC

Create a new directory for your add-on under [webuipoc](src/main/zapHomeFiles/webuipoc).

This is where you should put all of the files that need to be served up by ZAP.

Source TypeScript files should be added to a new directory under the [src](src) directory.

## Content Security Policy

This add-on defines a fairly strong [Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
which blocks things like inline scripts and inline styles.
If this causes you problems then talk to the ZAP team :grin:.

## Documenting Your PoC

Create a new directory under [docs](docs) and add a README.md file which gives more details about your PoC.
Link to that directory from the above list of PoCs.