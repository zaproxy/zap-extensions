# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
### Changed
- Update links to zaproxy repo.

## [15.3.0] - 2020-12-15
### Changed
- Invoke Selenium scripts synchronously for AJAX Spider's browsers, to prevent interferences with the crawler.
- Update minimum ZAP version to 2.10.0.

## [15.2.0] - 2020-03-31
### Added
- Support for selenium scripts which are invoked when browsers are launched.

### Changed
- Update minimum ZAP version to 2.9.0.
- Set Firefox browser.tabs.documentchannel pref to false to fix HUD issue

## [15.1.0] - 2020-01-17
### Added
- Add info and repo URLs.

### Changed
- Update Selenium to version 3.141.59.
- Workaround Chrome bug re ignoring cert errors

## [15.0.0] - 2019-06-07

- Remove support for Internet Explorer, does not support required capabilities.
- Quit corresponding WebDrivers when removing WebDriver provider.
- Enable ServiceWorker on launched Firefox browsers.
- Ensure "localhost" is proxied through ZAP on Firefox >= 67.
- Allow to start Chrome and Firefox in headless mode (Issue 3866).
- Start using Semantic Versioning.

## 14 - 2019-01-31

- Enable the extension for all DB types.
- Mention the configuration keys in the options help page.
- Tweak error message shown when failed to start/connect to the browser.
- Disable Firefox JSON viewer when used by AJAX Spider to prevent crawl.
- Prevent WebDriver process leak when closing ZAP.
- Ensure "localhost" is proxied through ZAP on Chrome >= 72.

## 13 - 2017-11-27

- Updated for 2.7.0.

## 12 - 2017-11-20

- Update Selenium to version 3.7.1.

## 11 - 2017-08-18

- Update Selenium to version 3.4.0.
- Move Bundled WebDrivers section to main help page and recommend using newer browser versions.
- Add menus and methods for launching browsers proxying through ZAP.

## 10 - 2017-03-31

- Update help page to mention the IDs of the browsers.

## 9 - 2017-03-06

- Allow add-ons to add new browsers.

## 8 - 2017-01-27

- Allow to use Firefox 48+ (Issue 2743).
- Allow to specify the path to geckodriver.
- Use bundled WebDrivers by default.

## 7 - 2016-08-04

- Allow to use Firefox 47.0.1 (Issue 2739).
- Allow to manually specify the paths to binaries and WebDrivers in the options.
- Allow to choose which Firefox binary is used.

## 6 - 2016-06-30

- Fix issue that prevented PhantomJS from starting (Issue 2636)

## 5 - 2016-03-15

- Updated to use Selenium 2.52.0 (Issue 2321)

## 4 - 2015-12-22

- Updated to use Selenium 2.48.2 (Issue 2149).

## 3 - 2015-08-31

- Updated to use Selenium 2.47.1

## 2 - 2015-08-23

- Minor code changes.

## 1 - 2015-04-13

- Updated to Selenium 2.45 and moved to release

[15.3.0]: https://github.com/zaproxy/zap-extensions/releases/selenium-v15.3.0
[15.2.0]: https://github.com/zaproxy/zap-extensions/releases/selenium-v15.2.0
[15.1.0]: https://github.com/zaproxy/zap-extensions/releases/selenium-v15.1.0
[15.0.0]: https://github.com/zaproxy/zap-extensions/releases/selenium-v15.0.0
