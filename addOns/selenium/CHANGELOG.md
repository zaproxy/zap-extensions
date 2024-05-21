# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased


## [15.24.0] - 2024-05-21
### Changed
- Update Selenium to version 4.21.0.

## [15.23.0] - 2024-05-07
### Changed
- Update minimum ZAP version to 2.15.0.

## [15.22.0] - 2024-04-26
### Changed
- Update Selenium to version 4.20.0.

## [15.21.0] - 2024-04-02
### Changed
- Update Selenium to version 4.19.1.

## [15.20.0] - 2024-03-28
### Added
- Support for menu weights (Issue 8369).

### Changed
- Update Selenium to version 4.19.0.
- Update HtmlUnit to major version 3.

### Fixed
- A typo on the intro page in the add-on's help.

## [15.19.0] - 2024-02-22
### Changed
- Update Selenium to version 4.18.1.
- Maintenance changes.

## [15.18.0] - 2024-01-26
### Changed
- Update Selenium to version 4.17.0.

## [15.17.0] - 2024-01-18
### Changed
- Update Selenium to version 4.16.1.

## [15.16.0] - 2023-11-10
### Changed
- Update Selenium to version 4.15.0.

### Fixed
- Add vertical scroll bar to the options panel to prevent the options from being hidden when resizing the Options dialogue (Issue 8178).

## [15.15.0] - 2023-10-12
### Changed
- Update Selenium to version 4.14.0.
- Update minimum ZAP version to 2.14.0.

## [15.14.0] - 2023-09-26
### Added
- Add statistics for browser launch successes and failures that include the requester, e.g.:
  - `stats.selenium.launch.<requester-id>.<browser-id>`
  - `stats.selenium.launch.<requester-id>.<browser-id>.failure`
- Allow to configure additional (CLI) arguments for Chrome and Firefox.
- Support for selecting a default Firefox profile.

### Changed
- Maintenance changes.
- Update Selenium to version 4.12.1.

## [15.13.0] - 2023-07-11
### Changed
- Update minimum ZAP version to 2.13.0.
- Update Selenium to version 4.

### Removed
- Remove support for Opera and PhantomJS (no longer being actively maintained).

## [15.12.1] - 2023-05-26
### Fixed
- Install Firefox extensions without using a profile (Issue 7878).

## [15.12.0] - 2023-05-23
### Changed
- Maintenance changes.

### Fixed
- Disable JSON view in Firefox for DOM XSS rule to prevent hangs when the "Save As" option is invoked.

## [15.11.0] - 2022-10-27
### Changed
- Update minimum ZAP version to 2.12.0.

## [15.10.0] - 2022-09-23
### Added
- Option to register and run 'browserHooks'.

### Changed
- Maintenance changes.

## [15.9.0] - 2022-05-06
### Changed
- Use Network add-on to obtain main proxy address/port.

### Fixed
- Restore usage of bundled ChromeDriver ([Issue #7272](https://github.com/zaproxy/zaproxy/issues/7272)).

## [15.8.0] - 2022-03-29
### Added
- Support aarch64/arm64 WebDrivers.
- Allow to choose the location of Chrome binary (Issue 7166).

## [15.7.0] - 2022-02-17
### Added
- Statistics, number of browsers launched.

### Fixed
- Quit all browsers when ZAP shuts down ([Issue #6643](https://github.com/zaproxy/zaproxy/issues/6643)).

## [15.6.0] - 2021-12-13
### Changed
- Update minimum ZAP version to 2.11.1.
- Maintenance changes (Issue 6963).

## [15.5.1] - 2021-11-28
### Fixed
- Address exception when saving the options (Issue 6951).

## [15.5.0] - 2021-11-25
### Added
- Support for browser extensions.
### Changed
- Dependency updates.

## [15.4.0] - 2021-10-06
### Changed
- Now using 2.10 logging infrastructure (Log4j 2.x).
- Update links to zaproxy repo.
- Maintenance changes (some changes impact the visibility of variables and getters/setters, which may impact third party add-ons or scripts).
- Update minimum ZAP version to 2.11.0.
- Disable open URL in browser from GUI in containers unless override option enabled.

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

[15.24.0]: https://github.com/zaproxy/zap-extensions/releases/selenium-v15.24.0
[15.23.0]: https://github.com/zaproxy/zap-extensions/releases/selenium-v15.23.0
[15.22.0]: https://github.com/zaproxy/zap-extensions/releases/selenium-v15.22.0
[15.21.0]: https://github.com/zaproxy/zap-extensions/releases/selenium-v15.21.0
[15.20.0]: https://github.com/zaproxy/zap-extensions/releases/selenium-v15.20.0
[15.19.0]: https://github.com/zaproxy/zap-extensions/releases/selenium-v15.19.0
[15.18.0]: https://github.com/zaproxy/zap-extensions/releases/selenium-v15.18.0
[15.17.0]: https://github.com/zaproxy/zap-extensions/releases/selenium-v15.17.0
[15.16.0]: https://github.com/zaproxy/zap-extensions/releases/selenium-v15.16.0
[15.15.0]: https://github.com/zaproxy/zap-extensions/releases/selenium-v15.15.0
[15.14.0]: https://github.com/zaproxy/zap-extensions/releases/selenium-v15.14.0
[15.13.0]: https://github.com/zaproxy/zap-extensions/releases/selenium-v15.13.0
[15.12.1]: https://github.com/zaproxy/zap-extensions/releases/selenium-v15.12.1
[15.12.0]: https://github.com/zaproxy/zap-extensions/releases/selenium-v15.12.0
[15.11.0]: https://github.com/zaproxy/zap-extensions/releases/selenium-v15.11.0
[15.10.0]: https://github.com/zaproxy/zap-extensions/releases/selenium-v15.10.0
[15.9.0]: https://github.com/zaproxy/zap-extensions/releases/selenium-v15.9.0
[15.8.0]: https://github.com/zaproxy/zap-extensions/releases/selenium-v15.8.0
[15.7.0]: https://github.com/zaproxy/zap-extensions/releases/selenium-v15.7.0
[15.6.0]: https://github.com/zaproxy/zap-extensions/releases/selenium-v15.6.0
[15.5.1]: https://github.com/zaproxy/zap-extensions/releases/selenium-v15.5.1
[15.5.0]: https://github.com/zaproxy/zap-extensions/releases/selenium-v15.5.0
[15.4.0]: https://github.com/zaproxy/zap-extensions/releases/selenium-v15.4.0
[15.3.0]: https://github.com/zaproxy/zap-extensions/releases/selenium-v15.3.0
[15.2.0]: https://github.com/zaproxy/zap-extensions/releases/selenium-v15.2.0
[15.1.0]: https://github.com/zaproxy/zap-extensions/releases/selenium-v15.1.0
[15.0.0]: https://github.com/zaproxy/zap-extensions/releases/selenium-v15.0.0
