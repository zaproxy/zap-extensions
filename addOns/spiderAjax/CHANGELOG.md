# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased


## [23.19.0] - 2024-05-07
### Added
- Video link in help for Automation Framework job.
- Support for menu weights (Issue 8369)

### Changed
- Update minimum ZAP version to 2.15.0.
- Maintenance changes.

### Fixed
- A typo in an API end-point description.

## [23.18.0] - 2023-11-10
### Added
- Add context menu item to Contexts tree to show the AJAX Spider dialogue with the selected Context.

### Changed
- Add icon to the Tools menu item.
- Scale icons.

## [23.17.0] - 2023-10-12
### Changed
- Update minimum ZAP version to 2.14.0.

### Fixed
- Add URL to start event.

## [23.16.0] - 2023-09-26
### Changed
- Maintenance changes.
- Depend on newer versions of Automation Framework and Common Library add-ons (Related to Issue 7961).
- Depend on newer version of Network add-on and allow to access the ZAP API while spidering.

## [23.15.0] - 2023-07-11
### Added
- Support for authentication handlers.

### Changed
- Update minimum ZAP version to 2.13.0.
- Depend on newer version of Selenium add-on.
- Update Crawljax to 3.7.1, to use the newer version of Selenium.

## [23.14.1] - 2023-06-02
### Fixed
- Handle job with no parameters when reading Excluded Elements (Issue 7889).

## [23.14.0] - 2023-05-31
### Added
- Allow to exclude elements from crawl (Issue 5875).
- Configure logging of dependencies directly, instead of relying on core.

## [23.13.1] - 2023-04-05
### Fixed
- Honour `-config` arguments when applying the default allowed resources (Issue 7809).

## [23.13.0] - 2023-03-15
### Added
- Automation Framework - HTML elements to click support

### Fixed
- Close the AJAX Spider dialogue when uninstalling the add-on.

## [23.12.0] - 2023-02-23
### Added
- Automation Framework - inScopeOnly option

### Changed
- Add default Allowed Resources if none present in existing home directory when updating the add-on (Issue 7719).

## [23.11.0] - 2023-02-06
### Changed
- Maintenance changes.
- Default number of threads to 2 * processor count.

### Fixed
- Ensure default Allowed Resources are present with a new home directory (Issue 7719).

## [23.10.0] - 2022-10-27
### Changed
- Update minimum ZAP version to 2.12.0.
- Maintenance changes.

## [23.9.0] - 2022-09-23
### Changed
- Maintenance changes.

### Added
- Support for automation monitor tests.
- Added 'runOnlyIfModern' Automation Framework option.

### Fixed
- Automation Framework dialog - min numberOfBrowsers now 1.
- Automation Framework job - correctly pick up URL from context.

## [23.8.0] - 2022-08-04
### Added
- Missing 'user' param in the Automation Framework help

### Changed
- Update minimum ZAP version to 2.11.1.
- Use Network add-on to proxy Crawljax/browser requests.
- Maintenance changes.

### Fixed
- Stop the spider scans when ZAP shuts down ([Issue #6643](https://github.com/zaproxy/zaproxy/issues/6643)).

## [23.7.0] - 2021-11-02
### Added
- Automation authentication support

### Changed
- Dependency updates.

## [23.6.0] - 2021-10-06
### Changed
- Update minimum ZAP version to 2.11.0.

## [23.5.0] - 2021-09-16
### Added
  - Add Job Name field in AJAX Spider Automation dialogue
### Fixed
 - Address errors when running the AJAX Spider with Automation Framework.
 - Fixed var support in URLs ([Issue #6726](https://github.com/zaproxy/zaproxy/issues/6726))

### Changed
- Maintenance changes.

## [23.4.0] - 2021-08-05
### Added
- Automation Framework GUI

### Changed
- Now using 2.10 logging infrastructure (Log4j 2.x).
- Maintenance changes.
- Handle multiple context URLs in automation.

### Deprecated
- Automation parameters `failIfFoundUrlsLessThan` and `warnIfFoundUrlsLessThan` in favour of the
`spiderAjax.urls.added` statistic test.

## [23.3.0] - 2021-03-09
### Added
- Initial support for the automation framework

### Changed
- Update minimum ZAP version to 2.10.0.

## [23.2.0] - 2020-11-09
### Added
- Allow to specify allowed resources (Issue 3236). The allowed resources are always fetched
even if out of scope, allowing to include necessary resources (e.g. scripts) from 3rd-parties.
By default it allows files with extension `.js` and `.css`.

### Changed
- Update minimum ZAP version to 2.9.0.
- Maintenance changes.

### Fixed
- Unregister the event publisher when the add-on is uninstalled.
- Persist the state of "Remove Without Confirmation" of non-default elements to click.

## [23.1.0] - 2020-01-17
### Added
- Add repo URL.

### Changed
 - Enable websockets ([Issue 4521](https://github.com/zaproxy/zaproxy/issues/4521))
- Change info URL to link to the site.

## [23.0.0] - 2019-06-07

- Correct WebDriver requester ID.
- Remove unused resource messages.
- Generate start and stop events.
- Run with Firefox headless by default (Issue 3866).
- Depend on newer version of Selenium add-on.

## 22 - 2018-08-08

- Maintenance changes.
- Add Export button to results table (Issue 4875).

## 21 - 2018-01-19

- Reset API scan also when in daemon mode (Issue 4163).

## 20 - 2017-11-27

- Updated for 2.7.0.

## 19 - 2017-11-24

- Code changes for Java 9 (Issue 2602).
- Fix "Internal Error" when accessing the full results API view.

## 18 - 2017-08-18

- Update to support Selenium version 3.4.0 (Issue 3509).
- Fix WebDriver process leak (Issue 3155).

## 17 - 2017-03-06

- Show alerts/tags in the AJAX Spider tab.
- Use a custom initiator ID (10) for AJAX Spider requests.
- Show always the latest configured browsers in AJAX Spider dialogue (Issue 3057).
- Honour global excluded URLs (Issue 3172).
- Reset URL counter on session change.
- Show excluded URLs in the AJAX Spider tab and through the ZAP API.
- Use provided browsers from Selenium add-on.
- Show messages that were not successful because of I/O errors.
- Ensure New Scan button is enabled, when the mode allows it.

## 16 - 2016-09-05

- Allow to show the AJAX Spider dialogue through Tools menu (and keyboard shortcut).
- Fixed the issue that prevented the ajaxSpider from resetting the crawled url count to zero while starting a new scan (Issue 2610).
- Warn always if attempting to AJAX spider "localhost" with PhantomJS.
- Allow to spider a context (Issue 1955).
- Allow to spider as a user (Issue 1956).
- Allow to manually specify the start URL in AJAX Spider dialogue (Issue 1957).
- Allow to spider just a site's subtree (Issue 2847).

## 15 - 2016-06-02

- Fix issue that prevented the spider from clicking all elements set in the options (Issue 2151).
- Minor update in help pages.
- Suppress log of innocuous warning.

## 14 - 2015-12-04

- Issue 2102: Allow ajax spider options to be set via the API.

## 13 - 2015-07-30

- Updated add-on's info URL.
- Changed to use the (full) URI of selected node (to be used as spider's seed).

## 12 - 2015-04-13

- Promoted to 'release' status (Issue 1326).
- Set to depend on 'Selenium' add-on (Issue 1534).
- Updated Crawljax to version 3.6 (Issue 1535).
- Advanced scan dialog (Issue 1177).

## 11 - 2014-09-22

- Exposed several Crawljax options (Issue 945).
- A warning message is shown if the selected browser was not successfully started.
- Disable the attack menu item "AJAX Spider Site" when the spider is running (Issue 1289).
- Updated Crawljax to version 3.5.1 and Selenium which adds support for Firefox 32 (Issue 1336).
- Error while updating "Ajax Spider" add-on (Issue 1337).
- Allow to use PhantomJS (Issue 1338).
- Allow to use Internet Explorer (Issue 1340).

## 10 - 2014-04-10

- Updated to use the latest core changes (Issues 609 and 1102).
- Changed to display the spider results in a table (Issue 503).
- Moved the Ajax Spider help pages from ZAP core to the add-on (Issue 1098).
- Updated add-on dir structure (Issue 1113).

## 9 - 2013-12-16

- Added support for modes and scope (Issue 334).
- Added API to control the Ajax Spider (Issue 369).
- AJAX Spider will now use the HTTP authentication credentials set in "Options" > "Authentication" (Issue 584).
- AJAX Spider will now use the options set in "Options" > "Connection".
- Changed to persist the configurations (Issue 678).
- Changed to proxy SSL traffic (Firefox) (Issue 824).
- Fixed a ChromeDriver process leak that occurred after closing the "Options" with Chrome browser selected (Issue 831).
- Changed to verify and deny all requests outside of spider scope (Issue 833).
- Updated Crawljax library (version 3.4) and dependencies (Issue 834).
- Changed to allow to set ChromeDriver's path through the "AJAX Spider" options (Issue 835).
- Changed to automatically configure the proxy settings (Issue 836).
- Changed to clear the results tab when a new spider process is started (Issue 926).
- Changed to not allow to start a new spider process if one is already running (Issue 927).
- Changed the AJAX Spider to listen to session changes (Issue 928).

## 8 - 2013-12-10

- Fixed problem where self referencing links could trap the spider

## 7 - 2013-09-11

- Updated for 2.2.0.

## 5 - 2013-06-02

- Changed to remove the footer status label when uninstalling;
- Updated Crawljax library (and its dependencies);
- Fixed a NoSuchMethodError which prevented the use of "Firefox" browser;
- Fixed a NoSuchMethodError which prevented the use of "HtmlUnit" browser;
- Changed the selection of browsers to use radio buttons.

## 4 - 2013-04-18

- Updated for ZAP 2.1.0

## 3 - 2013-01-28

- Updated to Selenium 2.28.0

## 2 - 2013-01-17

- Updated to support new addon format

## 1 - 2012-11-23



[23.19.0]: https://github.com/zaproxy/zap-extensions/releases/spiderAjax-v23.19.0
[23.18.0]: https://github.com/zaproxy/zap-extensions/releases/spiderAjax-v23.18.0
[23.17.0]: https://github.com/zaproxy/zap-extensions/releases/spiderAjax-v23.17.0
[23.16.0]: https://github.com/zaproxy/zap-extensions/releases/spiderAjax-v23.16.0
[23.15.0]: https://github.com/zaproxy/zap-extensions/releases/spiderAjax-v23.15.0
[23.14.1]: https://github.com/zaproxy/zap-extensions/releases/spiderAjax-v23.14.1
[23.14.0]: https://github.com/zaproxy/zap-extensions/releases/spiderAjax-v23.14.0
[23.13.1]: https://github.com/zaproxy/zap-extensions/releases/spiderAjax-v23.13.1
[23.13.0]: https://github.com/zaproxy/zap-extensions/releases/spiderAjax-v23.13.0
[23.12.0]: https://github.com/zaproxy/zap-extensions/releases/spiderAjax-v23.12.0
[23.11.0]: https://github.com/zaproxy/zap-extensions/releases/spiderAjax-v23.11.0
[23.10.0]: https://github.com/zaproxy/zap-extensions/releases/spiderAjax-v23.10.0
[23.9.0]: https://github.com/zaproxy/zap-extensions/releases/spiderAjax-v23.9.0
[23.8.0]: https://github.com/zaproxy/zap-extensions/releases/spiderAjax-v23.8.0
[23.7.0]: https://github.com/zaproxy/zap-extensions/releases/spiderAjax-v23.7.0
[23.6.0]: https://github.com/zaproxy/zap-extensions/releases/spiderAjax-v23.6.0
[23.5.0]: https://github.com/zaproxy/zap-extensions/releases/spiderAjax-v23.5.0
[23.4.0]: https://github.com/zaproxy/zap-extensions/releases/spiderAjax-v23.4.0
[23.3.0]: https://github.com/zaproxy/zap-extensions/releases/spiderAjax-v23.3.0
[23.2.0]: https://github.com/zaproxy/zap-extensions/releases/spiderAjax-v23.2.0
[23.1.0]: https://github.com/zaproxy/zap-extensions/releases/spiderAjax-v23.1.0
[23.0.0]: https://github.com/zaproxy/zap-extensions/releases/spiderAjax-v23.0.0
