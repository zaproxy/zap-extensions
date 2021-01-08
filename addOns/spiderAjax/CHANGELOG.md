# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased
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



[23.2.0]: https://github.com/zaproxy/zap-extensions/releases/spiderAjax-v23.2.0
[23.1.0]: https://github.com/zaproxy/zap-extensions/releases/spiderAjax-v23.1.0
[23.0.0]: https://github.com/zaproxy/zap-extensions/releases/spiderAjax-v23.0.0
