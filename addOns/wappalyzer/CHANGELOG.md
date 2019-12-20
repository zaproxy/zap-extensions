# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased


## [15] - 2019-12-20

### Changed
- Update patterns and icons as of AliasIO/wappalyzer@98814a0 (release 5.8.5+).
- Support for CPE information (as a table column in the GUI, and element in the new API output [as applicable]).
- Allow multi-select of rows to facilitate copy/paste, only show context menu if a single row is selected.

### Added
- Export button.
- API with three views:
  - listSites: Lists the sites that there are application (technology) details for [similar to the host:port drop down menu in the GUI].
  - listAll: Lists all sites and their associated applications (technologies).
  - listSite: Lists all the applications (technologies) for a given site [host:port] identifier.

## [14] - 2019-10-02

- Update apps.json and icons to align with AliasIO/Wappalyzer release 5.8.4 (plus any subsequent PRs).

## [13] - 2019-08-19

- Performance improvements.

## [12] - 2019-04-24

- Switch to using re2j where possible - results in significant performance improvements.
- Added version information column to Wappalyzer Results.
- Updated to align with AliasIO/Wappalyzer release v5.7.4.

## 11 - 2018-01-04

- Minor code changes to address deprecations.
- Updated for latest contributions from main wappalyzer project.

## 10 - 2017-11-28

- Updated for 2.7.0.

## 9 - 2017-11-24

- Updated Wappalyzer github link in help content.
- Code changes for Java 9 (Issue 2602).

## 8 - 2017-03-25

- Remove the use of passive scan rule.
- Minor code cleanup.
- Add support for wappalyzer META tag checks.

## 7 - 2016-06-02

- Allow to update/uninstall the add-on without restarting ZAP.

## 6 - 2016-02-08

- Updated for latest wappalyzer data.

## 5 - 2015-09-07

- Do not access view components when view is not initialised (Issue 1617).

## 4 - 2015-04-13

- Updated to latest apps.json

## 3 - 2014-04-03

- Minor code changes (Issues 503, 1083 and 1085).
- Changed help file structure to support internationalisation (Issue 981).
- Added content-type to help pages (Issue 1080).
- Updated add-on dir structure (Issue 1113).

## 2 - 2014-01-09

- Updated to latest rules and icons

## 1 - 2013-10-22

- First version


[15]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v15
[14]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v14
[13]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v13
[12]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v12
