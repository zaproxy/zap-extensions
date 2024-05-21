# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased


## [21.37.0] - 2024-05-21
### Changed
- Update minimum ZAP version to 2.15.0.
- Updated with enthec upstream icon and pattern changes.
- Maintenance changes (standardize on "Technology Detection" naming).

## [21.36.0] - 2024-05-02
### Fixed
- Implemented a change to address a resource contention issue when loading Tech Detection details (Issue 8464).

### Changed
- Suppress further un-helpful messages from the jsvg library logger.

## [21.35.0] - 2024-04-23
### Changed
- Maintenance changes.

### Fixed
- A typo in the help content.

## [21.34.0] - 2024-04-11
### Changed
- Updated with enthec upstream icon and pattern changes.
- Parallelize loading of the technology files, to improve install/start-up performance.

## [21.33.0] - 2024-03-28
### Changed
- Updated with enthec upstream icon and pattern changes.

## [21.32.0] - 2024-03-04
### Changed
- Updated with enthec upstream icon and pattern changes.
- Maintenance changes.

## [21.31.0] - 2024-02-09
### Changed
- Updated with enthec upstream icon and pattern changes.

## [21.30.0] - 2024-02-05
### Changed
- Updated with enthec upstream icon and pattern changes.
- Made UI strings and help less Wappalyzer centric and more Technology Detection focused.

## [21.29.0] - 2024-01-03
### Changed
- Updated with enthec upstream icon and pattern changes.

## [21.28.0] - 2023-12-04
### Changed
- Updated with enthec upstream icon and pattern changes.
- Dependency updates.

## [21.27.0] - 2023-11-03
### Changed
- Updated with enthec upstream icon and pattern changes.

## [21.26.0] - 2023-10-18
### Changed
- Updated with last AliasIO/Wappalyzer icon and pattern changes.
- Updated with first set of icon and pattern changes from enthec/webappanalyzer.
- Help entries are now identified as 'Technology Detection - Wappalyzer' to simplify searching/filtering.

## [21.25.0] - 2023-10-13
### Changed
- Update minimum ZAP version to 2.14.0.
- Moved from Apache batik libraries to weisJ's jsvg library (thus reducing the size of the add-on).

## [21.24.0] - 2023-09-07
### Changed
- Dependency updates.
- Depend on newer versions of Automation Framework and Common Library add-ons (Related to Issue 7961).

### Fixed
- Ensure icons render when expected.

## [21.23.0] - 2023-08-14
### Changed
- Maintenance changes.
- Update minimum ZAP version to 2.13.0.
- Updated with upstream Wappalyzer icon and pattern changes.

## [21.22.0] - 2023-06-06
### Changed
- Updated with upstream Wappalyzer icon and pattern changes.

## [21.21.0] - 2023-05-03
### Changed
- Updated with upstream Wappalyzer icon and pattern changes.

## [21.20.0] - 2023-04-04
### Changed
- Updated with upstream Wappalyzer icon and pattern changes.

## [21.19.0] - 2023-03-03
### Changed
- Updated with upstream Wappalyzer icon and pattern changes.
- Maintenance changes.

## [21.18.0] - 2023-01-06
### Changed
- Updated with upstream Wappalyzer icon and pattern changes.

## [21.17.0] - 2022-12-13
### Changed
- Updated with upstream Wappalyzer icon and pattern changes.

### Fixed
- Prevent exception if no display (Issue 3978).

## [21.16.0] - 2022-11-14
### Changed
- Updated with upstream Wappalyzer icon and pattern changes.

## [21.15.0] - 2022-11-03
### Changed
- Updated with upstream Wappalyzer icon and pattern changes.

## [21.14.0] - 2022-10-27
### Changed
- Update minimum ZAP version to 2.12.0.
- Updated with upstream Wappalyzer icon and pattern changes.
- Maintenance changes.

## [21.13.0] - 2022-09-23
### Changed
- Maintenance changes.
- Updated with upstream Wappalyzer icon and pattern changes.

## [21.12.0] - 2022-08-15
### Changed
- Maintenance changes.
- Updated with upstream Wappalyzer icon and pattern changes.

## [21.11.0] - 2022-06-03
###Changed
- Updated with upstream Wappalyzer icon and pattern changes.
- Update Wappalyzer URL in help documentation.

### Fixed
- Threading issue - only reproducible with currently unreleased core changes.

## [21.10.0] - 2022-05-03
### Changed
- Updated with upstream Wappalyzer icon and pattern changes.
- Updated the pattern parser to deal with Confidence or Version fields extending DOM patterns (for the time being they're ignored).
- Updated the passive scan rule to be thread safe.

### Fixed
- Address error when generating the report with Java 17 (Issue 6880).

## [21.9.0] - 2022-02-03
### Changed
- Updated with upstream Wappalyzer icon and pattern changes.

## [21.8.0] - 2022-02-02
### Added
- API help content.
- Maintenance changes.

### Changed
- Further support for DOM selector patterns (Issue 6607).

## [21.7.0] - 2022-01-03
### Changed
- Updated with upstream Wappalyzer icon and pattern changes.
- Update minimum ZAP version to 2.11.1.

## [21.6.0] - 2021-12-07
### Changed
- Updated with upstream Wappalyzer icon and pattern changes.
- Dependency updates.

## [21.5.0] - 2021-10-25
### Changed
- Updated with upstream Wappalyzer icon and pattern changes.
- Adapt script source handling to upstream changes.

## [21.4.0] - 2021-10-07
### Changed
- Updated with upstream Wappalyzer icon and pattern changes.
- Updated to handle upstream Wappalyzer data file changes (Issue 6784).
- Update minimum ZAP version to 2.11.0.

## [21.3.0] - 2021-08-25
### Changed
- Updated with upstream Wappalyzer icon and pattern changes.
- Maintenance changes.
- Reduce logging of "Unexpected header type" messages from error to debug (related to Issue 6607).

### Added
- Support for cookie patterns.

## [21.2.0] - 2021-06-17
### Changed
- Updated with upstream Wappalyzer icon and pattern changes.
- Update link to repository.
- Update RE2/J library to latest version (1.6).
- Maintenance changes.
- DOM patterns are now only attempted against HTML responses.

### Added
- Support for automation job data to make it available in reports.

## [21.1.0] - 2021-03-03
### Changed
- Updated with upstream Wappalyzer icon and pattern changes.
- Now using 2.10 logging infrastructure (Log4j 2.x).

### Added
- Support for DOM patterns, aligning with the upstream project (Issue 6180).

## [21.0.0] - 2020-12-15
### Changed
- Updated with upstream Wappalyzer icon and pattern changes.
- Now targeting ZAP 2.10.
- Add-on promoted to Release.
- Dependency updates.

### Added
- Added support for CSS patterns, aligning with upstream project.

## [20.3.0] - 2020-09-30
### Changed
- Updated with upstream Wappalyzer icon and pattern changes.
- Maintenance changes.
- When available the description of a given app/technology will show in the tooltip for a row in the table, and be included in detailed API responses.

## [20.2.0] - 2020-08-04
### Changed
- Updated with upstream Wappalyzer icon and pattern changes.

## [20.1.0] - 2020-06-30
### Changed
- Updated with upstream Wappalyzer icon and pattern changes.

### Fixed
- Correct script matching, check only script elements (Issue 6054).

## [20.0.0] - 2020-06-15
### Changed
- Update RE2/J library to latest version (1.4).
- Add-on promoted to Beta.

### Fixed
- Fixed an exception which was occurring when the tab was shown during install.

## [19] - 2020-06-09
### Changed
- Updated with upstream Wappalyzer icon and pattern changes.
- Wappalyzer's enabled state is now persisted between ZAP sessions.

### Fixed
- Fixed the Evidence context menu now functions properly again.

## [18] - 2020-04-06
### Changed
- Update minimum ZAP version to 2.9.0.
- Update with Wappalyzer icon and pattern changes.
- Maintenance changes.

### Added
- The Wappalyzer toolbar now has a toggle button to allow users to enable/disable the passive scanner simply from the GUI (Issue 5846).

## [17] - 2020-03-06

### Changed
- Update with Wappalyzer icon and pattern changes.

## [16] - 2020-01-24
### Added
- Add info and repo URLs.
- SVG icon support.

### Changed
- The panel is now shown when the add-on is installed.
- The site "names" are now normalized based on scheme and authority (including port if non-standard or specifically included). This represents a breaking change for any API code that is using listSite with host:port "names".
- Fixed an issue where large PNG icons weren't being resized.

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


[21.37.0]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v21.37.0
[21.36.0]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v21.36.0
[21.35.0]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v21.35.0
[21.34.0]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v21.34.0
[21.33.0]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v21.33.0
[21.32.0]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v21.32.0
[21.31.0]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v21.31.0
[21.30.0]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v21.30.0
[21.29.0]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v21.29.0
[21.28.0]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v21.28.0
[21.27.0]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v21.27.0
[21.26.0]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v21.26.0
[21.25.0]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v21.25.0
[21.24.0]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v21.24.0
[21.23.0]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v21.23.0
[21.22.0]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v21.22.0
[21.21.0]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v21.21.0
[21.20.0]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v21.20.0
[21.19.0]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v21.19.0
[21.18.0]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v21.18.0
[21.17.0]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v21.17.0
[21.16.0]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v21.16.0
[21.15.0]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v21.15.0
[21.14.0]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v21.14.0
[21.13.0]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v21.13.0
[21.12.0]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v21.12.0
[21.11.0]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v21.11.0
[21.10.0]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v21.10.0
[21.9.0]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v21.9.0
[21.8.0]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v21.8.0
[21.7.0]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v21.7.0
[21.6.0]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v21.6.0
[21.5.0]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v21.5.0
[21.4.0]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v21.4.0
[21.3.0]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v21.3.0
[21.2.0]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v21.2.0
[21.1.0]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v21.1.0
[21.0.0]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v21.0.0
[20.3.0]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v20.3.0
[20.2.0]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v20.2.0
[20.1.0]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v20.1.0
[20.0.0]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v20.0.0
[19]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v19
[18]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v18
[17]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v17
[16]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v16
[15]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v15
[14]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v14
[13]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v13
[12]: https://github.com/zaproxy/zap-extensions/releases/wappalyzer-v12
