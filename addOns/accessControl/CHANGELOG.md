# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased
### Changed
- Update minimum ZAP version to 2.15.0.

## [10] - 2024-03-25
### Changed
- Update minimum ZAP version to 2.14.0.
- Maintenance changes.
- Link website alert pages and help (Issues 8189).
- The results table now presents the same context menu as other similar tables (History, Search, etc) facilitating copying URLs, etc (Issue 8356).
- Now has a table export button (Issue 8356).
- Adjusted some labels/titles to use title caps (Issue 2000 & 8356).

### Fixed
- Now uses the General Font (Issue 8356), as set in the Display options.

## [9] - 2023-09-08
### Added
- Add OWASP Top 10 tags to the alerts raised.
- The add-on now includes example alert functionality for documentation generation purposes (Issue 6119).

### Changed
- Update minimum ZAP version to 2.13.0.
- Depend on Common Library add-on.
- Use vulnerability data directly from Common Library add-on.
- Maintenance changes.

## [8] - 2022-10-28
### Changed
- Maintenance changes.
- Update minimum ZAP version to 2.12.0.

## [7] - 2021-10-07
### Changed
- Don't set the font color for inherited entries (Issue 6397).
- Update minimum ZAP version to 2.11.0.
- Maintenance changes (some changes impact the visibility of variables and add getters/setters, which may impact third party add-ons or scripts).
- Change to no longer rely on core report classes, which are going to be deleted.

## [6] - 2020-10-06

### Added
- Add API support.
- Add info and repo URLs.

### Changed
- Update minimum ZAP version to 2.9.0.

## 5 - 2018-11-02

- Respect the current mode and react to changes.
- Dynamically unload the add-on.
- Inform of running tests (e.g. on session change, add-on uninstall).
- Improve error handling during test.
- Tweak alerts to use Other Info field instead of Attack/Evidence.

## 4 - 2017-11-28

- Updated for 2.7.0.

## 3 - 2017-11-24

- Fix exception that occurred with Java 9 (Issue 3934).
- Allow to copy multiple results and copy correct value from the result column.
- Display correct message when the table is sorted.

## 2 - 2016-06-02

- Fix an exception when cancelling the "Save" access control report dialogue.
- Do not allow to dynamically uninstall, not yet supported.

## 1 - 2015-04-13

- Initial version

[10]: https://github.com/zaproxy/zap-extensions/releases/accessControl-v10
[9]: https://github.com/zaproxy/zap-extensions/releases/accessControl-v9
[8]: https://github.com/zaproxy/zap-extensions/releases/accessControl-v8
[7]: https://github.com/zaproxy/zap-extensions/releases/accessControl-v7
[6]: https://github.com/zaproxy/zap-extensions/releases/accessControl-v6
