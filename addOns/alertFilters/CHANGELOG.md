# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased


## [21] - 2024-05-07
### Changed
- Update minimum ZAP version to 2.15.0.

## [20] - 2024-04-02
### Added
- Video link in help for Automation Framework job.

### Changed
- Reword label in the automation job to prevent any confusion between the Alert Filters and the Alerts.
- Maintenance changes.

## [19] - 2023-11-16
### Changed
- Allow to filter by alert reference (Issue 7438).
- Allow to specify custom IDs through the GUI.
- Maintenance changes.

### Fixed
- Do not fail to import or load a context with invalid alert filters.
- Incorrect warning about 'Unrecognised parameter' for deleteGlobalAlerts.
- Persist context filter data.

## [18] - 2023-10-12
### Changed
- Update minimum ZAP version to 2.14.0.
- Maintenance changes.
- Depend on newer version of Automation Framework add-on for the automation job (Related to Issue 7961).

## [17] - 2023-07-11
### Changed
- Update minimum ZAP version to 2.13.0.

### Fixed
- Allow to filter Directory Browsing (ID 0) alerts through the Automation Framework job, previously would report as a missing ID.

## [16] - 2023-06-12
### Added
- Allow to specify the HTTP method when filtering the alerts (Issue 5967).

### Changed
- Maintenance changes.

## [15] - 2023-01-03
### Changed
- Maintenance changes.

### Fixed
- Prevent exception if no display (Issue 3978).

## [14] - 2022-10-27
### Changed
- Update minimum ZAP version to 2.12.0.
- When the automation Job is edited via UI Dialog then the status will be set to Not started
- Maintenance changes.

### Fixed
- Include the ID when listing scan rules, to allow to differentiate scan rules with the same name (Issue 5699).

## [13] - 2021-10-06
### Added
- Stats for alerts changed

### Changed
- Update minimum ZAP version to 2.11.0.

### Fixed
- Dialogs being shown under the owning dialog / frame.

## [12] - 2021-09-16
### Added
- Support for the Automation Framework

## [11] - 2021-07-29
### Changed
- Update minimum ZAP version to 2.10.0.
- Maintenance changes.

### Added
- API endpoints "applyAll", "applyContext", and "applyGlobal" to apply enabled Alert Filters to existing alerts (Issue 5966).
- API endpoints "testAll", "testContext", and "testGlobal" to test enabled Alert Filters against existing alerts.

## [10] - 2020-01-17
### Added
- Add info and repo URLs.

## [9] - 2019-09-30

- Added support for parameter regex, attack and evidence strings and regexes (Issue 5574)
- Added support for global alert filters (Issue 5575)
- Added option to create alert filters from alert
- Added options to test which alerts will apply to and to actually apply them
- Removed the "Context" from the add-on name
- Promote Alert Filters addon to release status

## [8] - 2019-06-07

- Correct required state of an API parameter.
- Add description to API endpoints.

## 7 - 2018-02-15

- Fix an exception when running ZAP in daemon mode (Issue 4405).

## 6 - 2017-11-27

- Updated for 2.7.0.

## 5 - 2017-11-24

- Dynamically unload the add-on.
- Clear filters on session changes (Issue 3683).

## 4 - 2017-04-03

- Minor functional improvement.

## 3 - 2016-06-02

- Various minor UI improvements

## 2 - 2016-03-22

- Updated to use alertIds from 2.4.3+
- Misc minor bug fixes
- HTML report reports the filtered false positives as true results (Issue 2311)
- Promoted to beta and added icon
- Various minor UI improvements

## 1 - 2015-09-07

- First version

[21]: https://github.com/zaproxy/zap-extensions/releases/alertFilters-v21
[20]: https://github.com/zaproxy/zap-extensions/releases/alertFilters-v20
[19]: https://github.com/zaproxy/zap-extensions/releases/alertFilters-v19
[18]: https://github.com/zaproxy/zap-extensions/releases/alertFilters-v18
[17]: https://github.com/zaproxy/zap-extensions/releases/alertFilters-v17
[16]: https://github.com/zaproxy/zap-extensions/releases/alertFilters-v16
[15]: https://github.com/zaproxy/zap-extensions/releases/alertFilters-v15
[14]: https://github.com/zaproxy/zap-extensions/releases/alertFilters-v14
[13]: https://github.com/zaproxy/zap-extensions/releases/alertFilters-v13
[12]: https://github.com/zaproxy/zap-extensions/releases/alertFilters-v12
[11]: https://github.com/zaproxy/zap-extensions/releases/alertFilters-v11
[10]: https://github.com/zaproxy/zap-extensions/releases/alertFilters-v10
[9]: https://github.com/zaproxy/zap-extensions/releases/alertFilters-v9
[8]: https://github.com/zaproxy/zap-extensions/releases/alertFilters-v8
