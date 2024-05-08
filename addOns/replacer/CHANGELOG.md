# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased


## [18] - 2024-05-08
### Added
- Rules to disable Caching (Issue 8437).

## [17] - 2024-05-07
### Changed
- Update minimum ZAP version to 2.15.0.

### Added
- Video link in help for Automation Framework job.
- A rule to disable CSP reporting (Issue 740).

## [16] - 2023-11-30
### Changed
- Allow to replace (change or remove) the Host header (Issue 5475).

## [15] - 2023-10-12
### Changed
- Update minimum ZAP version to 2.14.0.

## [14] - 2023-09-07
### Added
- Support for the Automation Framework (Issue 7686).

### Changed
- Document that Token Processing applies just to string match types and disable the field in
the dialogue when other match types are selected.

## [13] - 2023-07-11
### Changed
- Update minimum ZAP version to 2.13.0.
- Maintenance changes.

## [12] - 2023-01-03
### Added
- Added special replacement string processing for:
  - Random Integer
  - UUID
  - Epoch Milliseconds

### Changed
- Maintenance changes.

## [11] - 2022-10-27
### Changed
- Update minimum ZAP version to 2.12.0.

### Added
- Allow the rules to apply to specific URLs (Issue 4793).

## [10] - 2022-09-23
### Fixed
- Allow the replacement type to be changed in existing rules (Issue 3840).

### Added
 - Allow to manage the replacer rules programmatically, for example, through ZAP scripts.

### Changed
- Update minimum ZAP version to 2.11.1.
- Maintenance changes.
- Promoted to Release status.

## [9] - 2021-10-06
### Changed
- Update minimum ZAP version to 2.11.0.
- Update links to zaproxy repo.
- Maintenance changes.

## [8] - 2020-01-17

### Added
 - Add info and repo URLs.
 - Allow byte replacement using hexadecimal escapes (Issue 5328).

### Fixed
 - Fix link in API endpoint description.

## 7 - 2018-10-26

- Maintenance changes.
- API, Replacement String should not be mandatory (Issue 5080).

## 6 - 2018-06-12

- Tweak help page.
- Ignore CFU HTTP messages.
- Allow to (explicitly) select Token Generator messages.

## 5 - 2018-01-19

- Fix exception during ZAP start up.

## 4 - 2017-11-27

- Updated for 2.7.0.

## 3 - 2017-06-23

- Added API support

## 2 - 2017-04-03

- Promoted to beta

## 1 - 2017-02-01

- First version

[18]: https://github.com/zaproxy/zap-extensions/releases/replacer-v18
[17]: https://github.com/zaproxy/zap-extensions/releases/replacer-v17
[16]: https://github.com/zaproxy/zap-extensions/releases/replacer-v16
[15]: https://github.com/zaproxy/zap-extensions/releases/replacer-v15
[14]: https://github.com/zaproxy/zap-extensions/releases/replacer-v14
[13]: https://github.com/zaproxy/zap-extensions/releases/replacer-v13
[12]: https://github.com/zaproxy/zap-extensions/releases/replacer-v12
[11]: https://github.com/zaproxy/zap-extensions/releases/replacer-v11
[10]: https://github.com/zaproxy/zap-extensions/releases/replacer-v10
[9]: https://github.com/zaproxy/zap-extensions/releases/replacer-v9
[8]: https://github.com/zaproxy/zap-extensions/releases/replacer-v8
