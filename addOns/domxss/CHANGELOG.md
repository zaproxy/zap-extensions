# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased


## [19] - 2024-05-07
### Changed
- Update minimum ZAP version to 2.15.0.
- Maintenance changes.

## [18] - 2023-10-12
### Changed
- Update minimum ZAP version to 2.14.0.

## [17] - 2023-09-08
### Changed
- Depend on newer version of Common Library add-on.
- Use vulnerability data directly from Common Library add-on.

## [16] - 2023-07-11
### Changed
- Update minimum ZAP version to 2.13.0.
- Depend on newer version of Selenium add-on.

### Fixed
- Respect global exclusions (Issue 7746).

## [15] - 2023-05-23
### Changed
- Maintenance changes.

### Fixed
- Disable JSON view in Firefox to prevent hangs when the "Save As" option is invoked.

## [14] - 2022-10-27
### Changed
- Update minimum ZAP version to 2.12.0.
- Promoted to Release status.

## [13] - 2022-08-02
### Added
- OWASP Web Security Testing Guide v4.2 mappings.

### Changed
- Update minimum ZAP version to 2.11.1.
- Use Network add-on to proxy browser requests.

### Fixed
- Stop the proxy when ZAP shuts down.

## [12] - 2021-12-06
### Changed
- Dependency updates.

### Added
- Functionality for example alert handling in order to assist in documentation efforts.

## [11] - 2021-10-06
### Added
- OWASP Top Ten 2021/2017 mappings.

### Fixed
- False Positives caused by un-related alerts or Basic auth prompts (Issue 6484).

### Changed
- Update links to repository.
- Maintenance changes.
- Update minimum ZAP version to 2.11.0.

## [10] - 2020-12-15
### Added
- Add info and repo URLs.
- Add link to the code in the help.
- Performance improvements
- Support for Chrome

### Changed
- Update minimum ZAP version to 2.10.0.
- Maintenance changes.
- Promote to beta
- Now clicking on different buttons throughout the page to see if it triggers XSS.

## [9] - 2019-06-12
### Fixed
- Use default browser when no browser is specified in the configuration rule.

## [8] - 2019-06-07
### Changed
- Run with Firefox headless by default (Issue 3866).
- Depend on newer version of Selenium add-on.

## 7 - 2018-03-07

- Issue 2918: Added an option to attack URL parameters.

## 6 - 2018-01-04

- Minor code changes.
- Add XSS Polyglot (Issue 2322).

## 5 - 2017-11-28

- Updated for 2.7.0.

## 4 - 2017-08-18

- Allow to use newer versions of Firefox (Issue 3396).
- Provide the reason why the scanner was skipped.

## 3 - 2016-10-24

- Skip the scanner if not able to start Firefox.

## 2 - 2015-12-04

- Change (duplicated) scanner ID, now it's 40026.

## 1 - 2015-08-24


[19]: https://github.com/zaproxy/zap-extensions/releases/domxss-v19
[18]: https://github.com/zaproxy/zap-extensions/releases/domxss-v18
[17]: https://github.com/zaproxy/zap-extensions/releases/domxss-v17
[16]: https://github.com/zaproxy/zap-extensions/releases/domxss-v16
[15]: https://github.com/zaproxy/zap-extensions/releases/domxss-v15
[14]: https://github.com/zaproxy/zap-extensions/releases/domxss-v14
[13]: https://github.com/zaproxy/zap-extensions/releases/domxss-v13
[12]: https://github.com/zaproxy/zap-extensions/releases/domxss-v12
[11]: https://github.com/zaproxy/zap-extensions/releases/domxss-v11
[10]: https://github.com/zaproxy/zap-extensions/releases/domxss-v10
[9]: https://github.com/zaproxy/zap-extensions/releases/domxss-v9
[8]: https://github.com/zaproxy/zap-extensions/releases/domxss-v8
