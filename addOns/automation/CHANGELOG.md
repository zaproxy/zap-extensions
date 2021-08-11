# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased
### Fixed
 - Address errors when running an automation plan with spiders and passive scan config.
 - Fixed var support in URLs ([Issue #6726](https://github.com/zaproxy/zaproxy/issues/6726))
 - Job remains selected when moved in the GUI.

## [0.4.1] - 2021-08-07
### Added
- Missing icons

## [0.4.0] - 2021-08-05
### Added
- Support for alert tests
- First phase of GUI

### Changed
- Infrastructure changes to support planned GUI.

## [0.3.0] - 2021-06-28
### Added
- Support for using variables in the config.
- Support for data jobs.
- Support for multiple top level URLs in a context.
- Passive scan config enableTags parameter
- Support for include/exclude regexes.
- Support for param data job
- Support for job tests.
- A new Requestor job to make specific requests.

### Changed
- Update links to repository.
- Maintenance changes.

### Fixed
- NPE in pscan config job when rule specified with no id (as per template).

### Deprecated
- Spider job parameters `failIfFoundUrlsLessThan` and `warnIfFoundUrlsLessThan` in favour of the
`automation.spider.urls.added` statistic test.

## [0.2.0] - 2021-04-12
### Added
- Support for job result data
- Support for passive scan rule configuration

## [0.1.0] - 2021-03-24
### Changed
- Added support for enum parameters.
- Added a new parameter "handleParameters" for the *spider* job.

### Fixed
- A bug where the plan did not stop when it encountered an error or warning and env:parameters:failOnError or env:parameters:failOnWarning was set to true.

## [0.0.1] - 2021-03-09

- First version.

[0.4.1]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.4.1
[0.4.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.4.0
[0.3.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.3.0
[0.2.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.2.0
[0.1.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.1.0
[0.0.1]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.0.1
