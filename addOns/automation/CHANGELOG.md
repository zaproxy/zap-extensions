# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased
### Changed
- Maintenance changes.

### Fixed
- Show each context URL in its own line when editing in the GUI (Issue 7241).
- Correct error messages.

## [0.15.0] - 2022-04-25
### Added
- Test type to check for presence of a URL.

### Changed
- Maintenance changes.

### Fixed
- Use correct authentication verification method for `request`.
- Exceptions when using the GUI.

## [0.14.0] - 2022-04-05
### Added
- Import Job profile (Issue 7078).

### Changed
- The ascan job 'Scan All Header' GUI label

### Fixed
- Register plans run by -autorun to prevent NPEs when editing them
- Issue when turning off specific active scan rules

## [0.13.0] - 2022-02-25
### Fixed
- Issue when adding or removing add-ons via the UI (Issue 7075)
- Issue when creating a script session management with parameters from an existing context

## [0.12.0] - 2022-02-01
### Added
- Script authentication support

### Fixed
- When a Job is loaded via yaml and edited via UI Dialog then the saved changes will be applied on the next job run
- DelayJob will be verified on yaml load

### Changed
- When a Job is edited via UI Dialog then the status will be set to Not started

## [0.11.0] - 2022-01-19
### Added
- Support for generating stats
- Form and JSON-based authentication support

### Changed
- Promoted to beta

## [0.10.1] - 2022-01-05
### Fixed
- Ensure system environment variables take precedence over configuration variables (Issue 7000).

## [0.10.0] - 2021-12-13
### Changed
- Update minimum ZAP version to 2.11.1.

### Fixed
- Setting delay job parameters from the commandline

## [0.9.0] - 2021-12-06

### Changed
- Disabled addOns job updateAddOns option due to problems updating the framework and jobs while they are running

## [0.8.0] - 2021-11-02
### Added
- Delay job
- Session management support
- User and HTTP authentication support
- Authentication verification support
- Set ZAP exit code when "-cmd" and "-autorun" options used
- Requestor, Spider and ActiveScan jobs changed to support an authenticated user
- Support for site specific statistics

### Changed
- Dependency updates.

### Fixed
- Plans saved without default ".yaml" extension.
- Env vars in context names replaced on load, so lost if the plan saved again via the GUI.

## [0.7.0] - 2021-10-06
### Added
 - API support: runplan action and planprogress view.
### Changed
 - Maintenance changes.
- Update minimum ZAP version to 2.11.0.

### Fixed
 - "Unexpected obj object java.lang.String" error shown during initialization

## [0.6.0] - 2021-09-16
### Changed
 - Maintenance changes.

## [0.5.0] - 2021-08-23
### Fixed
 - Address errors when running an automation plan with spiders and passive scan config.
 - Fixed var support in URLs ([Issue #6726](https://github.com/zaproxy/zaproxy/issues/6726))
 - Always enable the Save button on changes and prompt user when opening a plan if the current one has changes.

### Changed
 - Changes to support the Retest add-on.

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

[0.15.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.15.0
[0.14.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.14.0
[0.13.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.13.0
[0.12.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.12.0
[0.11.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.11.0
[0.10.1]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.10.1
[0.10.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.10.0
[0.9.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.9.0
[0.8.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.8.0
[0.7.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.7.0
[0.6.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.6.0
[0.5.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.5.0
[0.4.1]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.4.1
[0.4.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.4.0
[0.3.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.3.0
[0.2.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.2.0
[0.1.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.1.0
[0.0.1]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.0.1
