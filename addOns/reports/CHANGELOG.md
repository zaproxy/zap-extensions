# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased
### Fixed
- Prevent exception if no display (Issue 3978).

## [0.17.0] - 2022-11-22
### Added
- SARIF reporting

### Changed
- The XML and JSON reports now include programName metadata elements (Issue 6640).

## [0.16.0] - 2022-10-27
### Added
- "XML Plus" report format for XML with requests and responses
- Tags to "JSON Plus" report.

### Changed
- Update minimum ZAP version to 2.12.0.
- Maintenance changes.

### Fixed
- Correct the ID of reports' sections in the help.

## [0.15.0] - 2022-07-20

### Fixed
- API problems:
  - Mixed case sections could not be referenced
  - Risk-confidence-html report failed if no context specified
  - No theme is used if one was not specified, breaking theme links

## [0.14.0] - 2022-06-22
### Changed
- Maintenance changes.

### Fixed
- Exceptions when generating some reports without the Automation add-on being installed.

## [0.13.0] - 2022-04-05
### Changed
- Dependency updates.
- Replace variables present in `reportDir` and `reportFile` when running the automation job.

## [0.12.0] - 2022-02-11
### Changed
- Maintenance changes.

### Fixed
- Problem generating 'Risk and Confidence HTML' report with Java 17 (Issue 7026)

## [0.11.0] - 2022-02-08
### Added
- Traditional-json-plus report
- Template specific help pages
- Report generation statistics

### Changed
- Update minimum ZAP version to 2.11.1.
- Dependency updates.
- When the automation Job is edited via UI Dialog then the status will be set to Not started

## [0.10.0] - 2021-12-06
### Changed
- Dependency updates.
- Maintenance changes.

## [0.9.1] - 2021-10-14
### Fixed
- Made ReportHelper methods more defensive

## [0.9.0] - 2021-10-14
### Fixed
- Incorrect alert instances associated with alerts which have the same IDs (Issue 6873)

## [0.8.0] - 2021-10-07
### Added
- Default report title and description to new report jobs.

### Fixed
- risk-confidence-html template: guard against scanJobResultData being null; fix handling of empty paragraphs and nulls; and do not include description section if description is null or empty.

## [0.7.0] - 2021-10-06
### Added
- Support for custom messages in outputSummary job.
- Alert tags to the modern and traditional-plus reports.
- risk-confidence-html template.

### Changed
- Promoted to release.
- Minimum ZAP version 2.11.0

### Fixed
- Ignore false positives when listing messages in the outputSummary job.
- Bug in report job add-on which prevented the right theme from being used
- Added missing Modern template i18n messages

## [0.6.0] - 2021-09-16
### Fixed
- Address errors when running the OutputSummary job with Automation Framework.
- Alert counts to ignore false positives.

### Changed
- Maintenance changes.

## [0.5.0] - 2021-08-05
### Added
- Automation Framework 'theme' parameter.
- Automation Framework GUI

### Changed
- Maintenance changes.

## [0.4.0] - 2021-06-28
### Added
- Wappalyzer data to the traditional-html-plus report, if it is available.
- Traditional JSON report
- Automation job: outputSummary, aimed at mimicking the output of the packaged scans.
- Modern template - submitted via the ZAP Reporting Competition
- Parameter data to the traditional-html-plus report
- Methods to make it easier to generate reports from other add-ons

### Changed
- Maintenance changes.
- Handle multiple context URLs in automation.
- Traditional plus report - link to zaproxy.org pages for passing scan rules.
- Update links to repository.

### Fixed
- Include all relevant alerts in XML report templates (Issue 6627).
- Made XML reports more backwards compatible and fixed issue with generating it via the API.
- Issue with reports for sites with trailing slashes

## [0.3.0] - 2021-05-06
### Added
- API Support.
- Support for statistics

### Changed
- Maintenance Changes.
- Promote to beta

### Fixed
- Correct logging of dependency.
- Inconsistencies between traditional reports and the 'old' core ones
- Do not rely on default encoding when creating the reports, use UTF-8 always (Issue 6561).

## [0.2.0] - 2021-04-12

### Added
- Support for template sections
- Automation job: support risk, confidence and section configuration
- Passing rules to traditional plus HTML report

### Changed
- Format HTML and XML templates as part of the build

## [0.1.0] - 2021-03-19

### Added
- Support for resources such as JavaScript and images
- Support for template specific i18n property files
- Reload templates on dir change and handle no reports

## [0.0.1] - 2021-03-09

- First version.

[0.17.0]: https://github.com/zaproxy/zap-extensions/releases/reports-v0.17.0
[0.16.0]: https://github.com/zaproxy/zap-extensions/releases/reports-v0.16.0
[0.15.0]: https://github.com/zaproxy/zap-extensions/releases/reports-v0.15.0
[0.14.0]: https://github.com/zaproxy/zap-extensions/releases/reports-v0.14.0
[0.13.0]: https://github.com/zaproxy/zap-extensions/releases/reports-v0.13.0
[0.12.0]: https://github.com/zaproxy/zap-extensions/releases/reports-v0.12.0
[0.11.0]: https://github.com/zaproxy/zap-extensions/releases/reports-v0.11.0
[0.10.0]: https://github.com/zaproxy/zap-extensions/releases/reports-v0.10.0
[0.9.1]: https://github.com/zaproxy/zap-extensions/releases/reports-v0.9.1
[0.9.0]: https://github.com/zaproxy/zap-extensions/releases/reports-v0.9.0
[0.8.0]: https://github.com/zaproxy/zap-extensions/releases/reports-v0.8.0
[0.7.0]: https://github.com/zaproxy/zap-extensions/releases/reports-v0.7.0
[0.6.0]: https://github.com/zaproxy/zap-extensions/releases/reports-v0.6.0
[0.5.0]: https://github.com/zaproxy/zap-extensions/releases/reports-v0.5.0
[0.4.0]: https://github.com/zaproxy/zap-extensions/releases/reports-v0.4.0
[0.3.0]: https://github.com/zaproxy/zap-extensions/releases/reports-v0.3.0
[0.2.0]: https://github.com/zaproxy/zap-extensions/releases/reports-v0.2.0
[0.1.0]: https://github.com/zaproxy/zap-extensions/releases/reports-v0.1.0
[0.0.1]: https://github.com/zaproxy/zap-extensions/releases/reports-v0.0.1
