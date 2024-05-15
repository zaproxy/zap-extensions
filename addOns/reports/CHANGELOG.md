# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased


## [0.32.0] - 2024-05-07
### Changed
- Update minimum ZAP version to 2.15.0.
- The following reports now include the number of Sites tree nodes actively scanned:
  - Traditional HTML with Requests and Responses

## [0.31.0] - 2024-03-25
### Changed
- Tweaked OSF sponsorship links.

### Fixed
- Handle alerts without HTTP message gracefully (Issue 6880).
- More issues with illegal XML characters in pdf reports (Issue 8330).

## [0.30.0] - 2024-03-13
### Changed
- Added OSF sponsorship line to reports.

## [0.29.0] - 2024-02-12
### Fixed
- Error message to give report name.
- Issues with illegal XML characters in pdf reports (Issue 8330).
- Corrected pdf report href from #olugin to #plugin.
- Deprecated syntax in risk-confidence report.

## [0.28.0] - 2024-01-16
### Changed
- Default to same dir as plan if none specified.

### Fixed
- Ensure the Sections' options are fully shown always in Generate Report Dialog (Issue 8259).
- Replace env vars in URL when used for report file name.

## [0.27.0] - 2023-12-19
### Changed
- Dependency updates.

### Fixed
- Addressed warnings caused by Risk and Confidence HTML template.

## [0.26.0] - 2023-10-12
### Changed
- Update minimum ZAP version to 2.14.0.

## [0.25.0] - 2023-10-04
### Changed
- Depend on newer versions of Automation Framework and Common Library add-ons (Related to Issue 7961).
- Update JavaDoc links to always link to latest version of ZAP.

### Fixed
- Fix error when generating the High Level Report Sample with an alert that has an empty description (Issue 8071).

## [0.24.0] - 2023-08-17
### Changed
- Maintenance changes.
- The following reports now include "Other Info" for alerts:
    - Traditional HTML Report
    - Traditional HTML Report with requests and responses
    - Traditional Markdown Report
    - Traditional PDF Report
- Depend on Common Library add-on to reuse libraries (Issue 7961).
- Update program name in reports.

## [0.23.0] - 2023-07-11
### Changed
- Update minimum ZAP version to 2.13.0.
- Reduce add-on size.
- Dependency updates.

## [0.22.0] - 2023-06-12
### Added
- Automation job: support for sites (Issue 7858).

### Fixed
- Change SARIF's Base64 encoder to not rely on the default character encoding.

## [0.21.0] - 2023-06-06
### Added
- Add ZAP version to HTML and PDF reports.

### Fixed
- Validate that `outputSummary`'s job field `summaryFile` has a parent directory.

## [0.20.0] - 2023-04-04

### Added
- The Traditional JSON report, Traditional JSON Report with requests and responses, Traditional XML Report and Traditional XML Report with requests and responses now has "otherinfo" field per alert instance (Issue 7260).

### Changed
- Include templates available when reporting invalid template in the automation job.

### Deprecated
- The "otherinfo" field in the alert will be removed and replaced by the "otherinfo" field in the alert instances.

### Fixed
- Correct ID of Markdown template listed in the help page.

## [0.19.0] - 2023-02-09

### Added
- A description of riskdesc fields in the relevant report templates' help (Issue 7445).
- Support for relative report file and directory names in the Automation Framework job.

### Changed
- Maintenance changes.

## [0.18.0] - 2023-01-03
### Changed
- Maintenance changes.

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

[0.32.0]: https://github.com/zaproxy/zap-extensions/releases/reports-v0.32.0
[0.31.0]: https://github.com/zaproxy/zap-extensions/releases/reports-v0.31.0
[0.30.0]: https://github.com/zaproxy/zap-extensions/releases/reports-v0.30.0
[0.29.0]: https://github.com/zaproxy/zap-extensions/releases/reports-v0.29.0
[0.28.0]: https://github.com/zaproxy/zap-extensions/releases/reports-v0.28.0
[0.27.0]: https://github.com/zaproxy/zap-extensions/releases/reports-v0.27.0
[0.26.0]: https://github.com/zaproxy/zap-extensions/releases/reports-v0.26.0
[0.25.0]: https://github.com/zaproxy/zap-extensions/releases/reports-v0.25.0
[0.24.0]: https://github.com/zaproxy/zap-extensions/releases/reports-v0.24.0
[0.23.0]: https://github.com/zaproxy/zap-extensions/releases/reports-v0.23.0
[0.22.0]: https://github.com/zaproxy/zap-extensions/releases/reports-v0.22.0
[0.21.0]: https://github.com/zaproxy/zap-extensions/releases/reports-v0.21.0
[0.20.0]: https://github.com/zaproxy/zap-extensions/releases/reports-v0.20.0
[0.19.0]: https://github.com/zaproxy/zap-extensions/releases/reports-v0.19.0
[0.18.0]: https://github.com/zaproxy/zap-extensions/releases/reports-v0.18.0
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
