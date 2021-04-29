# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased

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

[0.2.0]: https://github.com/zaproxy/zap-extensions/releases/reports-v0.2.0
[0.1.0]: https://github.com/zaproxy/zap-extensions/releases/reports-v0.1.0
[0.0.1]: https://github.com/zaproxy/zap-extensions/releases/reports-v0.0.1
