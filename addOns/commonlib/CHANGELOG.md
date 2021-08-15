# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased


## [1.4.0] - 2021-06-23
### Added
- An HTTP date parser/formatter.

### Fixed
- Take into account the timezone when checking if a cookie is expired (Issue 6550).

## [1.3.0] - 2021-05-10
### Added
- Added AbstractHostFilePlugin for use with ElmahScanRule and other future Host level file scan rules (Issue 6133).
- Maintenance changes (Issue 6376 & Issue 6099).
- Added DiceMatcher, which implements the Dice algorithm to calculate the percentage similarity between two strings.

## [1.2.0] - 2020-12-15
### Changed
- Update minimum ZAP version to 2.10.0.
- AbstractAppFilePlugin > ensure that test requests are appropriately rebuilt for this type of scan rule (Issue 6129). This will make the following Alpha and Beta active scan rules slightly more accurate:
  - Trace.axd, .env File, .htaccess file

## [1.1.0] - 2020-08-04
### Changed
- AbstractAppFilePlugin > don't raise issues for responses other than 200 - Ok unless at LOW threshold (Issue 6077). This will make the following Alpha and Beta active scan rules slightly less False Positive prone:
  - Trace.axd, .env File, .htaccess file

## [1.0.0] - 2020-05-21

First version.

[1.4.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.4.0
[1.3.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.3.0
[1.2.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.2.0
[1.1.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.1.0
[1.0.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.0.0
