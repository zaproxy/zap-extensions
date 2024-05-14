# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased


## [1.26.0] - 2024-05-10
### Added
- Include the Jackson Datatype: JSR310 library for other add-ons to use.

## [1.25.0] - 2024-05-07
### Added
- Support for code and help links for script scan rules.
### Changed
- Update minimum ZAP version to 2.15.0.
- Maintenance changes.

## [1.24.0] - 2024-04-11
### Added
- Helper classes for scripts used as scan-rules (Issue 7105).

## [1.23.0] - 2024-03-25
### Added
- Support for menu weights (Issue 8369)
- Add solution to HTTP Response Smuggling alert (Issue 8056)

### Changed
- Maintenance changes.

## [1.22.0] - 2024-01-26
### Added
- Add alert tag for scan rules that use time based tests.

## [1.21.0] - 2024-01-16
### Added
- Add solution to 'Server Misconfiguration' and 'Application Misconfiguration' vulnerabilities (Issue 8056).

### Changed
- Update Vulnerabilities' references to use https links and retire some which were out-dated (Issue 8262).
- Maintenance changes.

## [1.20.0] - 2023-12-07

### Changed
- Dependency updates.

### Added
- Add utilities for time-based checks, migrated from Active scanner rules add-on.

### Changed
- Added solution to 'Insecure Indexing', 'Insufficient Anti automation', 'Fingerprinting' (Issue 8056).

## [1.19.0] - 2023-11-10
### Added
- A generic UI component for keeping menu items sorted.

### Changed
- Add solution to 'Brute Forcing Credit Card Information', 'Content Spoofing', 'Credential and Session Prediction', 'XML Injection' and 'XML External Entities' vulnerabilities (Issue 8056).

## [1.18.0] - 2023-10-12
### Changed
- Update minimum ZAP version to 2.14.0.
- Add solution to 'Brute Forcing Log-in Credentials', 'Brute Forcing Session Identifiers' and 'Brute Forcing Directories and Files' vulnerabilities (Issue 8056).
- Update vulnerabilities' CWE references to use HTTPS scheme.

## [1.17.0] - 2023-09-07
### Added
- Provide Jackson datatype library for other add-ons (Issue 7961).
- Provide the Value Generator for other add-ons (Issue 8016).
- Provide vulnerability data, migrated from core (Issue 8012).

## [1.16.0] - 2023-08-14
### Added
- Provide Jackson parsing library, to reuse the library in other add-ons (Issue 7961).

### Changed
- Maintenance changes.

## [1.15.0] - 2023-07-11
### Changed
- Update minimum ZAP version to 2.13.0.
- Dependency updates.

## [1.14.0] - 2023-02-24
### Fixed
- Comparable Response functionality is now more robust and doesn't fail when processing types other than JSON Object (Issue 7736).

## [1.13.0] - 2023-02-03
### Changed
- Maintenance changes.

### Added
- Add info URL.
- Constant for default number of threads.

### Fixed
- Correctly parse cookie name when set-cookie header value doesn't end with semicolon.

## [1.12.0] - 2022-12-13
### Added
- Provide HTTP Fields names.

### Changed
- Maintenance changes.

## [1.11.0] - 2022-10-27
### Changed
- Update minimum ZAP version to 2.12.0.

## [1.10.0] - 2022-09-15
### Changed
- Maintenance changes.

## [1.9.0] - 2022-03-21
### Changed
- Maintenance changes.

## [1.8.0] - 2022-03-07
### Added
- A generic component for displaying progress, such as when importing an openapi definition (Issue 6783).

### Changed
- Maintenance changes.

## [1.7.0] - 2022-02-02
### Changed
- Update minimum ZAP version to 2.11.1.

### Added
- Maintenance changes (Issue 6810).

## [1.6.0] - 2021-12-01
### Changed
- Dependency updates.
- Add OWASP WSTG v4.2 Alert Tags.

### Fixed
- Adjusted the tag of "OWASP_A10_LOGGING_FAIL" to match other alert tags for 2017/2021.

## [1.5.0] - 2021-10-06
### Added
- Common alert tags for OWASP Top Ten 2021 and 2017.

### Changed
- Update minimum ZAP version to 2.11.0.

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

[1.26.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.26.0
[1.25.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.25.0
[1.24.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.24.0
[1.23.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.23.0
[1.22.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.22.0
[1.21.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.21.0
[1.20.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.20.0
[1.19.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.19.0
[1.18.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.18.0
[1.17.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.17.0
[1.16.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.16.0
[1.15.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.15.0
[1.14.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.14.0
[1.13.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.13.0
[1.12.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.12.0
[1.11.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.11.0
[1.10.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.10.0
[1.9.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.9.0
[1.8.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.8.0
[1.7.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.7.0
[1.6.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.6.0
[1.5.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.5.0
[1.4.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.4.0
[1.3.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.3.0
[1.2.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.2.0
[1.1.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.1.0
[1.0.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.0.0
