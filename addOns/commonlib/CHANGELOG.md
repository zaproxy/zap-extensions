# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
### Changed
- Update minimum ZAP version to 2.17.0.
- Update dependencies.

## [1.38.0] - 2025-10-21
### Added
- SYSTEMIC tag.

### Changed
- Update dependencies.

## [1.37.0] - 2025-10-07
### Added
- Support for alert reference overrides in script scan rule metadata.

## [1.36.0] - 2025-09-18
### Added
- QA CICD policy tag.

## [1.35.0] - 2025-09-02
### Changed
- Update dependency.
- Expose constant related to authentication.

## [1.34.0] - 2025-07-04
### Added
- Added Alert Tags for PCI DSS and HIPAA standards.
- Added a help page for the alert tags provided through this add-on.

## [1.33.0] - 2025-06-20
### Added
- Constants related to authentication.

## [1.32.0] - 2025-04-09
### Added
- Add an alert tag for scan rules that are believed to be of interest to Penetration Testers (essentially everything except the Example rules).

## [1.31.0] - 2025-03-25
### Added
- Replace the default Output panel with a tabbed version to allow multiple sources of output to be displayed in separate tabs.
- Add support functionality for usage of TOTP data defined under user credentials.

## [1.30.0] - 2025-01-09
### Added
- Add solutions to Insufficient Process Validation vulnerability (Issue 8056).

### Changed
- Update minimum ZAP version to 2.16.0.
- Improve solution and add more references to 'Information Leakage' vulnerability (Issue 8056).

## [1.29.0] - 2024-12-23
### Changed
- Dependency updates.
- Let the Value Generator add-on provide the custom values through this add-on (Issue 8016).

### Added
- Policy tags for use with scan rules and the new Scan Policies add-on.

### Fixed
- Be more lenient with the input used for providing values, to prevent exceptions.

## [1.28.0] - 2024-09-24
### Changed
- Maintenance changes.

## [1.27.0] - 2024-09-02
### Fixed
- Address false positives/negatives when handling cookies without name value pair separator (Issue 8613).

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

[1.38.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.38.0
[1.37.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.37.0
[1.36.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.36.0
[1.35.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.35.0
[1.34.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.34.0
[1.33.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.33.0
[1.32.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.32.0
[1.31.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.31.0
[1.30.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.30.0
[1.29.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.29.0
[1.28.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.28.0
[1.27.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.27.0
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
