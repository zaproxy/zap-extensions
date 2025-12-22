# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased
### Changed
- Update minimum ZAP version to 2.17.0.

## [7] - 2025-09-18
### Changed
- Update alert reference and help link to latest location.

## [6] - 2025-06-19
### Added
- Updated to Image Location and Privacy Scanner version 1.2; merged from [source](https://github.com/veggiespam/ImageLocationScanner)
    - Updated dependency Metadata Extractor to 2.19.0
    - Added support for scanning HEIF image format used by modern iPhone images
    - Added support for Samsung, more Reconyxs, & Sony camera proprietary privacy leakage 
    - Added detection for a few new information leakage tags in currently supported cameras.
    - Added GPS elevation detection
- The rule has been tagged of interest to Penetration Testers and QA.

### Changed
- Depends on an updated version of the Common Library add-on.
- Update minimum ZAP version to 2.16.0.

### Removed
- No longer support XMP as it was too unreliable.

## [5] - 2024-04-11
### Changed
- Update minimum ZAP version to 2.14.0.
- Maintenance changes.

### Added
- Website alert links (Issue 8189).

## [4] - 2022-09-23
### Changed
- Update minimum ZAP version to 2.11.1.
- Maintenance changes.

### Added
- OWASP Web Security Testing Guide v4.2 mappings.

## [3] - 2021-10-07
### Added
- OWASP Top Ten 2021/2017 mappings.
- Example alert to support documentation efforts.

### Changed
- Update link to repository.
- Update minimum ZAP version to 2.11.0.
- Maintenance changes.

## [2] - 2020-07-03
### Added
- Add info and repo URLs.
- Updated to Image Location and Privacy Scanner version 1.1; merged from [source](https://github.com/veggiespam/ImageLocationScanner) 

### Changed
- Update minimum ZAP version to 2.9.0.
- Maintenance changes.
- Correct repository URL in about help page.

## 1 - 2018-02-27

- Promoted to beta and separated from the passive scan alpha add-on.

[7]: https://github.com/zaproxy/zap-extensions/releases/imagelocationscanner-v7
[6]: https://github.com/zaproxy/zap-extensions/releases/imagelocationscanner-v6
[5]: https://github.com/zaproxy/zap-extensions/releases/imagelocationscanner-v5
[4]: https://github.com/zaproxy/zap-extensions/releases/imagelocationscanner-v4
[3]: https://github.com/zaproxy/zap-extensions/releases/imagelocationscanner-v3
[2]: https://github.com/zaproxy/zap-extensions/releases/imagelocationscanner-v2
