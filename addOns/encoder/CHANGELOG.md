# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased


## [1.5.0] - 2024-05-07
### Added
- Support for menu weights (Issue 8369)
### Changed
- Update minimum ZAP version to 2.15.0.
- Maintenance changes.

## [1.4.0] - 2023-10-12
### Changed
- Update minimum ZAP version to 2.14.0.

## [1.3.0] - 2023-09-08
### Changed
- Maintenance changes.

### Fixed
- Do not rely on the default charset in Full URL and ASCII Hex encoders/decoders.

## [1.2.0] - 2023-07-11
### Changed
- Update minimum ZAP version to 2.13.0.

## [1.1.0] - 2023-03-13
### Changed
- Maintenance changes.

### Added
- A context menu active on the output text areas facilitating the replacement of input text.
- PowerShell encoder (hat tip to hackvertor/hackvertor#71 for the idea and details).

## [1.0.0] - 2022-12-15

### BREAKING CHANGE
- Existing scripts will fail as the process method signature has changed, scripts can be fixed by changing the signature from: process(value) to process(helper, value).

### Changed
- Maintenance changes.
- Add-on promoted to Release status.
- Allow script processors to return strings without requiring an "EncodeDecodeResult" wrapper.
- Show help and options buttons in the main dialog.
- The Base64 decoder now uses a Mime decoder and handles line wrapped input.
- Updated script templates to use the new process method.

### Added
- Add an option which controls whether or not Hash output panels use full caps or lower case (Issue 7503).
- Utility processors (not shown by default).
    - Lower case
    - Remove Whitespace
    - Reverse
    - Upper case

## [0.7.0] - 2022-10-27
### Changed
- Maintenance changes.
- Update minimum ZAP version to 2.12.0.

### Added
- A Full HTML Entity encoder (Issue 2222).

## [0.6.0] - 2021-10-06
### Changed
- Maintenance changes.
- Update minimum ZAP version to 2.11.0.

### Removed
- Groovy default template moved to Groovy add-on.

## [0.5.0] - 2021-02-08
### Changed
- Remove "Advanced" in help page.

## [0.4.0] - 2020-12-15

### Changed
- Promoted to Beta.
- Added Info URL to manifest.
- Target ZAP 2.10. Remove "Advanced" from labels, titles, and name.

## [0.3.0] - 2020-09-14

### Added
- rot13.js example script.
- SHA256 predefined processor.
- Full URL Encode predefined processor (Issue 6171).

## [0.2.0] - 2020-06-01

### Added
- Help information.
- Base64 character set and line break options, including migration of settings from core component.


## [0.1.0] - 2020-05-20

- First version.

[1.5.0]: https://github.com/zaproxy/zap-extensions/releases/encoder-v1.5.0
[1.4.0]: https://github.com/zaproxy/zap-extensions/releases/encoder-v1.4.0
[1.3.0]: https://github.com/zaproxy/zap-extensions/releases/encoder-v1.3.0
[1.2.0]: https://github.com/zaproxy/zap-extensions/releases/encoder-v1.2.0
[1.1.0]: https://github.com/zaproxy/zap-extensions/releases/encoder-v1.1.0
[1.0.0]: https://github.com/zaproxy/zap-extensions/releases/encoder-v1.0.0
[0.7.0]: https://github.com/zaproxy/zap-extensions/releases/encoder-v0.7.0
[0.6.0]: https://github.com/zaproxy/zap-extensions/releases/encoder-v0.6.0
[0.5.0]: https://github.com/zaproxy/zap-extensions/releases/encoder-v0.5.0
[0.4.0]: https://github.com/zaproxy/zap-extensions/releases/encoder-v0.4.0
[0.3.0]: https://github.com/zaproxy/zap-extensions/releases/encoder-v0.3.0
[0.2.0]: https://github.com/zaproxy/zap-extensions/releases/encoder-v0.2.0
[0.1.0]: https://github.com/zaproxy/zap-extensions/releases/encoder-v0.1.0
