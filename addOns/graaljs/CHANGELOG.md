# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased
### Changed
- Maintenance changes.

## [0.5.0] - 2023-10-12
### Changed
- Update minimum ZAP version to 2.14.0.
- Update Graal JavaScript engine.

## [0.4.0] - 2023-07-11
### Added
- Add info URL.

### Changed
- Update minimum ZAP version to 2.13.0.
- Replace usage of singletons with injected variables (e.g. `model`, `control`) in scripts.

### Fixed
- Updated encode-decode script templates to conform to the latest method signatures.
- Update the content-length header field after setting the request body in the authentication templates.

## [0.3.0] - 2022-10-27
### Changed
- Update minimum ZAP version to 2.12.0.

### Fixed
- Declare the engine is single threaded (Issue 6992).

## [0.2.0] - 2021-10-06
### Added
- encode-decode Default and rot13 templates.

### Changed
- Update minimum ZAP version to 2.11.0.
- Update links to zaproxy repo.

## [0.1.0] - 2020-11-17

First version.

[0.5.0]: https://github.com/zaproxy/zap-extensions/releases/graaljs-v0.5.0
[0.4.0]: https://github.com/zaproxy/zap-extensions/releases/graaljs-v0.4.0
[0.3.0]: https://github.com/zaproxy/zap-extensions/releases/graaljs-v0.3.0
[0.2.0]: https://github.com/zaproxy/zap-extensions/releases/graaljs-v0.2.0
[0.1.0]: https://github.com/zaproxy/zap-extensions/releases/graaljs-v0.1.0
