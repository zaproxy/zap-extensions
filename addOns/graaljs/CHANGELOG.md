# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased
### Changed
- Update dependencies.

### Fixed
- Close script engine when no longer in use (Issue 9230).

## [0.12.0] - 2025-12-15
### Changed
- Update minimum ZAP version to 2.17.0.

## [0.11.0] - 2025-11-04
### Changed
- Update dependencies.
- Update the Active script template to contain a `scanHost` function that is called once per host being scanned.
- Update minimum scripts add-on version to 45.15.0.

## [0.10.0] - 2025-10-07
### Changed
- Update Graal JavaScript engine to version 25 (Issues 8477 and 9010).
- Use example links in Active/Passive Rule templates' references.
- Update scan rule templates to use alertRefOverrides.

## [0.9.0] - 2025-01-09
### Changed
- Update minimum ZAP version to 2.16.0.

## [0.8.0] - 2024-09-24
### Added
- Document the engine name in the help page.

### Changed
- Maintenance changes.
- Update script templates:
  - authentication/Authentication default template GraalJS.js - remove outdated example code.
  - httpsender/AddZapHeader GraalJS.js - fix runtime error (Issue 8611) and update documentation.
  - httpsender/HttpSender default template GraalJS.js - update documentation.

## [0.7.0] - 2024-05-07
### Changed
- Update minimum ZAP version to 2.15.0.
- Disable warns about the engine being executed in interpreter mode, that's the expected mode of execution.

## [0.6.0] - 2024-04-11
### Changed
- Update Active and Passive Script Templates to include a `getMetadata` function. This will allow them to be used as regular scan rules.
- Depend on the `commonlib` and `scripts` add-ons for scan rule scripts.
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

[0.12.0]: https://github.com/zaproxy/zap-extensions/releases/graaljs-v0.12.0
[0.11.0]: https://github.com/zaproxy/zap-extensions/releases/graaljs-v0.11.0
[0.10.0]: https://github.com/zaproxy/zap-extensions/releases/graaljs-v0.10.0
[0.9.0]: https://github.com/zaproxy/zap-extensions/releases/graaljs-v0.9.0
[0.8.0]: https://github.com/zaproxy/zap-extensions/releases/graaljs-v0.8.0
[0.7.0]: https://github.com/zaproxy/zap-extensions/releases/graaljs-v0.7.0
[0.6.0]: https://github.com/zaproxy/zap-extensions/releases/graaljs-v0.6.0
[0.5.0]: https://github.com/zaproxy/zap-extensions/releases/graaljs-v0.5.0
[0.4.0]: https://github.com/zaproxy/zap-extensions/releases/graaljs-v0.4.0
[0.3.0]: https://github.com/zaproxy/zap-extensions/releases/graaljs-v0.3.0
[0.2.0]: https://github.com/zaproxy/zap-extensions/releases/graaljs-v0.2.0
[0.1.0]: https://github.com/zaproxy/zap-extensions/releases/graaljs-v0.1.0
