# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased


## [0.2.1] - 2025-03-25
### Fixed
- Allow add-ons to obtain (empty) tags before the extension is fully initialised to prevent exceptions.

### Changed
- Automation Framework progress and log messages with regard to setting scan rule threshold no longer include commas in scan rule ID numbers.

## [0.2.0] - 2025-02-12
### Added
- Allow add-ons to obtain the auto tagging tags.

### Changed
- Correct help configuration to work with any language.
- Maintenance changes.
- Clarified passiveScan-wait > maxDuration documentation.

### Fixed
- Fix broken link the help page.

## [0.1.0] - 2025-01-10
### Added
- Manage the passive scan related options and the scan rules (Issue 7959).
- Add passive scanner (Issue 7959).

### Changed
- Update minimum ZAP version to 2.16.0.
- Fields with default or missing values are omitted for the following automation jobs in saved Automation Framework plans:
    - `passiveScan-config`
    - `passiveScan-wait`

### Fixed
- Fixed `passiveScan-wait` alert tests.

## [0.0.1] - 2024-09-02
### Added
- Provide the Passive Rules script type (Issue 7959).
- Provide the Stats Passive Scan Rule (Issue 7959).
- Provide the scan status label (Issue 7959).
- Provide the `pscan` API on newer ZAP versions (Issue 7959).
- Provide the Automation Framework passive scan jobs:
  - `passiveScan-config`
  - `passiveScan-wait`
- Dynamically un/load add-on passive scan rules (Issue 7959).

[0.2.1]: https://github.com/zaproxy/zap-extensions/releases/pscan-v0.2.1
[0.2.0]: https://github.com/zaproxy/zap-extensions/releases/pscan-v0.2.0
[0.1.0]: https://github.com/zaproxy/zap-extensions/releases/pscan-v0.1.0
[0.0.1]: https://github.com/zaproxy/zap-extensions/releases/pscan-v0.0.1
