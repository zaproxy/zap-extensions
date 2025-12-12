# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
### Changed
- Migrate handling of Alerts raised statistics from the core.
- Update minimum ZAP version to 2.17.0.

### Removed
- Dropped help references to ZAP in Ten videos which are no longer available.

## [0.5.0] - 2025-09-10

### Changed
- Updated Automation Framework template plans and help content for passiveScan-* jobs to be more consistent.

## [0.4.0] - 2025-09-02
### Added
- Allow to configure the option max body size through the API (Issue 8974).
- Support for stopping the passiveScan-wait automation job.

### Changed
- To only record `stats.pscan.<rule-name>` statistics for scanners that have no IDs.
- To support other add-ons which manage passive scan rules. These rules will not currently be fully supported in the UI.

## [0.3.0] - 2025-06-20
### Changed
- Adjusted further dialog, progress, and log messages with regard to preventing inclusion of commas in scan rule ID numbers. As well as ensuring consistency in use of ID (full caps) for table column headings.
- Depend on the Common Library add-on.
- Log all errors that might happen during the passive scan.

### Added
- The Stats Passive Scan Rule been tagged of interest to Penetration Testers, as well as adding tags associated with DEV or QA applicability.

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

[0.5.0]: https://github.com/zaproxy/zap-extensions/releases/pscan-v0.5.0
[0.4.0]: https://github.com/zaproxy/zap-extensions/releases/pscan-v0.4.0
[0.3.0]: https://github.com/zaproxy/zap-extensions/releases/pscan-v0.3.0
[0.2.1]: https://github.com/zaproxy/zap-extensions/releases/pscan-v0.2.1
[0.2.0]: https://github.com/zaproxy/zap-extensions/releases/pscan-v0.2.0
[0.1.0]: https://github.com/zaproxy/zap-extensions/releases/pscan-v0.1.0
[0.0.1]: https://github.com/zaproxy/zap-extensions/releases/pscan-v0.0.1
