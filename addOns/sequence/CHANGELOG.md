# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased
### Changed
- Update minimum ZAP version to 2.17.0.
- Allow to override the default alert threshold of the bundled policy.
- Maintenance changes.

## [8] - 2025-01-10
### Added
- Add Automation Framework jobs:
  - `sequence-import` to import HARs as sequences.
  - `sequence-activeScan` to active scan sequences.
- Data for reporting.
- Stats for import automation and active scan.
- Sequence active scan policy which will be used if neither a policy nor policyDefinition are set.
- Add Import top level menu item to import HAR as sequence.
- Active Scan Sequence dialog.

### Changed
- Depend on Import/Export add-on to allow to import HARs as sequences.
- Update minimum ZAP version to 2.16.0.
- Maintenance changes.
- Sequence scan implementation.
- Promoted to beta.

### Removed
- Sequence panel from the Active Scan dialog.

## [7] - 2023-10-23
### Changed
- Maintenance changes.
- Update minimum ZAP version to 2.14.0.

### Fixed
- Prevent exception if no display (Issue 3978).

## [6] - 2021-10-07
### Added
- Add info and repo URLs.

### Changed
- Update minimum ZAP version to 2.11.0.
- Issue 2000 - Updated strings shown in active scan dialog with title caps.
- Enable help button in Sequence tab of Active Scan dialog.
- Maintenance changes.

## 5 - 2017-11-28

- Updated for 2.7.0.

## 4 - 2017-05-25

- Correct error message to include the script name.
- Add help content (Issue 2191).
- Depend on Zest extension, since it is currently the only script option for Sequence scripts.

## 3 - 2016-06-02

- Allow to dynamically unload the add-on.
- Other code changes.

## 2 - 2015-09-07

- Updated to latest core changes.

## 1 - 2015-04-13



[8]: https://github.com/zaproxy/zap-extensions/releases/sequence-v8
[7]: https://github.com/zaproxy/zap-extensions/releases/sequence-v7
[6]: https://github.com/zaproxy/zap-extensions/releases/sequence-v6
