# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased
### Added
- Support for menu weights (Issue 8369)

### Changed
- Update minimum ZAP version to 2.15.0.
- Maintenance changes.
- Default number of threads to 2 * processor count.

### Fixed
- Help content typos.

## [10] - 2022-10-27
### Changed
- Use the Network add-on to obtain the outgoing proxy.
- Maintenance changes.
- Update minimum ZAP version to 2.12.0.

## [9] - 2021-10-07
### Added
- Add info and repo URLs.

### Changed
- Update minimum ZAP version to 2.11.0.
- Update default values in the options to match the ones in the default configuration file.
- Maintenance changes.

## 8 - 2017-11-24

- Code changes for Java 9 (Issue 2602).
- Issue 3513: Options panel UI fixes.

## 7 - 2015-12-04

- Minor code changes.
- Do not access view components when view is not initialised (Issue 1617).

## 6 - 2015-04-13

- Safe menu items will now be enabled in protected and safe modes (Issue 1278).
- Disable the attack menu item if a scan is already in progress (Issue 1290).
- Updated for ZAP 2.4

## 5 - 2014-04-10

- Changed to clear the results when the option "--Select Site--" is selected (Issue 606).
- Updated to use the latest core changes (Issue 609).
- Changed to display the port scan results in a table (Issue 503).
- Changed help file structure to support internationalisation (Issue 981).
- Added content-type to help pages (Issue 1080).
- Updated add-on dir structure (Issue 1113).

## 4 - 2013-09-11

- Updated for ZAP 2.2.0

## 3 - 2013-05-27

- Updated language files.

## 2 - 2013-05-13

- Updated for ZAP 2.1.0 and changed to unload all components when uninstalling.

## 1 - 2013-02-05

- First release as an add-on (previously bundled in ZAP).

[10]: https://github.com/zaproxy/zap-extensions/releases/portscan-v10
[9]: https://github.com/zaproxy/zap-extensions/releases/portscan-v9
