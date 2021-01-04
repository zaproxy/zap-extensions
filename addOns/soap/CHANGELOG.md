# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased


## [5] - 2021-01-04
### Changed
- Add support for ValueGenerator (Issue 3345).

## [4] - 2020-12-16
### Changed
- Internationalise file filter description.
- Dynamically unload the add-on.
- Change default accelerator for "Import a WSDL file from local file system".
- Update minimum ZAP version to 2.10.0.
- Add import menus to (new) top level Import menu instead of Tools menu.
- Add support for SOAP version 1.2 to the Action Spoofing Scan Rule.
- Distinguish alerts by adding the SOAP version to the "Other Info" section.
- Maintenance changes.

### Fixed
- Various fixes (related to Issue 4832 and other testing).
- Fix exception with Java 9+ (Issue 4037).
- SOAP operations are no longer overwritten in sites tree (Issue 1867).
- Persist the add-on configuration required by the scan rules in the ZAP database (Issue 4866).

## 3 - 2017-03-31

- Added API, help and other minor code changes.

## 2 - 2015-09-07

- Fixes a problem where operations under the same location were overwritten. Other minor fixes.

## 1 - 2015-04-13

- First version

[5]: https://github.com/zaproxy/zap-extensions/releases/soap-v5
[4]: https://github.com/zaproxy/zap-extensions/releases/soap-v4
