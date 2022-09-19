# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased
### Added
- Add Send button to Response tab.
- Add shortcut to Send buttons (Issue 6448).
- Add a context menu to open the Manual Request Editor, on ZAP versions newer than 2.11.
- Add button to allow to regenerate Anti-CSRF tokens (Issue 111).

### Changed
- Improve reporting of TLS errors (Issue 2699).
- Maintenance changes.
- Promoted to Beta.

## [6] - 2022-05-10
### Added
- Support for renaming tabs.
- More help.

### Changed
- Update minimum ZAP version to 2.11.1.
- Maintenance changes.
- Moved Help button to the Response tab.

## [5] - 2021-10-07
### Changed
- Warn when unable to save (malformed) HTTP message (Issue 4235).
- Update minimum ZAP version to 2.11.0.
- Maintenance changes.
- Add button to automatically update content length (Issue 6254).

## [4] - 2020-07-15
### Added
- Add help.
- Add info and repo URLs.
- Allow to disable cookies (Issue 4934).

### Changed
- Update minimum ZAP version to 2.9.0.

### Fixed
- Add the requests to the Sites tree to be able to active scan them (Issue 5778).
- Enforce the mode when sending the request and following redirections.

## 3 - 2018-10-15

- Maintenance changes.
- Change default accelerator for Requester tab.
- Dynamically unload the add-on.
- Ensure use of title caps (Issue 2000).

## 2 - 2017-11-28

- Code changes for Java 9 (Issue 2602).

## 1 - 2016-05-13



[6]: https://github.com/zaproxy/zap-extensions/releases/requester-v6
[5]: https://github.com/zaproxy/zap-extensions/releases/requester-v5
[4]: https://github.com/zaproxy/zap-extensions/releases/requester-v4
