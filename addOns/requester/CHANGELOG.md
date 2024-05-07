# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased


## [7.6.0] - 2024-05-07
### Changed
- Update minimum ZAP version to 2.15.0.

## [7.5.0] - 2024-03-25
### Added 
- Button to lowercase request header names (Issue 8176).
- Support for menu weights (Issue 8369)

### Changed
- Manual request dialog to be opened with selected message on CTRL-M (Issue 8365)
- Manual request dialog to be used instead of a separate Resend dialog.

## [7.4.0] - 2023-10-12
### Added
- Option to manipulate Host header.

### Changed
- Update minimum ZAP version to 2.14.0.
- Maintenance changes.

## [7.3.0] - 2023-07-11
### Changed
- Update minimum ZAP version to 2.13.0.

## [7.2.0] - 2023-03-23
### Changed
- Maintenance changes.

### Fixed
- Allow to read HTTP/2 trailing headers.

## [7.1.0] - 2022-12-19
### Added
- Find control in footer

## [7.0.0] - 2022-10-27
### Added
- Add Send button to Response tab.
- Add shortcut to Send buttons (Issue 6448).
- Add button to allow to regenerate Anti-CSRF tokens (Issue 111).
- Provide the necessary infrastructure for other add-ons (e.g. WebSocket) to send messages.
- Manage the send/resend Manual Request Editor dialogues.
- Add a Tools menu item to open the send Manual Request Editor.
- Add a context menu item to open the resend Manual Request Editor.
- Allow to establish WebSocket connections with the send/resend Manual Request Editor dialogues.

### Changed
- Update minimum ZAP version to 2.12.0.
- Improve reporting of TLS errors (Issue 2699).
- Maintenance changes.
- Promoted to Beta.
- Now following Semantic Versioning.

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



[7.6.0]: https://github.com/zaproxy/zap-extensions/releases/requester-v7.6.0
[7.5.0]: https://github.com/zaproxy/zap-extensions/releases/requester-v7.5.0
[7.4.0]: https://github.com/zaproxy/zap-extensions/releases/requester-v7.4.0
[7.3.0]: https://github.com/zaproxy/zap-extensions/releases/requester-v7.3.0
[7.2.0]: https://github.com/zaproxy/zap-extensions/releases/requester-v7.2.0
[7.1.0]: https://github.com/zaproxy/zap-extensions/releases/requester-v7.1.0
[7.0.0]: https://github.com/zaproxy/zap-extensions/releases/requester-v7.0.0
[6]: https://github.com/zaproxy/zap-extensions/releases/requester-v6
[5]: https://github.com/zaproxy/zap-extensions/releases/requester-v5
[4]: https://github.com/zaproxy/zap-extensions/releases/requester-v4
