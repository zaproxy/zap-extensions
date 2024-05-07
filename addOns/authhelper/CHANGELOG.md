# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased


## [0.13.0] - 2024-05-07
### Changed
- Update minimum ZAP version to 2.15.0.
- Maintenance changes.

## [0.12.0] - 2024-02-06

### Changed
- Handle traditional apps better in authentication detection dialog.
- Make cookies set in auth request available to header based session management.

### Fixed
- Correct HTTP field names shown in diagnostic data.

## [0.11.0] - 2024-01-10
### Changed
- Maintenance changes.
- Dropped "to Clipboard" from ZAP copy menu items or buttons (Issue 8179).
- Update cookies in header based session management, to cope with apps that set them via JavaScript.

### Fixed
- Read the user details from the session rather than the individual messages, which could cause an NPE.

## [0.10.0] - 2023-10-12
### Changed
- Update minimum ZAP version to 2.14.0.
- Maintenance changes.

## [0.9.0] - 2023-07-11
### Added
- Direct support for handling browser based authentication in the AJAX spider.
- Support for cookie based session management.

### Changed
- Update minimum ZAP version to 2.13.0.

## [0.8.0] - 2023-06-06
### Changed
- Prefer username fields with known id/name strings.

### Fixed
- Correct example alert of Session Management Response Identified scan rule.

## [0.7.0] - 2023-05-23
### Added
- Authentication tester dialog.

### Changed
- Promoted to Beta

## [0.6.0] - 2023-05-09
### Added
- Support for login pages where the username has to be submitted before the password field is accessible.

## [0.5.0] - 2023-05-04
### Added
- Support for verification type of "autodetect" (post 2.12).

### Fixed
- Ensure verification processor shut down on exit, otherwise the AF hangs.

## [0.4.0] - 2023-04-28
### Added
- Support for session management identification.
- Support for auto-detect authentication.
- Support for auto-detect session management.
- Support for auto-detect verification.

### Fixed
- Clear launched browser authentication when disabled, otherwise it would prevent enabling it again.

## [0.3.0] - 2023-03-13
### Added
- Support for browser based authentication.

## [0.2.0] - 2023-02-08
### Added
- Support for header based session management.

### Fixed
- Code link in help.


## [0.1.0] - 2023-01-17

### Added
- Support of authentication request identification and configuration.

[0.13.0]: https://github.com/zaproxy/zap-extensions/releases/authhelper-v0.13.0
[0.12.0]: https://github.com/zaproxy/zap-extensions/releases/authhelper-v0.12.0
[0.11.0]: https://github.com/zaproxy/zap-extensions/releases/authhelper-v0.11.0
[0.10.0]: https://github.com/zaproxy/zap-extensions/releases/authhelper-v0.10.0
[0.9.0]: https://github.com/zaproxy/zap-extensions/releases/authhelper-v0.9.0
[0.8.0]: https://github.com/zaproxy/zap-extensions/releases/authhelper-v0.8.0
[0.7.0]: https://github.com/zaproxy/zap-extensions/releases/authhelper-v0.7.0
[0.6.0]: https://github.com/zaproxy/zap-extensions/releases/authhelper-v0.6.0
[0.5.0]: https://github.com/zaproxy/zap-extensions/releases/authhelper-v0.5.0
[0.4.0]: https://github.com/zaproxy/zap-extensions/releases/authhelper-v0.4.0
[0.3.0]: https://github.com/zaproxy/zap-extensions/releases/authhelper-v0.3.0
[0.2.0]: https://github.com/zaproxy/zap-extensions/releases/authhelper-v0.2.0
[0.1.0]: https://github.com/zaproxy/zap-extensions/releases/authhelper-v0.1.0
