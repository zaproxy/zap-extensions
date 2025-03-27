# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased


## [0.25.0] - 2025-03-25
### Changed
- Use TOTP data defined under user credentials for Client Script and Browser Based Authentication, when available.
- Maintenance changes.
- Depend on newer version of Common Library add-on.

### Added
- The Authentication Report now includes information around authentication failures (if applicable).

## [0.24.0] - 2025-03-21
### Added
- Document custom steps for Browser Based Authentication.
- Document Authentication Report diagnostics data.
- Sanitized post data to auth diagnostics.
- Help content for configuration and use of Header Based Session Management via ZAP API (these additions will only work properly when used with ZAP 2.16.1 or later).

### Changed
- Add any session related cookies which are not being tracked.
- Ignore non proxied requests in auth tester diagnostics.
- Replace credentials with special tokens.
- Rewrite of the auth request detection code to handle more cases.
- Add domain to context if creds posted to it and using using auto-detect for session management.
- Skip disabled authentication steps when creating the context from the Authentication Tester dialog.

### Fixed
- Allow the Client Script Authentication, and Browser Based Authentication method types as well as Header Based Session Management to be configured via the API (these fixes will only work properly when used with ZAP 2.16.1 or later).
- Bug where some of the data structures were not being reset when the session changed.
- Address concurrent modification exceptions.

## [0.23.0] - 2025-03-04
### Added
- If authentication fails then try to find a likely looking login link.
- Persist diagnostics to the session and include it in the Authentication Report (JSON) for Client Script and Browser Based Authentication methods.
- A reset button.
- Checks to try to find a verification URL with a login link, if nothing better has been found.

### Changed
- Prefer form related fields in Browser Based Authentication for the selection of username field.
- Tweaked the auth report summary keys.
- Only check URLs and methods once for being good verification requests.
- Added API support to the browser based auth method proxy.

### Fixed
- Correctly read the API parameters when setting up Browser Based Authentication.
- Tweaked auth report output to ensure that values are properly escaped.
- Report to use better stats with browser based auth.
- Session handling to cope with X-CSRF-Token headers.

## [0.22.0] - 2025-02-12
### Added
- Initial authentication report (JSON).

## [0.21.0] - 2025-02-10
### Fixed
- Delays identifying verification due to tests being performed on too many unlikely URLs (such as images).

## [0.20.0] - 2025-02-07
### Changed
- Reduce add-on size.
- Improved session management detection.

### Fixed
- Maintain the correct cookie state when using client script authentication.
- Do not close windows when running client auth in the spiders.
- Always close all of the windows when running client auth not in the spiders.

## [0.19.0] - 2025-02-04
### Added
- Added support for Client Script Authentication when used in conjunction with the Ajax Spider add-on or the Client Spider via the Client Side Integration add-on.
- Add support for custom authentication steps in Browser Based Authentication.

### Fixed
- Reset always the state of the demo mode in the Authentication Tester dialogue.

## [0.18.0] - 2025-01-27
### Changed
- Ignore non-displayed fields when selecting the user name and password.
- Use single displayed field for user name, e.g. multi step login.

### Fixed
- Input fields that do not explicitly declare their type were no longer being chosen by the Browser Based Authentication.

## [0.17.0] - 2025-01-09
### Changed
- Update minimum ZAP version to 2.16.0.
- Depend on Passive Scanner add-on (Issue 7959).
- Address deprecation warnings with newer Selenium version (4.27).
- Optionally depend on the Client Integration add-on to provide Browser Based Authentication to the Client Spider.

## [0.16.0] - 2024-11-06
### Fixed
- Address concurrency issue while passive scanning with the Session Management Response Identified scan rule (Issue 8187).

## [0.15.1] - 2024-09-02
### Changed
- Restored stats removed in previous release as these could be used in AF tests.

## [0.15.0] - 2024-08-28
### Changed
- Maintenance changes.
### Fixed
- Bug in session detection scan rule which impacted performance.

## [0.14.0] - 2024-07-31
### Fixed
- Potential timing issue trying to use browser based auth to authenticate before the session management method has been identified.
- Timing issue with session management detection.

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

[0.25.0]: https://github.com/zaproxy/zap-extensions/releases/authhelper-v0.25.0
[0.24.0]: https://github.com/zaproxy/zap-extensions/releases/authhelper-v0.24.0
[0.23.0]: https://github.com/zaproxy/zap-extensions/releases/authhelper-v0.23.0
[0.22.0]: https://github.com/zaproxy/zap-extensions/releases/authhelper-v0.22.0
[0.21.0]: https://github.com/zaproxy/zap-extensions/releases/authhelper-v0.21.0
[0.20.0]: https://github.com/zaproxy/zap-extensions/releases/authhelper-v0.20.0
[0.19.0]: https://github.com/zaproxy/zap-extensions/releases/authhelper-v0.19.0
[0.18.0]: https://github.com/zaproxy/zap-extensions/releases/authhelper-v0.18.0
[0.17.0]: https://github.com/zaproxy/zap-extensions/releases/authhelper-v0.17.0
[0.16.0]: https://github.com/zaproxy/zap-extensions/releases/authhelper-v0.16.0
[0.15.1]: https://github.com/zaproxy/zap-extensions/releases/authhelper-v0.15.1
[0.15.0]: https://github.com/zaproxy/zap-extensions/releases/authhelper-v0.15.0
[0.14.0]: https://github.com/zaproxy/zap-extensions/releases/authhelper-v0.14.0
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
