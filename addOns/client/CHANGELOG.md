# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased
### Added
- Support for other add-ons to piggyback the secure connection established with the ZAP browser extension.
### Changed
- Set the extension order so that it will always be available to unordered extensions.

## [0.20.0] - 2025-12-15
### Changed
- Update the automation framework template to include missing field (`scopeCheck`).
- Update minimum ZAP version to 2.17.0.
- Updated Chrome and Firefox extensions to v0.1.8.

## [0.19.0] - 2025-12-03
### Changed
- Updated Chrome and Firefox extensions to v0.1.7.
- Bundle Chrome extension unpacked due changes in Chrome.

## [0.18.0] - 2025-11-04
### Added
- Add optional parameters for the Client Spider API action `scan`:
  - `numberOfBrowsers` - control concurrency (number of browser windows).
  - `scopeCheck` - select Scope Check (Flexible or Strict).
- Spider stats.

## [0.17.0] - 2025-09-02
### Added
- Edge recorder link to help.
- Support for stopping the spiderCient automation job.
- Support for configuring the client passive scan rules via the passiveScan-config Automation Framework job. This add-on now depends on the pscan add-on.

### Changed
- Updated Chrome and Firefox extensions to v0.1.6.
- Reduce warnings when passive scanning.

### Fixed
- Error logs to always include stack trace.
- Log Firefox missing at debug instead of error.

## [0.16.0] - 2025-06-20
### Added
- Client Spider scope check.
- Added optional parameters for Page Load Time and Max Crawl Depth to the Client Spider API.
- Recording advice and guidance.

### Changed
- Updated Chrome and Firefox extensions to v0.1.3.

### Fixed
- Client Spider to allow all requests while authenticating.
- Ensure that the `clientSpider` API endpoint `status` returns 100(%) only when finished.

## [0.15.0] - 2025-03-25
### Added
- Add API endpoints for the Client Spider.

## [0.14.0] - 2025-03-04
### Added
- Added an API action to export the Client Map.

### Fixed
- Correct Client Passive Scan Queue counter, which could be showing one when none left.
- Correctly fill input elements when spidering (Issue 8851).

## [0.13.0] - 2025-02-04
### Added
- Added support for Client Script Authentication when installed in conjunction with the Authentication Helper add-on.

## [0.12.0] - 2025-01-24
### Fixed
- Extension not enabled when launched from ZAP.
- Browser recording not enabled when launched from ZAP recorder.

## [0.11.0] - 2025-01-17
### Fixed
- Fix concurrency issue with page components which could lead to exceptions in the GUI.

### Changed
- Updated Chrome and Firefox extensions to v0.0.11.

### Added
- A context menu allowing users to Export Client Map.

## [0.10.0] - 2025-01-10
### Changed
- Update minimum ZAP version to 2.16.0.
- Maintenance changes.
- The current passive scan rules now uses a more specific CWE (Issue 8712).
- Updated Chrome and Firefox extensions to v0.0.10.

### Added
- Added support for Browser Based Authentication when installed in conjunction with the Auth Helper add-on.
- Client spider, along with Automation Framework support.

## [0.9.0] - 2024-11-29
### Changed
- Update minimum ZAP version to 2.15.0.
- Updated Chrome and Firefox extensions to v0.0.9.

### Added
- Support for menu weights (Issue 8369).

### Fixed
- Address exception with deleted messages while handling client event.

## [0.8.0] - 2024-01-16
### Changed
- Updated the Chrome extension to v0.0.8.

## [0.7.0] - 2023-12-01
### Added
- Support for base64 decoding in existing scan rules.
- Passive scan rule: JWT in Browser Storage.
- Additional input field data returned from the extension.

### Changed
- Updated the Firefox extension to v0.0.8.

## [0.6.0] - 2023-11-23
### Added
- Support for passive scanning.
- Passive scan rules:
  - Information Disclosure - Information in Browser Storage.
  - Information Disclosure - Sensitive Information in Browser Storage.

### Changed
- Dropped "to Clipboard" from ZAP copy menu items (Issue 8179).
- Changed to add back '#' nodes.

## [0.5.0] - 2023-11-07
### Added
- Client History and Details context menu items.

### Changed
- Maintenance changes.

### Fixed
- Do not use white background in Client Details and show Client Map icons properly when using Mac OS X look and feel (Issue 8175).

## [0.4.0] - 2023-10-31
### Added
- Note about custom containers in the help.
- Client Map context menu items.

### Changed
- Updated the Chrome extension to v0.0.7.

### Fixed
- Cases where the Firefox profile was not added successfully via Selenium.
- Reworked the Client Map to correctly handle parameters and more edge cases.

## [0.3.0] - 2023-10-23
### Changed
- Update minimum ZAP version to 2.14.0.
- Updated the Firefox extension to v0.0.7.

### Added
- AJAX spider enhancement.
- More help pages.

### Fixed
- Do not show ZAP API calls.
- Missing 'Cookies' translation.

## [0.2.0] - 2023-09-26

### Changed
- Updated the Chrome extension to v0.0.6.
- Disable client events automatically only for Zest recording.
- Create Firefox profile to enable the ZAP extension for all sites.

## [0.1.0] - 2023-09-19

### Changed
- Updated the Firefox extension to v0.0.6.
- Updated the Chrome extension to v0.0.5.

## [0.0.1] - 2023-09-11

- First version.

[0.20.0]: https://github.com/zaproxy/zap-extensions/releases/client-v0.20.0
[0.19.0]: https://github.com/zaproxy/zap-extensions/releases/client-v0.19.0
[0.18.0]: https://github.com/zaproxy/zap-extensions/releases/client-v0.18.0
[0.17.0]: https://github.com/zaproxy/zap-extensions/releases/client-v0.17.0
[0.16.0]: https://github.com/zaproxy/zap-extensions/releases/client-v0.16.0
[0.15.0]: https://github.com/zaproxy/zap-extensions/releases/client-v0.15.0
[0.14.0]: https://github.com/zaproxy/zap-extensions/releases/client-v0.14.0
[0.13.0]: https://github.com/zaproxy/zap-extensions/releases/client-v0.13.0
[0.12.0]: https://github.com/zaproxy/zap-extensions/releases/client-v0.12.0
[0.11.0]: https://github.com/zaproxy/zap-extensions/releases/client-v0.11.0
[0.10.0]: https://github.com/zaproxy/zap-extensions/releases/client-v0.10.0
[0.9.0]: https://github.com/zaproxy/zap-extensions/releases/client-v0.9.0
[0.8.0]: https://github.com/zaproxy/zap-extensions/releases/client-v0.8.0
[0.7.0]: https://github.com/zaproxy/zap-extensions/releases/client-v0.7.0
[0.6.0]: https://github.com/zaproxy/zap-extensions/releases/client-v0.6.0
[0.5.0]: https://github.com/zaproxy/zap-extensions/releases/client-v0.5.0
[0.4.0]: https://github.com/zaproxy/zap-extensions/releases/client-v0.4.0
[0.3.0]: https://github.com/zaproxy/zap-extensions/releases/client-v0.3.0
[0.2.0]: https://github.com/zaproxy/zap-extensions/releases/client-v0.2.0
[0.1.0]: https://github.com/zaproxy/zap-extensions/releases/client-v0.1.0
[0.0.1]: https://github.com/zaproxy/zap-extensions/releases/client-v0.0.1
