# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased
### Changed
- Update minimum ZAP version to 2.17.0.

## [0.15.0] - 2025-09-02
### Added
- Added support for adding payloads which are disabled by default.

## [0.14.0] - 2025-01-15
### Changed
- Promoted to Release status.
- Update minimum ZAP version to 2.16.0.
- Maintenance changes.
- The superfluous/unused ID element of the custom payloads has been removed from the GUI and config.
- Now depends on the Common Library add-on.

### Added
- Add help button to Options panel and add further detailed Help content.

### Fixed
- The add-on will no longer attempt to save or load Payloads for which there is no Category.
- Ensure file is selected, exists, and is readable when attempting to import multiple payloads.

## [0.13.0] - 2023-11-10
### Changed
- Update minimum ZAP version to 2.14.0.
- Maintenance changes.
- Promoted to Beta.

### Added
- Initial API support:
    - Actions
        - Enable payloads.
        - Disable payloads.
        - Enable payload.
        - Disable payload.
        - Add payload.
        - Remove payload.
    - Views:
        - Payload categories.
        - Payloads (optionally filtered by category).

## [0.12.0] - 2022-09-23
### Changed
- Maintenance changes.
- Update minimum ZAP version to 2.11.1.
- Add help content linking to the Scan Rules which support Custom Payloads.

## [0.11.0] - 2021-10-07
### Changed
- Update minimum ZAP version to 2.11.0.

## [0.10.0] - 2021-06-17
### Added
- Add info and repo URLs.
- Add functionality to add multiple payloads from a file.

### Changed
- Update minimum ZAP version to 2.10.0.
- Maintenance changes.

## [0.9.0] - 2019-10-31

- First version.

[0.15.0]: https://github.com/zaproxy/zap-extensions/releases/custompayloads-v0.15.0
[0.14.0]: https://github.com/zaproxy/zap-extensions/releases/custompayloads-v0.14.0
[0.13.0]: https://github.com/zaproxy/zap-extensions/releases/custompayloads-v0.13.0
[0.12.0]: https://github.com/zaproxy/zap-extensions/releases/custompayloads-v0.12.0
[0.11.0]: https://github.com/zaproxy/zap-extensions/releases/custompayloads-v0.11.0
[0.10.0]: https://github.com/zaproxy/zap-extensions/releases/custompayloads-v0.10.0
[0.9.0]: https://github.com/zaproxy/zap-extensions/releases/custompayloads-v0.9.0
