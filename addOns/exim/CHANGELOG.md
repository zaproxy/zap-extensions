# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased


## [0.9.0] - 2024-05-07
### Added
- Initial PCAP import support (Issue 4812).
- Support for menu weights (Issue 8369)

### Changed
- Update minimum ZAP version to 2.15.0.
- Maintenance changes.

## [0.8.0] - 2023-11-10
### Changed
- Keep the Export menu items sorted alphabetically.
- Dropped "to Clipboard" from ZAP copy menu items (Issue 8179).

## [0.7.0] - 2023-10-12
### Changed
- Update minimum ZAP version to 2.14.0.
- Depend on newer versions of Automation Framework and Common Library add-ons (Related to Issue 7961).

## [0.6.0] - 2023-07-11
### Changed
- Update minimum ZAP version to 2.13.0.

## [0.5.0] - 2023-04-04
### Changed
- Log cause of error when failed to import the HAR file.

### Fixed
- Ensure the 'ZAP messages' Export delimiters are consistent with the Import expectation.

## [0.4.0] - 2023-02-09
### Added
- Support for relative file paths and ones including vars in the Automation Framework job.

### Changed
- Maintenance changes.

### Fixed
- Show missing API endpoints' descriptions.

## [0.3.0] - 2022-10-27
### Changed
- Update minimum ZAP version to 2.12.0.
- Maintenance changes.
- When importing a file of URLs the output tab and log will now be more informative about failures.

### Added
- HAR related API endpoints being migrated from core (Issue 6579).

## [0.2.0] - 2022-07-20
### Fixed
- Tweaked import functionality to mark import progress components completed when an exception occurs during import (thus allowing them to be cleared properly).
- HAR imports will now use an indeterminate progress bar if the count of entries cannot be determined.
- Correct import of HAR responses to allow them to be passively scanned.

### Added
- Copy URLs, Export Context URLs, Export Selected URLs, Export Messages, and Export Responses functionality similar to what was previously offered via core functionality.
- Stats for migrated core components.

### Changed
- Save RAW functionality now includes an All option which saves the entire HTTP message.

## [0.1.0] - 2022-03-07
### Changed
- Reduce logging and display a warning dialog when unable to read files being imported (Issue 7081).
- Promoted to Beta.

### Added
- Importing a file of URLs or HAR is now displayed in the progress panel provided via commonlib.
- Automation Framework (Issue 7078).

## [0.0.1] - 2021-12-22

- First release.

[0.9.0]: https://github.com/zaproxy/zap-extensions/releases/exim-v0.9.0
[0.8.0]: https://github.com/zaproxy/zap-extensions/releases/exim-v0.8.0
[0.7.0]: https://github.com/zaproxy/zap-extensions/releases/exim-v0.7.0
[0.6.0]: https://github.com/zaproxy/zap-extensions/releases/exim-v0.6.0
[0.5.0]: https://github.com/zaproxy/zap-extensions/releases/exim-v0.5.0
[0.4.0]: https://github.com/zaproxy/zap-extensions/releases/exim-v0.4.0
[0.3.0]: https://github.com/zaproxy/zap-extensions/releases/exim-v0.3.0
[0.2.0]: https://github.com/zaproxy/zap-extensions/releases/exim-v0.2.0
[0.1.0]: https://github.com/zaproxy/zap-extensions/releases/exim-v0.1.0
[0.0.1]: https://github.com/zaproxy/zap-extensions/releases/exim-v0.0.1
