# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased
### Fixed
- Tweaked import functionality to mark import progress components completed when an exception occurs during import (thus allowing them to be cleared properly).
- HAR imports will now use an indeterminate progress bar if the count of entries cannot be determined.

### Added
- Copy URLs, Export Context URLs, Export Selected URLs, Export Messages, and Export Responses functionality similar to what was previously offered via core functionality.

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

[0.1.0]: https://github.com/zaproxy/zap-extensions/releases/exim-v0.1.0
[0.0.1]: https://github.com/zaproxy/zap-extensions/releases/exim-v0.0.1
