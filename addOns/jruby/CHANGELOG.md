# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased
### Changed
- Update minimum ZAP version to 2.15.0.
- Maintenance changes.
- This add-on now depends on the Scripts add-on for providing scanning related functionality.
- The active and passive scan rule templates were updated to import classes from the scripts add-on.

### Fixed
- Update the content-length header field after setting the request body in the authentication template.

## [8] - 2021-10-07
### Changed
- Update links to zaproxy repo.
- Rename reliability to confidence in active/passive templates.
- Maintenance changes.
- Update minimum ZAP version to 2.11.0.

## [7] - 2020-12-15
### Added
- Add info and repo URLs.

### Changed
- Update the help to mention the bundled JRuby version.
- Update minimum ZAP version to 2.10.0.

### Fixed
- Fix link in a script template.
- Fix exception while uninstalling the add-on with newer Java versions.
- Fix passive template.

## 6 - 2017-11-27

- Updated for 2.7.0.

## 5 - 2017-09-28

- Add template for HTTP Sender script.
- Dynamically unload the add-on.

## 4 - 2015-04-13

- Updated for ZAP 2.4

## 3 - 2014-04-10

- Moved to beta
- Changed help file structure to support internationalisation (Issue 981).
- Added content-type to help pages (Issue 1080).
- Updated add-on dir structure (Issue 1113).

## 2 - 2013-10-10

- Fixed bug where non ruby scripts were treated as ruby scripts (issue 810)

## 1 - 2013-10-02

- First version

[8]: https://github.com/zaproxy/zap-extensions/releases/jruby-v8
[7]: https://github.com/zaproxy/zap-extensions/releases/jruby-v7
