# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased
### Added
- Handle cookie parameters (Issue 6045).
- Use default values in `x-www-form-urlencoded` and `json` bodies (Issue 6095).

### Changed
- Show import exceptions in the Output tab (Issue 6042).
- Maintenance changes.

### Fixed
- Add imported messages synchronously to the Sites tree (Issue 5936).
- Correct parent dialogue when choosing the file to import (Issue 6041).
- Properly handle no schema when generating the request body (Issue 6042).
- Return API error `illegal_parameter` (instead of `internal_error`) when unable to get the OpenAPI definition from the provided URL.

## [16] - 2020-06-09
### Added
- Map Structure support for OpenAPI v3.0 (Issue 5863).
- Using OpenAPI Example values for value generation in request bodies and urls (Issue 5168).

### Changed
- Improve content checks when spidering for specifications (Issue 5725).
- Update minimum ZAP version to 2.9.0.
- Maintenance changes.

### Fixed
- Notify all redirects followed for proper passive scanning.

## [15] - 2020-01-17
### Added
- Add info and repo URLs.

### Changed
- Promote addon to Beta.

## [14] - 2019-12-02
### Added
- Support OpenAPI v3.0 (Issue 4549).
- Allow to specify the target URL (scheme, authority, and path) when importing through the command line.

### Changed
- Do not consume spider resource if not parsed as OpenAPI definition.
- Allow to specify the target URL when importing from file through the API and GUI.
- Allow to override also the scheme and path when importing from URL through the API.

## [13] - 2019-07-18

- Added Accept header for importing an OpenAPI definition from an URL, in the proper format.
- Correct import of v1.2 definitions (Issue 5262).
- Fix exception when reporting errors.
- Update minimum ZAP version to 2.8.0.
- Add import menu to (new) top level Import menu instead of Tools menu.
- Add support for primitive values (standalone and within arrays) in a request body (Issue 5250).

## 12 - 2018-05-18

- Ignore BOM when parsing and don't rely on default character encoding (Issue 4676).

## 11 - 2018-05-15

- Include exception message in warning dialog when a parse error occurs (Issue 4667).
- Open previously chosen directory when importing local file.

## 10 - 2018-01-17

- Fallback to host of request URI (Issue 4271).

## 9 - 2017-12-13

- Update Swagger/OpenAPI parser (Issue 3479).
- Fix exception with ref parameters.

## 8 - 2017-11-24

- Fix NPE in BodyGenerator.
- Fix NPEs when a parameter is null.

## 7 - 2017-09-28

- Correct validations when importing a file through the API.

## 6 - 2017-06-02

- Support optional host override.
- Detect and warn on potential loops.
- Allow add-on to be unloaded dynamically.
- Support user specified values when importing (Issue 3344).
- Support older swagger formats (Issue 3598).

## 5 - 2017-05-05

- Run synchronously and return any warnings when importing via API or cmdline.

## 4 - 2017-04-21

- Fallback to scheme of request URI (Issue 3433).

## 3 - 2017-04-20

- Added cmdline support.

## 2 - 2017-04-18

- Configure Swagger library logging.

## 1 - 2017-03-30

- First Version

[16]: https://github.com/zaproxy/zap-extensions/releases/openapi-v16
[15]: https://github.com/zaproxy/zap-extensions/releases/openapi-v15
[14]: https://github.com/zaproxy/zap-extensions/releases/openapi-v14
[13]: https://github.com/zaproxy/zap-extensions/releases/openapi-v13
