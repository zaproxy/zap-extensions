# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased


## [41] - 2024-05-10
### Changed
- Rely on Common Library add-on for use of Jackson library.

## [40] - 2024-05-07
### Changed
- Update minimum ZAP version to 2.15.0.
- Maintenance changes.
- Dependency updates.

## [39] - 2024-01-26
### Added
- Video link in help for Automation Framework job.

### Changed
- Dependency updates.

## [38] - 2023-10-23
### Changed
- Dependency updates.

### Fixed
- An issue in the headers generator which might lead to content-type header being incorrectly set.

## [37] - 2023-10-12
### Changed
- Update minimum ZAP version to 2.14.0.

## [36] - 2023-09-07
### Changed
- Dependency updates.
- The "Import an OpenAPI definition from the local file system" and "Import an OpenAPI definition from a URL" menu items
  were merged into one, "Import an OpenAPI Definition".
- Depend on newer versions of Automation Framework and Common Library add-ons (Related to Issue 7961).
- Use Common Library add-on to obtain the Value Generator (Issue 8016).

### Fixed
- Importing empty or invalid OpenAPI definitions failed silently in some cases (Issue 7949).

## [35] - 2023-07-11
### Changed
- Update minimum ZAP version to 2.13.0.
- Dependency updates.

## [34] - 2023-06-27
### Changed
- Dependency updates.

### Fixed
- Fix exception when generating data for parameters without schema.
- An exception which might occur on large definition imports (Issue 7876).

## [33] - 2023-04-04
### Changed
- Dependency updates.

### Fixed
- Fix null pointer exception when importing a definition with requestBody content set as an empty dictionary (Issue 7808).

## [32] - 2023-02-09
### Added
- Support for relative file paths and ones including vars in the Automation Framework job.

### Changed
- Maintenance changes.

## [31] - 2023-01-03
### Changed
- Maintenance changes.

### Fixed
- When a definition doesn't define a response then an appropriate warning bubbles up, no longer resulting in a NullPointerException (Issue 7115).

## [30] - 2022-11-15
### Changed
- Dependency updates.
- Each imported endpoint is included in the selected context, unless its URL matches an already existing *Include in
  Context* regex entry.

## [29] - 2022-10-27
### Changed
- Update minimum ZAP version to 2.12.0.
- Remove parser used for core spider (Related to Issue 3113).
- Maintenance changes.


## [28] - 2022-09-21
### Added
- Imported specs are now persisted to the session database. They are used by the new variant to mark path parameters as
  Data Driven Nodes.

### Fixed
- JSON body examples specified under `schema` were being enclosed in quotes.
- Error message when `apiFile` field is not accessible was outputting the `targetUrl` and not the incorrect filename (Issue 7370).

### Changed
- Maintenance changes.
- Use Spider add-on (Issue 3113).
- Use Form Handler add-on directly.
- DDNs added as Structural Modifiers have been superseded by a custom variant. The variant supports nested DDNs and leaf
  DDNs, prevents non-parameter URL paths from being merged with DDNs, and treats paths with different HTTP methods
  uniquely. DDNs are named with the parameter name from the spec.

## [27] - 2022-03-29
### Added
- Support content field (JSON) in parameters (Issue 6166).

### Changed
- Now depends on commonlib for display of import progress (Issue 6783).
- Dependency updates.

### Fixed
- Properly generate Content-Type header when in presence of more than one supported content (Issue 7082).
- Quote provided string values in JSON content (Issue 7128).
- Properly handle empty default values in server variables.

## [26] - 2022-02-01

### Fixed
- Do not report "Unrecognised parameter" for valid parameters.

## [25] - 2022-01-18
### Changed
- Update minimum ZAP version to 2.11.1.
- Dependency updates.
- When the automation Job is edited via UI Dialog then the status will be set to Not started

### Fixed
- Parameter examples specified as part of the schema were not being used.

## [24] - 2021-12-06
### Changed
- Use examples defined in parameters ([Issue #6870](https://github.com/zaproxy/zaproxy/issues/6870)).
- Tweak error message shown when content type is not supported.
- Dependency updates.

### Fixed
- Fixed ClassCastException when using nested map properties with mixed definition styles. 

## [23] - 2021-10-06
### Fixed
- Fixed StackOverflow in the Body/DataGenerator when an invalid property type is specified. ([Issue #6591](https://github.com/zaproxy/zaproxy/issues/6591))

### Added
- Use path and operation servers ([Issue #6754](https://github.com/zaproxy/zaproxy/issues/6754)).

### Changed
- Warn when request has content type `application/xml`, not supported (Related to [Issue #6767](https://github.com/zaproxy/zaproxy/issues/6767)).
- Maintenance changes.
- Update minimum ZAP version to 2.11.0.

## [22] - 2021-09-16
### Changed
- Maintenance changes.

## [21] - 2021-09-01
### Added
- The import progress is now displayed using a Progress Panel.

### Fixed
- Fixed var support in URLs ([Issue #6726](https://github.com/zaproxy/zaproxy/issues/6726))
- Import file definition even if it has issues ([Issue #6758](https://github.com/zaproxy/zaproxy/issues/6758)).

### Changed
- Use `application/json` media type examples when available.

## [20] - 2021-08-05
### Added
- Automation Framework GUI

### Changed
- Maintenance changes.

### Fixed
- Fix RequestMethod enum name for OPTIONS (Issue 6666)

## [19] - 2021-06-29
### Added
- Added support for Multipart form-data (Issue 6418).

### Changed
- Always use enum values when defined (Issue 6489).
- Now using 2.10 logging infrastructure (Log4j 2.x).
- Automation parameters are now in camelCase. This is a breaking change, and older automation configurations containing all-lowercase openapi parameters will stop working.
- The import dialogs now show the values used in the previous import when reopened.
- Maintenance changes.

### Fixed
- NPE if form has no schema element. 

## [18] - 2021-03-09
### Added
- Support for the Automation Framework
- Support for statistics (number of URLs added) 

### Changed
- Maintenance changes.

## [17] - 2020-12-15
### Added
- Handle cookie parameters (Issue 6045).
- Use default values in `x-www-form-urlencoded` and `json` bodies (Issue 6095).

### Changed
- Show import exceptions in the Output tab (Issue 6042).
- Maintenance changes.
- Update minimum ZAP version to 2.10.0.

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

[41]: https://github.com/zaproxy/zap-extensions/releases/openapi-v41
[40]: https://github.com/zaproxy/zap-extensions/releases/openapi-v40
[39]: https://github.com/zaproxy/zap-extensions/releases/openapi-v39
[38]: https://github.com/zaproxy/zap-extensions/releases/openapi-v38
[37]: https://github.com/zaproxy/zap-extensions/releases/openapi-v37
[36]: https://github.com/zaproxy/zap-extensions/releases/openapi-v36
[35]: https://github.com/zaproxy/zap-extensions/releases/openapi-v35
[34]: https://github.com/zaproxy/zap-extensions/releases/openapi-v34
[33]: https://github.com/zaproxy/zap-extensions/releases/openapi-v33
[32]: https://github.com/zaproxy/zap-extensions/releases/openapi-v32
[31]: https://github.com/zaproxy/zap-extensions/releases/openapi-v31
[30]: https://github.com/zaproxy/zap-extensions/releases/openapi-v30
[29]: https://github.com/zaproxy/zap-extensions/releases/openapi-v29
[28]: https://github.com/zaproxy/zap-extensions/releases/openapi-v28
[27]: https://github.com/zaproxy/zap-extensions/releases/openapi-v27
[26]: https://github.com/zaproxy/zap-extensions/releases/openapi-v26
[25]: https://github.com/zaproxy/zap-extensions/releases/openapi-v25
[24]: https://github.com/zaproxy/zap-extensions/releases/openapi-v24
[23]: https://github.com/zaproxy/zap-extensions/releases/openapi-v23
[22]: https://github.com/zaproxy/zap-extensions/releases/openapi-v22
[21]: https://github.com/zaproxy/zap-extensions/releases/openapi-v21
[20]: https://github.com/zaproxy/zap-extensions/releases/openapi-v20
[19]: https://github.com/zaproxy/zap-extensions/releases/openapi-v19
[18]: https://github.com/zaproxy/zap-extensions/releases/openapi-v18
[17]: https://github.com/zaproxy/zap-extensions/releases/openapi-v17
[16]: https://github.com/zaproxy/zap-extensions/releases/openapi-v16
[15]: https://github.com/zaproxy/zap-extensions/releases/openapi-v15
[14]: https://github.com/zaproxy/zap-extensions/releases/openapi-v14
[13]: https://github.com/zaproxy/zap-extensions/releases/openapi-v13
