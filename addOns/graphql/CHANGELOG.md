# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
### Added
- It is now possible to disable the query generator completely.

## [0.16.0] - 2023-05-31
### Added
- An informational alert is raised when the GraphQL server implementation is identified using fingerprinting techniques.

### Changed
- Dependency updates.

## [0.15.0] - 2023-05-03
### Added
- An informational alert is raised if a GraphQL endpoint that supports introspection is discovered during spidering.

### Changed
- Dependency updates.
- Improved detection of GraphQl endpoints while spidering.
- It is no longer a requirement for schema URLs to end with `.graphql` or `.graphqls` when importing from the UI.

### Fixed
- Display the whole operation name in the Sites tree (could be missing a character).

## [0.14.0] - 2023-04-04
### Fixed
- Do not report errors parsing valid JSON arrays.

### Changed
- Dependency updates.

## [0.13.0] - 2023-02-09
### Added
- Support for relative file paths in the Automation Framework job.

### Changed
- Dependency updates and maintenance changes.

### Fixed
- Fixed exception in the variant when POST message has empty body and no content-type (Issue 7689).

## [0.12.0] - 2022-11-17
### Changed
- The GraphQL Support Script has been superseded by a variant.
- Argument names will now be used to get values from the form handler add-on, instead of argument types.
- Dependency updates and maintenance changes.

### Fixed
- Introspection was not working for some applications (Issue 7602).
- Variables in JSON queries were being added incorrectly.
- Attack payloads were being injected outside the quotes of inline string arguments.

## [0.11.0] - 2022-10-27
### Changed
- Update minimum ZAP version to 2.12.0.
- Remove parser used for core spider (Related to Issue 3113).

## [0.10.0] - 2022-09-23
### Changed
- Maintenance changes.
- Update dependency, which reduces add-on file size (Issue 7322).
- Use Spider add-on (Issue 3113).

## [0.9.0] - 2022-04-05
### Changed
- Replace variables present in `schemaFile` when running the automation job.

## [0.8.0] - 2022-02-02
### Changed
- Update minimum ZAP version to 2.11.1.
- Reduce printed errors messages in the script Input Vector.
- When the automation Job is edited via UI Dialog then the status will be set to Not started

## [0.7.0] - 2021-11-01
### Fixed
- A message is displayed if the "data" object in an introspection response
  is `null` ([Issue 6890](https://github.com/zaproxy/zaproxy/issues/6890)).

### Changed
- Dependency updates.

## [0.6.0] - 2021-10-06
### Changed
- Update minimum ZAP version to 2.11.0.

## [0.5.0] - 2021-09-16
### Fixed
 - Fixed var support in URLs ([Issue #6726](https://github.com/zaproxy/zaproxy/issues/6726))
 
### Changed
- Maintenance changes.

## [0.4.0] - 2021-08-05
### Added
- Automation Framework GUI

### Changed
- Maintenance changes.
- Report no URL specified in automation job as info instead of failure.

## [0.3.0] - 2021-03-30
### Changed
- Update minimum ZAP version to 2.10.0.
- Add two new options that allow enforcing maximum query depth leniently for fields with no leaf types.
- Add support for the automation framework.
- Maintenance changes.

### Fixed
- Fix invalid query generation when query depth was reached and the deepest fields had no leaf types (Issue 6316).
- Cope with missing Nashorn engine (Issue 6501).

## [0.2.0] - 2020-11-18
### Changed
- Enhanced Support for Script Input Vectors.
- Options are now exposed through the API.
- Optional Arguments are enabled by default.

### Fixed
- Fix clashes in variable names. See [PR#2550](https://github.com/zaproxy/zap-extensions/pull/2550) for details.
- Fix a bug where the "GraphQL Support.js" script was enabled when ZAP was restarted even if it had been disabled and saved before.
- Fix a bug where sites tree entries were not showing parameters because of the script.

## [0.1.0] - 2020-08-28
- First Version
- Features
  - Import a GraphQL Schema
  - Generate Queries from an imported Schema

[0.16.0]: https://github.com/zaproxy/zap-extensions/releases/graphql-v0.16.0
[0.15.0]: https://github.com/zaproxy/zap-extensions/releases/graphql-v0.15.0
[0.14.0]: https://github.com/zaproxy/zap-extensions/releases/graphql-v0.14.0
[0.13.0]: https://github.com/zaproxy/zap-extensions/releases/graphql-v0.13.0
[0.12.0]: https://github.com/zaproxy/zap-extensions/releases/graphql-v0.12.0
[0.11.0]: https://github.com/zaproxy/zap-extensions/releases/graphql-v0.11.0
[0.10.0]: https://github.com/zaproxy/zap-extensions/releases/graphql-v0.10.0
[0.9.0]: https://github.com/zaproxy/zap-extensions/releases/graphql-v0.9.0
[0.8.0]: https://github.com/zaproxy/zap-extensions/releases/graphql-v0.8.0
[0.7.0]: https://github.com/zaproxy/zap-extensions/releases/graphql-v0.7.0
[0.6.0]: https://github.com/zaproxy/zap-extensions/releases/graphql-v0.6.0
[0.5.0]: https://github.com/zaproxy/zap-extensions/releases/graphql-v0.5.0
[0.4.0]: https://github.com/zaproxy/zap-extensions/releases/graphql-v0.4.0
[0.3.0]: https://github.com/zaproxy/zap-extensions/releases/graphql-v0.3.0
[0.2.0]: https://github.com/zaproxy/zap-extensions/releases/graphql-v0.2.0
[0.1.0]: https://github.com/zaproxy/zap-extensions/releases/graphql-v0.1.0
