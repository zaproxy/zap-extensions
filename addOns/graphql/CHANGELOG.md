# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased


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

[0.2.0]: https://github.com/zaproxy/zap-extensions/releases/graphql-v0.2.0
[0.1.0]: https://github.com/zaproxy/zap-extensions/releases/graphql-v0.1.0
