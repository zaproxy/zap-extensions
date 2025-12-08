# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
### Added
- Document the engine name in the help page.

### Changed
- Update minimum ZAP version to 2.17.0.
- Update Groovy from 3.0.14 to 5.0.3.  
  Existing Groovy scripts should work without issues, 
  but if you encounter problems, please refer to the following.
  - [Groovy 4 Release Notes](https://groovy-lang.org/releasenotes/groovy-4.0.html)
  - [Groovy 5 Release Notes](https://groovy-lang.org/releasenotes/groovy-5.0.html#Groovy5.0-breaking)
- Update script templates:
  - authentication/AuthenticationDefaultTemplate.groovy - remove outdated example code.
  - httpsender/HttpSenderDefaultTemplate.groovy - update documentation.
  - encode-decode/EncodeDecodeDefaultTemplate.groovy - remove the `final` modifier from the `test` field.
  - httpfuzzerprocessor/FuzzerHttpProcessorDefaultTemplate.groovy - remove the `final` modifier from the `count` field.  
    **NOTE:** The last two changes were required due to the Groovy update.

## [3.2.0] - 2024-04-11
### Changed
- Update minimum ZAP version to 2.14.0.
- Maintenance changes.
- Replace usage of singletons with injected variables (e.g. `model`, `control`) in scripts.
- Dependency updates.
- Update Active and Passive Script Templates to include a `getMetadata` function. This will allow them to be used as regular scan rules.
- Depend on the `commonlib` and `scripts` add-ons for scan rule scripts.

### Fixed
- Updated encode-decode script template to conform to the latest method signatures.

## [3.1.0] - 2021-10-07
### Added
- encode-decode default template.

### Changed
- Update links to zaproxy and zap-extensions repos.
- Update minimum ZAP version to 2.11.0.

## [3.0.0] - 2020-12-15
### Added
- Add info and repo URLs.

### Changed
- Update minimum ZAP version to 2.10.0.
- Promote to beta status.
- Change add-on name/description and update help.
- Start using Semantic Versioning.
- Update Groovy from 2.4.14 to 3.0.2.

### Fixed
- Fix links in script templates.
- Fix missing parameter functions in template

## 2 - 2018-04-19

- Add help.
- Added script templates.

## 1 - 2018-03-15

- Initial Release

[3.2.0]: https://github.com/zaproxy/zap-extensions/releases/groovy-v3.2.0
[3.1.0]: https://github.com/zaproxy/zap-extensions/releases/groovy-v3.1.0
[3.0.0]: https://github.com/zaproxy/zap-extensions/releases/groovy-v3.0.0
