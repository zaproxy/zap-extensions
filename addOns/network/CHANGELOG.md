# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
### Changed
- Minor tweaks in help pages for better rendering.
- Promoted to Beta status.

## [0.2.0] - 2022-04-06
### Added
- On weekly releases and versions after 2.11:
  - Management of local servers/proxies, supersedes core functionality;
  - Configuration of aliases for the servers/proxies ([Issue 3594](https://github.com/zaproxy/zaproxy/issues/3594));
  - Pass-through connections ([Issue 6832](https://github.com/zaproxy/zaproxy/issues/6832)).

## [0.1.0] - 2022-02-01
### Added
- Provide HTTP servers/proxies to other add-ons.

### Changed
- Update minimum ZAP version to 2.11.1.

## [0.0.1] - 2021-12-03
### Added
- API endpoints to generate, import ([Issue 2280](https://github.com/zaproxy/zaproxy/issues/2280)), and obtain the root CA certificate.
- On weekly releases and versions after 2.11:
  - Server certificates management.
  - Handle command line arguments `-certload`, `-certpubdump`, and `-certfulldump`.
  - Options panel to manage the root CA certificate and issued certificates.
  - API endpoints to configure the validity of the root CA certificate and issued certificates ([Issue 4673](https://github.com/zaproxy/zaproxy/issues/4673)).

[0.2.0]: https://github.com/zaproxy/zap-extensions/releases/network-v0.2.0
[0.1.0]: https://github.com/zaproxy/zap-extensions/releases/network-v0.1.0
[0.0.1]: https://github.com/zaproxy/zap-extensions/releases/network-v0.0.1
