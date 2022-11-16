# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
### Changed
- Update dependency.

### Fixed
- Use always a plain connection to the outgoing HTTP proxy (Issue 7594).
- Do not change the case of the Content-Length header.
- Use the available response content when the Content-Length is more than what is available.
- Properly persist proxy error responses.

## [0.5.0] - 2022-11-09
### Fixed
- Fix authentication with TRACE requests and HTTP/NTLM reauthentication to proxy (Issue 7566).

## [0.4.0] - 2022-11-07
### Added
- Allow to enable and configure ALPN for local servers/proxies.

### Changed
- Update dependencies.

### Fixed
- Allow to send TRACE requests with payload and with an outgoing proxy (Issue 7578).
- Correct HTTP/NTLM reauthentication to target and proxy (Issue 7566).

## [0.3.0] - 2022-10-27
### Added
- Client Certificates management (PKCS#11 and PKCS#12).
- Connection options, HTTP proxy, and SOCKS proxy.
- A newer HTTP client implementation.

### Changed
- Update minimum ZAP version to 2.12.0.
- Minor tweaks in help pages for better rendering.
- Promoted to Beta status.
- Maintenance changes.
- Update user agents.

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

[0.5.0]: https://github.com/zaproxy/zap-extensions/releases/network-v0.5.0
[0.4.0]: https://github.com/zaproxy/zap-extensions/releases/network-v0.4.0
[0.3.0]: https://github.com/zaproxy/zap-extensions/releases/network-v0.3.0
[0.2.0]: https://github.com/zaproxy/zap-extensions/releases/network-v0.2.0
[0.1.0]: https://github.com/zaproxy/zap-extensions/releases/network-v0.1.0
[0.0.1]: https://github.com/zaproxy/zap-extensions/releases/network-v0.0.1
