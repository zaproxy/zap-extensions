# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased


## [0.9.0] - 2023-06-06
### Changed
- Use `TRACE` level (instead of `DEBUG`) to log client side HTTP traffic to avoid accidentally enabling it when debugging other add-ons.

### Fixed
- Do not close the client connection when the server closes it, if not required, to keep the client connection in good state and be used longer.

## [0.8.0] - 2023-05-03
### Added
- Allow to log client side HTTP traffic for debug purposes, using the name `org.zaproxy.addon.network.http`.

### Fixed
- Do not pass-through requests to the local proxies themselves (e.g. ZAP domain, aliases).
- Correctly handle concurrent requests (Issue 7838).
- Close connection on recursive request after notifying all handlers to still allow custom local proxies to serve or rewrite the request.
- Ensure WebSocket and SSE connections are not incorrectly reused (Issue 7730).

## [0.7.0] - 2023-04-04
### Changed
- Maintenance changes.
- Fallback to HTTP/1.1 in the main proxy if the client does not negotiate a protocol (ALPN) (Issue 7699).
- Read all main proxy configurations (`-config`) available, even if they don't include an address.
- Increase buffer used to read the HTTP body, to make reads more efficient.
- Clarify the description of command line arguments `-host` and `-port`.

### Fixed
- Ensure the whole HTTP response is delivered to the client before closing the connection.

## [0.6.0] - 2023-01-03
### Changed
- Allow access to the ZAP API when running in command line mode.
- Fallback to HTTP/1.1 in internal local servers/proxies if the client does not negotiate a protocol (ALPN).
- Dynamically unload the add-on on newer core versions.
- Update dependencies.
- Maintenance changes.

### Fixed
- Use always a plain connection to the outgoing HTTP proxy (Issue 7594).
- Do not change the case of the Content-Length header.
- Use the available response content when the Content-Length is more than what is available.
- Properly persist proxy error responses.
- Correctly manage cookies with domain and path attributes (Issue 7631).
- Do not prevent serving internal requests to the local servers/proxies.
- Consume the response body even when none expected (e.g. 204, HEAD), otherwise the previous body
would not be cleared when reusing the same message.

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

[0.9.0]: https://github.com/zaproxy/zap-extensions/releases/network-v0.9.0
[0.8.0]: https://github.com/zaproxy/zap-extensions/releases/network-v0.8.0
[0.7.0]: https://github.com/zaproxy/zap-extensions/releases/network-v0.7.0
[0.6.0]: https://github.com/zaproxy/zap-extensions/releases/network-v0.6.0
[0.5.0]: https://github.com/zaproxy/zap-extensions/releases/network-v0.5.0
[0.4.0]: https://github.com/zaproxy/zap-extensions/releases/network-v0.4.0
[0.3.0]: https://github.com/zaproxy/zap-extensions/releases/network-v0.3.0
[0.2.0]: https://github.com/zaproxy/zap-extensions/releases/network-v0.2.0
[0.1.0]: https://github.com/zaproxy/zap-extensions/releases/network-v0.1.0
[0.0.1]: https://github.com/zaproxy/zap-extensions/releases/network-v0.0.1
