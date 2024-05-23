# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
### Changed
- Maintenance changes.

## [0.16.0] - 2024-05-07
### Changed
- Update minimum ZAP version to 2.15.0.
- Update default user-agents.

### Fixed
- Help content typos.

## [0.15.0] - 2024-03-25
### Added
- Methods for accessing the upstream proxy.

## [0.14.0] - 2024-02-22
### Changed
- Notify proxy listeners concurrently, might break listeners that do not correctly handle concurrency.
- Update dependencies.

### Removed
- Remove legacy options panels that helped the user find the new options panels:
  - Client Certificate
  - Connection
  - Dynamic SSL Certificates
  - Local Proxies

### Fixed
- Accept rate limit rule's group by in lower case, when handling the API requests.
- Prevent configuration of the outgoing HTTP/SOCKS Proxy with the address of one of the Local Servers/Proxies, as it would lead to unintended request loops (Issue 5308).
- Fix exception while proxying NTLM authentication (Issue 7685).

## [0.13.0] - 2023-11-17
### Added
- On weekly releases and versions after 2.14, handle content encodings and add `br` content encoding on supported OSes (Issue 2198).

### Fixed
- Handle cookies like browsers, mostly send what is received (Issues 1232 and 7874).
- Do not set content-length to SSE responses, which would end up being closed prematurely.

## [0.12.0] - 2023-10-12
### Added
- Allow to completely disable host header normalization.

### Changed
- Update minimum ZAP version to 2.14.0.
- Update default user-agents.
- Update dependencies.

### Fixed
- Do not initialize the view when failed to start the main proxy in `cmd` and `daemon` modes.

## [0.11.2] - 2023-09-27
### Fixed
- Ensure the main proxy with custom port (`-port`) is stopped when initialising after installation in `cmd` and `daemon` modes.

## [0.11.1] - 2023-09-27
### Fixed
- Ensure servers are stopped when initialising after installation in `cmd` and `daemon` modes.

## [0.11.0] - 2023-09-26
### Added
- Allow to create custom servers with the ZAP API.

### Changed
- Maintenance changes.
- Update names of generated root CA certificate and issued server certificates.
- Help improvements.

### Fixed
- Correct declaration of mandatory parameters of the API endpoint `setRateLimitRuleEnabled`.

## [0.10.0] - 2023-07-11
### Added
- HTTP/HTTPS rate limiting capability.
- Allow to add a CRL Distribution Point in generated server certificates.
- On weekly releases and versions after 2.12 allow to manage global exclusions, supersedes core functionality.

### Changed
- Update minimum ZAP version to 2.13.0.
- Update dependencies.
- Update default user-agents.

### Fixed
- Keep the original stack trace of timeout and unknown host exceptions.

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

[0.16.0]: https://github.com/zaproxy/zap-extensions/releases/network-v0.16.0
[0.15.0]: https://github.com/zaproxy/zap-extensions/releases/network-v0.15.0
[0.14.0]: https://github.com/zaproxy/zap-extensions/releases/network-v0.14.0
[0.13.0]: https://github.com/zaproxy/zap-extensions/releases/network-v0.13.0
[0.12.0]: https://github.com/zaproxy/zap-extensions/releases/network-v0.12.0
[0.11.2]: https://github.com/zaproxy/zap-extensions/releases/network-v0.11.2
[0.11.1]: https://github.com/zaproxy/zap-extensions/releases/network-v0.11.1
[0.11.0]: https://github.com/zaproxy/zap-extensions/releases/network-v0.11.0
[0.10.0]: https://github.com/zaproxy/zap-extensions/releases/network-v0.10.0
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
