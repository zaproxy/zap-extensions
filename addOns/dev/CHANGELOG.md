# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased
### Changed
- Update minimum ZAP version to 2.14.0.

### Added
- Add ZAP API endpoint to get the OpenAPI definition of the ZAP API.

## [0.3.0] - 2023-09-07

### Added
- Auth page where the return key does not submit the form
- Auth page which uses one request and one cookie
- Auth page which uses multiple requests and multiple cookies
- OpenAPI auth and unauth pages

### Changed
- Update minimum ZAP version to 2.13.0.
- Added TestAuthDirectory abstract class to reduce duplicated code.

## [0.2.0] - 2023-05-09

### Added
- Auth pages where the password field is not accessible until the username is filled in.

## [0.1.0] - 2023-04-28

### Changed
- Auth pages to provide a variety of verification responses.

## [0.0.1] - 2023-04-19

- First version.

[0.3.0]: https://github.com/zaproxy/zap-extensions/releases/dev-v0.3.0
[0.2.0]: https://github.com/zaproxy/zap-extensions/releases/dev-v0.2.0
[0.1.0]: https://github.com/zaproxy/zap-extensions/releases/dev-v0.1.0
[0.0.1]: https://github.com/zaproxy/zap-extensions/releases/dev-v0.0.1
