# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased
### Added
- Add more auth examples:
 - Login form with existing (invalid) values for the credentials.
 - A div that may obscure the login fields with all requiring scrolling.
 - Login with a non std header and unrelated (but required) cookies.
 - Login with no link to the login form. Access is only via a redirect to a one time URL.
 - Login with fields under shadom DOM.
 - Login where the session token is base64 encoded when passed to the browser.
 - HTML page with input elements added with increasing delays.
 - A mock MS online login.

### Changed
- Update minimum ZAP version to 2.17.0.

## [0.10.0] - 2025-05-15
### Added
- Basic CSRF test app.
- Page with input elements that appear after a delay and off the displayed screen.
- Auth app which uses multiple (faked) domains.
- An auth example where there's a div that may obscure the login fields.

## [0.9.0] - 2025-01-31
### Added
- Link which is only shown if a localStorage item is set, for testing in browser spider authentication.

### Changed
- Update minimum ZAP version to 2.16.0.

## [0.8.0] - 2024-11-13
### Changed
- Sequence performance test to make it actually possible to test it using automation.
- CSS and JS responses are now set cache enabled.

## [0.7.0] - 2024-10-07
### Added
- Extra protected pages to simple-json-cookie to ensure spidering really works.
- Sequence performance test.

### Fixed
- Issue where folder level pages without a trailing slash did not link correctly to sub pages.


## [0.6.0] - 2024-07-22
### Added
- Page protected by auth in order to provide a simple test for authenticated spidering.

### Changed
- Update minimum ZAP version to 2.15.0.

## [0.5.0] - 2024-01-10
### Added
- Auth page which uses header and a cookie set via JavaScript.

## [0.4.0] - 2023-12-19
### Changed
- Update minimum ZAP version to 2.14.0.
- Maintenance changes.

### Added
- Add ZAP API endpoint to get the OpenAPI definition of the ZAP API.
- Pages which store a variety of data in localStorage and sessionStorage.

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

[0.10.0]: https://github.com/zaproxy/zap-extensions/releases/dev-v0.10.0
[0.9.0]: https://github.com/zaproxy/zap-extensions/releases/dev-v0.9.0
[0.8.0]: https://github.com/zaproxy/zap-extensions/releases/dev-v0.8.0
[0.7.0]: https://github.com/zaproxy/zap-extensions/releases/dev-v0.7.0
[0.6.0]: https://github.com/zaproxy/zap-extensions/releases/dev-v0.6.0
[0.5.0]: https://github.com/zaproxy/zap-extensions/releases/dev-v0.5.0
[0.4.0]: https://github.com/zaproxy/zap-extensions/releases/dev-v0.4.0
[0.3.0]: https://github.com/zaproxy/zap-extensions/releases/dev-v0.3.0
[0.2.0]: https://github.com/zaproxy/zap-extensions/releases/dev-v0.2.0
[0.1.0]: https://github.com/zaproxy/zap-extensions/releases/dev-v0.1.0
[0.0.1]: https://github.com/zaproxy/zap-extensions/releases/dev-v0.0.1
