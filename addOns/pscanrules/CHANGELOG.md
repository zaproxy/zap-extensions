# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased


## [31] - 2020-12-15
### Changed
- Now targeting ZAP 2.10.
- The following scan rules now support Custom Page definitions:
  - Application Error
  - Cache Control
  - X-Content-Type-Options
  - X-Frame-Options

## [30] - 2020-11-26
### Changed
- The CSP scan rule now checks if the form-action directive allows wildcards.
- The CSP scan rule now includes further information in the description of allowed wildcard directives alerts when the impacted directive is one (or more) which doesn't fallback to default-src.
- Maintenance changes.
- Changed ViewState and XFrameOption rules to return example alerts for the docs.
- Handle an IllegalArgumentException that could occur in the CSP scan rule if multiple CSP headers were present and one (or more) had a report-uri directive when trying to merge them.
- Allow to ignore cookies in same site and loosely scoped scan rules.
- The Application Error scan rule will not alert on web assembly responses.

## [29] - 2020-06-01
### Changed
- Updated owasp.org references (Issue 5962).
- Correct spelling of "frame-ancestors" in the alert details of the CSP scan rule wildcard directive check (Issue 6014).

## [28] - 2020-04-08

### Changed
- 'CSP Scanner' rule upgrade salvation library to v2.7.2.
- 'CSP Scanner' rule now merges (intersects) multiple CSP header fields to more accurately evaluate policies and prevent parsing issues (Issue 5931).
- 'X-Frame-Options Header Scanner' replace now invalid MSDN reference link with MDN link on X-Frame-Options (Issue 5867).
- 'Information Disclosure Referrer' scan rule added support for looking up evidence against an Open Source Bank Identification Number List. Confidence is now modified based on whether the lookup is successful or not. Additional details are added to 'Other Info' if available (Issue 5842).

## [27] - 2020-02-11

### Changed
- Minimum ZAP version is now 2.9.0. (Various scan rules adjusted to address core deprecations.)
- 'Username Hash Found' scan rule now uses updated core functionality to retrieve configured users.
- Tweak help for 'Cookie HttpOnly' scan rule.
- 'Information Disclosure: Suspicious Comments' if matched within script block or JS response raise Alert with Low confidence.
- Migrate an input file from Beta to Release that were missed during previous promotions.
  - This addresses errors such as `[ZAP-PassiveScanner] ERROR org.zaproxy.zap.extension.pscanrules.InformationDisclosureInURL  - No such file: .... /xml/URL-information-disclosure-messages.txt`
- 'Application Error' scan rule now supports custom payloads when used in conjunction with the Custom Payloads addon.
- Timestamp Disclosure scan rule now only considers potential timestamps within plus or minus one year when used at High threshold (Issue 5837).
- 'Application Error' scan rule's patterns file `application_errors.xml` is now copied to ZAP's home directory, which means it is editable by the user. As well as being more consistent with other similar input files.
- 'Information Disclosure - Sensitive Information in URL' correct evidence field for some alerts, and enhance other info details (Issue 5832).
- Maintenance changes.

### Removed
- 'Header XSS Protection' was deprecated and removed (Issue 5849).

### Fixed
- Fix typo in the help page.

## [26] - 2020-01-17

### Changed
- "Cookie HttpOnly", "Cookie Secure Flag", and "Cookie Without SameSite Attribute" scan rules no longer alert on expired (deleted) cookies (Issue 5295).

### Added
- Added links to the code in the help.
- Add info and repo URLs.

## [25] - 2019-12-16

### Changed
- Content Security Policy scan rule: Update to Salvation 2.7.0, add handling for script-src-elem, script-src-attr, style-src-elem, and style-src-attr (Issue 5459).
- Minimum ZAP version is now 2.8.0.

### Added
- The following scan rules were added, promoted from Beta to Release:
  - Cookie Without SameSite Attribute
  - Cross Domain Misconfiguration
  - Information Disclosure: In URL
  - Information Disclosure: Referrer
  - Information Disclosure: Suspicious Comments
  - Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s)
  - Timestamp Disclosure
  - Username Hash Found
  - X-AspNet-Version Response Header Scanner
  - X-Debug-Token Information Leak

## [24] - 2019-06-07

- Maintenance changes.
- Migrate CSP Scanner into the main passive scan release package (promoting it to Release). Upgrade Salvation (dependency) to 2.6.0.
- Application Error scanner change for HTTP 500. Alert changed to low risk for HTTP 500, and not raised at all when Threshold is High.  
- Updated the reference link for the alert: Web Browser XSS Protection Not Enabled.
- Promote Charset Mismatch Scanner to release (Issue 4460).
- Promote ViewState Scanner to release (Issue 4453).
- Promote Insecure JSF ViewState Scanner to release (Issue 4455).
- Promote Insecure Authentication Scanner to release (Issue 4456).
- Promote Information Disclosure Debug Errors Scanner to release (Issue 4457).
- Promote CSRF Countermeasures Scanner to release (Issue 4458).
- Promote Cookie Loosely Scoped Scanner to release (Issue 4459).

## 23 - 2018-08-15

- Fix a typo in the description of Referer Exposes Session ID.
- Address false negative on jsessionid in URL Rewrite when preceded by a semi-colon and potentially followed by parameters (Issue 3008).
- Address potential false positive in Cross Domain Script Inclusion Scanner by ensuring that only HTML responses are analyzed.

## 22 - 2018-01-19

- Retired the password auto-complete passive scan rule (Issue 4215).

## 21 - 2017-11-27

- Update for 2.7.0, Minor code changes to address deprecation.

## 20 - 2017-11-24

- Fix false positive with Secure Pages Include Mixed Content and JavaScript files (Issue 3581).
- Fix false positive with Private IP Disclosure when target is a private IP on a non-standard port (Issue 3549).
- Fix false positive with X-Content-Type-Options Header Missing with certain system locales.
- Fix X-Content-Type-Options help content (Issue 3986).
- Remove N/A value from parameter of alert Session ID in URL Rewrite.

## 19 - 2017-04-06

- Correct evidence of alerts raised by scanner "Application Error Disclosure".
- Fixed some false positives caused by scanner "Private Address Disclosure".
- Add support for cookie ignore rule.

## 18 - 2016-08-09

- Only report issues on errors and redirects at LOW threshold.
- Only report X-Frame-Options issues at LOW threshold if CSP 'frame-ancestors' element present.
- Issue 2732: False positives for security headers missing due to redirections.

## 17 - 2016-07-15

- Correctly check that the cookie being set has the Secure and HttpOnly attributes.
- Do not set the attack field for Private IP Disclosure and Secure Pages Include Mixed Content.
- Remove "N/A" parameter from the alert of Application Error Disclosure.
- Issue 2539 - X-Frame-Options passive scanner, add compliance variants.
- Corrected Password Autocomplete parameter in alert

## 16 - 2016-06-02

- Issue 823 - i18n (internationalise) release passive scan rules.
- Add CWE and WASC IDs to passive scanners which may have been lacking those details.
- Issue 2405 - Accommodate responses with multiple Cache-Control headers.
- Issue 395 - Add handling for allowed cross domain hosts (via context definition at HIGH threshold).

## 15 - 2015-12-04

- Issue 1594 - TestInfoSessionIdURL overhaul matching mechanism.

## 14 - 2015-09-07

- Issue 1600 - XFrameOptionScanner, add handling to prevent alerts on error responses at High threshold.
- Issue 760 - XContentTypeOptionsScanner, add handling to prevent alerts on error responses at High threshold.

## 13 - 2015-08-23

- Minor code changes.

## 12 - 2015-04-13

- Minor fixes to XFrameOptionsScanner (Issue 1256).
- XContentTypeOptionsScanner Internationalization (Issue 1343).
- XContentTypeOptionsScanner default/error page updates (Issue 760).
- TestInfoSessionIdURL added value length check to reduce false positives (Issue 1396).
- Application Error Disclosure shows evidence in attack (Issue 1487).
- Updated to ZAP 2.4.
- Issue 823: i18n active/passive scan rules.

## 11 - 2014-06-14

- Improved scanner "Web Browser XSS Protection Not Enabled" (former "IE8's XSS protection filter not disabled");
- Fixed duplicated plug-in ID.

## 10 - 2014-05-21

- Fixed an issue with search of strings that affected "Application Error disclosure" scanner (Issue 1186).

## 9 - 2014-04-10

- Added reference for X-Content-Type-Options header missing.
- Changed help file structure to support internationalisation (Issue 981).
- Added content-type to help pages (Issue 1080).
- Changed passive scanners to expose its IDs (Issue Issue 1101).
- Updated add-on dir structure (Issue 1113).

## 8 - 2013-10-21

- Refactored new plugins for information disclosure detection

## 7 - 2013-09-11

- Updated to be compatible with 2.2.0

## 4 - 2013-04-18

- Updated for ZAP 2.1.0

## 3 - 2013-01-17

- Updated to support new addon format

## 1 - 2012-12-10



[31]: https://github.com/zaproxy/zap-extensions/releases/pscanrules-v31
[30]: https://github.com/zaproxy/zap-extensions/releases/pscanrules-v30
[29]: https://github.com/zaproxy/zap-extensions/releases/pscanrules-v29
[28]: https://github.com/zaproxy/zap-extensions/releases/pscanrules-v28
[27]: https://github.com/zaproxy/zap-extensions/releases/pscanrules-v27
[26]: https://github.com/zaproxy/zap-extensions/releases/pscanrules-v26
[25]: https://github.com/zaproxy/zap-extensions/releases/pscanrules-v25
[24]: https://github.com/zaproxy/zap-extensions/releases/pscanrules-v24
