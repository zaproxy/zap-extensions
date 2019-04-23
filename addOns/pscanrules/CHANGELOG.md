# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased

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



