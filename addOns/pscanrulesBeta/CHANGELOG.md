# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased
### Changed
- Update minimum ZAP version to 2.15.0.

## [37] - 2024-02-12

### Added
- Website alert links (Issue 8189).

### Changed
- Maintenance changes.

## [36] - 2024-01-16
### Changed
- Update minimum ZAP version to 2.14.0.
- The Source Code Disclosure rule no longer considers responses that contain ISO control characters (those which are likely to be binary file types) (Issue 8191).

## [35] - 2023-09-08
### Changed
- Use HTTPS and resolve redirections in the alert references.
- The alerts of the Source Code Disclosure scan rule no longer have the evidence duplicated in the Other Info field.

## [34] - 2023-07-20
### Added
- The following scan rules were added, having been promoted from Alpha:
  - Insufficient Site Isolation Against Spectre Vulnerability
  - Source Code Disclosure

### Changed
- Update minimum ZAP version to 2.13.0.
- Maintenance changes.

## [33] - 2023-05-03

### Changed
- The following scan rules now have functionality to generate example alerts for documentation purposes (Issue 6119).
    - In Page Banner Information Leak
    - Java Serialization Object
    - HTTP Parameter Override
    - Sub Resource Integrity Attribute Missing

## [32] - 2023-03-03
### Changed
- Maintenance changes.

### Fixed
- The Cacheable scan rule should now be more tolerant when parsing s-max-age values.

## [31] - 2022-10-27
### Added
- The following scan rules were added, having been promoted from Alpha:
  - Content Cacheable
  - In Page Banner Info Leak
  - JS Function
  - JSO
  - Permissions Policy
  - Sub Resource Integrity Attribute

### Changed
- Update minimum ZAP version to 2.12.0.
- Content Cacheability scan rule now has functionality to generate example alerts for documentation purposes (Issue 7502).

### Removed
- The following scan rules were removed, having been promoted to Release:
  - Big Redirects
  - Directory Browsing
  - Hash Disclosure
  - HeartBleed
  - Insecure Form Load
  - Insecure Form Post
  - Link Target
  - Modern App Detection
  - PII
  - Retrieved From Cache
  - Server Header Info Leak
  - Strict Transport Security
  - User Controlled Charset
  - User Controlled Cookie
  - User Controlled HTML Attributes
  - User Controlled Javascript Event
  - User Controlled Open Redirect
  - X-Backend-Server Information Leak
  - X-ChromeLogger-Data Info Leak   

## [30] - 2022-09-15
### Changed
- Maintenance changes.
- Reverse Tabnabbing scan rule now leverages the Common Library Trusted Domains implementation.

## [29] - 2022-04-05
### Changed
- Update minimum ZAP version to 2.11.1.
- Maintenance changes.

### Removed
- Content Security Policy (CSP) Header Not Set scan rule promoted to release.

## [28] - 2021-12-01
### Fixed
- Fixed false positive in Reverse Tabnabbing scan rule.

### Changed
- Maintenance changes.

### Added
- OWASP Web Security Testing Guide v4.2 mappings where applicable.

## [27] - 2021-10-07
### Added
- OWASP Top Ten 2021/2017 mappings.

### Changed
- Reverse Tabnabbing Scan Rule will now alert when the 'opener' keyword is present.
- Maintenance changes.
- Update minimum ZAP version to 2.11.0.

## [26] - 2021-07-29
### Fixed
- PII Disclosure scan rule now ignores images (Issue 6697).
- PII Disclosure scan rule will now ignore seeming decimal numbers unless at Low threshold (Issue 6639).

## [25] - 2021-06-17
### Changed
- Now using 2.10 logging infrastructure (Log4j 2.x).
- Update RE2/J library to latest version (1.6).
- PII Scan Rule will now ignore CSS and style information (Issue 6288).
- Discontinued use of CWE-16 and switched to more specific weaknesses in the following scan rules:
  - CSP Missing
  - Insecure Form Load
  - Insecure Form Post
  - Strict-Transport-Security
- Hash Disclosure scan rule will now only evaluate JavaScript responses at Low threshold (Issue 6071).
- Added/updated the details of some alerts (some changes might break Alert Filters)
  - Insecure Form Load
    - Added evidence
  - Insecure Form Post
    - Added evidence
- Maintenance changes.
- Update links to repository.

## [24] - 2020-12-15
### Changed
- Now targeting ZAP 2.10.
- The following scan rules now support Custom Page definitions:
  - Insecure Form Load
  - Insecure Form Post
  - User Controlled Charset
  - User Controlled HTML Attribute
  - User Controlled JavaScript Event

## [23] - 2020-11-18
### Changed
- Update RE2/J library to latest version (1.5).
- Maintenance changes.
- Content Security Policy header missing scan rule changed to Medium risk in order to align with other CSP findings, and confidence to High (Issue 6301).

## [22] - 2020-06-01
### Added
- Added links to the code in the help.
- Add info and repo URLs.
- 'Modern Web Application' scan rule was added, being promoted to Beta.

### Changed
- Update minimum ZAP version to 2.9.0.
- 'PII Disclosure scanner' alerts and help entry renamed 'PII Disclosure' for clarity and proper title caps.
- 'PII Disclosure' added further false positive handling with regard to exponential numbers such as 2.4670000000000001E-2 or 2.4670000000000001E2.
- Maintenance changes.
- 'Servlet Parameter Pollution' scan rule will now only scan responses for in Context URLs for which the Technology JSP/Servlet is applicable.
- Updated owasp.org references (Issue 5962).
- 'PII Disclosure' added support for looking up evidence against an Open Source Bank Identification Number List. Confidence is now modified based on whether the lookup is successful or not. Additional details are added to 'Other Info' if available (Issue 5842).
- Changed to set Risk Info and Confidence Low for the following passive scan rules: User Controlled Cookie, User Controlled JavaScript Event, and User Controlled Charset.

## [21] - 2019-12-16

### Added
- The following scan rules were added being promoted from Alpha to Beta:
  - Big Redirect Detected (Potential Sensitive Information Leak)
  - Content Security Policy (CSP) Header Not Set
  - Cookie Poisoning
  - Directory Browsing
  - Hash Disclosure
  - Heartbleed OpenSSL Vulnerability (Indicative)
  - HTTP Server Response Header Scanner
  - HTTP to HTTPS Insecure Transition in Form Post
  - HTTPS to HTTP Insecure Transition in Form Post
  - Open Redirect
  - PII Scanner
  - Retrieved from Cache
  - Reverse Tabnabbing
  - Strict-Transport-Security Header Scanner
  - User Controllable Charset
  - User Controllable HTML Element Attribute (Potential XSS)
  - User Controllable JavaScript Event (XSS)
  - X-Backend-Server Header Information Leak
  - X-ChromeLogger-Data (XCOLD) Header Information Leak

### Removed
- The following scan rules were removed in being promoted Beta to Release:
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

## [20] - 2019-11-19

### Changed
- Tweak Information Disclosure - Suspicious Comments scanner to ignore whitespace before/after suspicious comments terms in the suspicious-comments.txt config file.
- Only scan for Servlet Parameter Pollution at LOW threshold (part of Issue 4454).
- Username IDOR scan rule now supports use of the Custom Payload addon.

## [19] - 2019-06-07

- Fix typo and correct term in help page.
- Fix typo in scanner name.
- Tweak alert Authentication Credentials Captured to use Description field instead of Attack.
- Remove Charset Mismatch Scanner (promoted to release Issue 4460).
- Remove ViewState Scanner (promoted to release Issue 4453).
- Remove Insecure JSF ViewState Scanner (promoted to release Issue 4455).
- Remove Insecure Authentication Scanner (promoted to release Issue 4456).
- Remove Information Disclosure Debug Errors Scanner (promoted to release Issue 4457).
- Remove CSRF Countermeasures Scanner (promoted to release Issue 4458).
- Remove Cookie Loosely Scoped Scanner (promoted to release Issue 4459).
- Promote Cookie Same Site Scanner to Beta (Issue 4464).
- Promote Cross Domain Misconfiguration Scanner to Beta (Issue 4465).
- Promote Timestamp Scanner to Beta (Issue 4466).
- Promote Username IDOR Scanner to Beta (Issue 4467).
- Promote X AspNet Version Scanner to Beta (Issue 4468).
- Promote X Debug Token Scanner to Beta (Issue 4469).
- Promote X PoweredBy Scanner to Beta (Issue 4470).

## 18 - 2018-01-19

- Minor code changes to address deprecation.<br/>
- At HIGH threshold only perform CSRF checks for in scope messages (Issue 1354).<br/>
- Exclude JavaScript response types from the InformationDisclosureDebugErrors scanner unless threshold is Low (Issue 4210).<br/>

## 17 - 2017-11-24

- Minor changes to InsecureJFSViewStatePassiveScanner (check response contains JSF viewstate or if it's server stored).<br/>
- Improve the domain matching in CookieLooselyScopedScanner.<br/>
- Issue 3449: CSRFcountermeasures passive scanner now raises alerts on a per-form basis on pages with multiple forms.<br/>
- Issue 3937: Update ServletParameterPollutionScanner reference.<br/>

## 16 - 2017-04-25

- Added some keywords to the list of suspicious comments. <br/>

## 15 - 2017-01-18

- Support security annotations for forms that dont need anti-CSRF tokens.

## 14 - 2016-10-24

- Issue 2576: CSRFCountermeasures, remove unneeded Attack and Evidence messages.
- Issue 2574: CookieLooselyScopedScanner, remove attack field and update description.
- Support ignoring specified forms when checking for CSRF vulnerabilities.
- Correct the plugin ID of Absence of Anti-CSRF Tokens from 40014 to 10202.
- Issue 2860: Add further reference links.

## 13 - 2016-06-02

- Issue 1966: Charset Mismatch passive scanner now handles HTML5 meta charset, and multiple conditions.
- Issue 316: 'Information Disclosure - Debug Error' added mysql and ASP.Net messages.
- Issue 823: i18n (internationalise) beta passive scan rules.
- Issue 2230: Weak Auth Passive Scanner - Evidence vs Attack.
- Add CWE and WASC IDs to passive scanners which may have been lacking those details.
- Create help for scanners which were missing entries.

## 12 - 2015-12-04

- Change (duplicated) scanner ID of Weak Authentication Method, now it's 10105.

## 11 - 2015-09-07

- Minor code changes.

## 10 - 2015-04-13

- Updated for ZAP 2.4

## 9 - 2014-04-10

- Fixed the plug-in ID of Viewstate scanner.
- Changed help file structure to support internationalisation (Issue 981).
- Added content-type to help pages (Issue 1080).
- Changed all plug-ins to expose its IDs (Issue 1101).
- Updated add-on dir structure (Issue 1113).

## 7 - 2013-12-16

- Restored the name of "Loosely Scoped Cookie" alert/scanner (Issue 850).
- Restored the name of "Charset Mismatch" alert/scanner (Issue 851).
- Cope with ZAP running from dir other than the one its installed in (Issue 933)

## 6 - 2013-09-11

- Updated to be compatible with 2.2.0

## 3 - 2013-05-27

- Added new passive scanners: "CharsetMismatchScanner" and "CookieLooselyScopedScanner";
- Updated language files;
- Updated for ZAP 2.1.0.

## 2 - 2013-01-17

- Updated to support new addon format

[37]: https://github.com/zaproxy/zap-extensions/releases/pscanrulesBeta-v37
[36]: https://github.com/zaproxy/zap-extensions/releases/pscanrulesBeta-v36
[35]: https://github.com/zaproxy/zap-extensions/releases/pscanrulesBeta-v35
[34]: https://github.com/zaproxy/zap-extensions/releases/pscanrulesBeta-v34
[33]: https://github.com/zaproxy/zap-extensions/releases/pscanrulesBeta-v33
[32]: https://github.com/zaproxy/zap-extensions/releases/pscanrulesBeta-v32
[31]: https://github.com/zaproxy/zap-extensions/releases/pscanrulesBeta-v31
[30]: https://github.com/zaproxy/zap-extensions/releases/pscanrulesBeta-v30
[29]: https://github.com/zaproxy/zap-extensions/releases/pscanrulesBeta-v29
[28]: https://github.com/zaproxy/zap-extensions/releases/pscanrulesBeta-v28
[27]: https://github.com/zaproxy/zap-extensions/releases/pscanrulesBeta-v27
[26]: https://github.com/zaproxy/zap-extensions/releases/pscanrulesBeta-v26
[25]: https://github.com/zaproxy/zap-extensions/releases/pscanrulesBeta-v25
[24]: https://github.com/zaproxy/zap-extensions/releases/pscanrulesBeta-v24
[23]: https://github.com/zaproxy/zap-extensions/releases/pscanrulesBeta-v23
[22]: https://github.com/zaproxy/zap-extensions/releases/pscanrulesBeta-v22
[21]: https://github.com/zaproxy/zap-extensions/releases/pscanrulesBeta-v21
[20]: https://github.com/zaproxy/zap-extensions/releases/pscanrulesBeta-v20
[19]: https://github.com/zaproxy/zap-extensions/releases/pscanrulesBeta-v19
