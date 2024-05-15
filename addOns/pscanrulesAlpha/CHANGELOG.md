# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased
### Changed
- Update minimum ZAP version to 2.15.0.

## [42] - 2024-01-16
### Changed
- Update minimum ZAP version to 2.14.0.
### Added
- Website alert links (Issue 8189).
- Full Path Disclosure vulnerability passive scanner (Issue 413).

## [41] - 2023-09-08
### Changed
- Maintenance changes.
- Use HTTPS and resolve redirections in the alert references.
- The alerts ASP.NET ViewState Disclosure and ASP.NET ViewState Integrity no longer have the evidence duplicated in the Other Info field.
- Depend on newer version of Common Library add-on.
- Use vulnerability data directly from Common Library add-on.

## [40] - 2023-07-20
### Added
- Fetch Metadata Request Headers scan rule (Issue 6955).

### Changed
- Update minimum ZAP version to 2.13.0.

### Removed
- The following scan rules were removed, having been promoted to Beta:
  - Insufficient Site Isolation Against Spectre Vulnerability
  - Source Code Disclosure

## [39] - 2023-05-03
### Added
- Base64, Example, Site Isolation, and Source Code Disclosure scan rules now all provide example alerts for documentation purposes. 
As well as Alert Refs where applicable (Issues 6119 & 7100).

## [38] - 2023-03-03
### Fixed
- Use case insensitive HTTP field name check in Insufficient Site Isolation Against Spectre Vulnerability scan rule.

### Changed
- Maintenance changes.

## [37] - 2022-10-27
### Changed
- Update minimum ZAP version to 2.12.0.

### Removed
- The following scan rules were removed, having been promoted to Beta:
  - Content Cacheable
  - In Page Banner Info Leak
  - JS Function
  - JSO
  - Permissions Policy
  - Sub Resource Integrity Attribute

## [36] - 2022-09-16
### Changed
- Update minimum ZAP version to 2.11.1.
- Maintenance changes.
- Sub Resource Integrity Attribute Missing scan rule now supports Trusted Domains.
- The Base64 Disclosure scan rule will now ignore headers which are known to contain irrelevant Base64 like strings or are covered by other rules (ETag, Authorization, X-ChromeLogger-Data, X-ChromePhp-Data) (Issue 6619).
- Added new Custom Payloads alert tag to the example alerts of the Dangerous JS Function scan rule.
- Permissions Policy scan rule updated for consistency and documentation purposes (Issue 7458).

### Fixed
- False positive condition from Sub Resource Integrity Attribute Missing scan rule when rel=canonical is used (Issue 7040).
- Threading issue in Dangerous JS Functions rule - only reproducible with currently unreleased core changes.

## [35] - 2021-12-01
### Changed
- Maintenance changes.

### Added
- OWASP Web Security Testing Guide v4.2 mappings where applicable.
- Sub Resource Integrity Attribute Missing scan rule will now include the suggested integrity hash (Base64 encoded SHA384 hash) as part of the relevant Alert's Other Info details if the referenced script can be found in the Sites Tree (Issue 5894).

## [34] - 2021-10-07
### Added
- OWASP Top Ten 2021/2017 mappings.

### Changed
- Ignore CSS, JavaScript, images, or font files when scanning for source code disclosures (Issues: 6595, 6795, & 6820).
- Update minimum ZAP version to 2.11.0.

## [33] - 2021-07-07
### Fixed
- Correct dependency declaration on Common Library add-on (Issue 6674).

## [32] - 2021-07-06
### Changed
- Maintenance changes.

### Fixed
- Correct dependency requirements.

## [31] - 2021-06-17
### Changed
- Now using 2.10 logging infrastructure (Log4j 2.x).
- Discontinued use of CWE-16 and switched to more specific weaknesses in the following scan rules:
  - Feature Policy
  - Site Isolation
  - Sub Resource Integrity
- Maintenance changes.
- Rename of Feature-Policy header to Permissions-Policy to follow spec change.
- Update links to repository.

### Fixed
- Dangerous JS Function scan rule, use word boundaries to reduce false positives (Issue 6594).

## [30] - 2021-02-08

### Changed
- Now targeting ZAP 2.10.
- The In Page Banner Information Leak scan rule and Site Isolation scan rule now support Custom Page definitions.
- Update links to zaproxy repo.

## [29] - 2020-11-16

### Added
 - Add rule for Site Isolation (CORP/COEP/COOP).

### Changed
- Maintenance changes.

## [28] - 2020-08-13
### Changed
- Maintenance changes.

### Fixed
- Fixed bug where Sub Resource Integrity Attribute Missing scan rule alerts even when HTML asset is inline (Issue 6047).

## [27] - 2020-06-01
### Added
- Added links to the code in the help.
- Add info and repo URLs.
- Add JS Function Scanner

### Changed
- Update minimum ZAP version to 2.9.0.
- Update ZAP blog links.
- Updated owasp.org references (Issue 5962).

### Fixed
- Fixed NullPointerException in Sub Resource Integrity Attribute Missing scan rule (Issue 5789).
- Minor spacing issue in help content.
- Base64 Disclosure do not keep looping after identifying a disclosure (Issue 5856), unless the Threshold is set to Low.

### Removed
- 'Insecure Component' was deprecated and removed (Issue 5788).
- 'Modern Web Application' scan rule was removed in being promoted to Beta.

## [26] - 2019-12-16

### Added
- Add Java Serialized Object (JSO) Scanner.
- Add Sub Resource Integrity Attribute Missing Scanner.

### Changed
- Fixed false positive when redirect destination is the same domain (Issue 5289).
- CSP Missing and Feature Policy scan rule: Ignore missing headers on redirects unless Low threshold used.

### Removed
- The following scan rules were removed in being promoted to Beta:
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

## [25] - 2019-07-11

- Added Modern App Detection Scanner

## [24] - 2019-06-07

- PiiScanner add word boundary checks to reduce false positives.
- HashDisclosureScanner prevent false positives on obvious jsessionid values (Issue 5215).
- Remove Cookie Same Site Scanner (promoted to beta Issue 4464).
- Remove Cross Domain Misconfiguration Scanner (promoted to beta Issue 4465).
- Remove Timestamp Scanner (promoted to beta Issue 4466).
- Remove Username IDOR Scanner (promoted to beta Issue 4467).
- Remove X AspNet Version Scanner (promoted to beta Issue 4468).
- Remove X Debug Token Scanner (promoted to beta Issue 4469).
- Remove X PoweredBy Scanner (promoted to beta Issue 4470).
- Add scanner for missing Feature Policy header.
- Report source code disclosure alerts at Medium instead of High 

## 23 - 2019-02-08

- Fix a stack overflow with PII Scanner.
- Fix a DateParseException in Cacheable Scanner (Issue 4969).
- Fix Open Redirect (10028) "Attack" should be Desc.
- Fix false positive due to RxJS Observable method being mistaken for ASP source disclosure.
- Tweak User Controllable Charset and Cookie Poisoning to use Description/Other Info field instead of Attack (Issue 5149).
- Only report missing STS header on redirects to HTTPS URLs on the same domain at Low threshold.
- Hash Disclosure (10097): Add threshold filtering and fix hash confidence levels.

## 22 - 2018-08-15

- Help documentation improvements and cleanup.
- Prevent User Controlled HTML Attribute scanner from sometimes raising duplicate alerts.
- User Controlled HTML Attribute scanner now properly reports the parameter name in alerts.
- Add In Page Banner Info Leak scanner (Issue 178).
- CacheableScanner: Handle max-age with comma but no space in directive (Issue 4924).
- Make the title for the "Reverse Tabnabbing" alert titlecaps.

## 21 - 2018-02-27

- Renamed blank link target to reverse tabnabbing scanner and fixed implementation.
- Remove Image Location Scanner, it's been separated into it's own addon and promoted to beta.

## 20 - 2018-02-19

- Change Image Location and Privacy Scanner to escape HTML inside of embedded image comments.
- Bump jar version of Image Location and Privacy Scanner dependancy xmpcore.
- Update Image Location and Privacy Scanner to version 1.0.
- Fix exception in blank link target scanner.
- Fix exception in Username Hash Found scanner.

## 19 - 2018-02-13

- Minor code changes to comply with deprecations.
- Added passive PII Scanner (which currently looks for Credit Card # patterns).
- Change Image Location and Privacy Scanner to scan hidden images.
- Added blank link target scanner.

## 18 - 2017-11-24

- Correct typo in XCOLD alert description (Issue 3997).
- Do not set a value in the attack fields.
- Do not rely on system's charset to create request/response bodies.

## 17 - 2017-11-06

- Code changes for Java 9 (Issue 2602).
- Bug fix - Added Strict-Transport-Security to the ignored header on Timestamp Disclosure scanner.
- Add X-AspNet-Version Header scanner - detecting information disclosure via HTTP headers.

## 16 - 2017-10-05

- HTTP "Server" response header, report any "Server" header if Threshold is LOW.
- Update Image Location Scanner (passive rule) to leverage 0.4 of the code and 2.10.1 of the library it depends on.

## 15 - 2017-07-07

- Added scanner that looks for simple hashes of usernames based on context user configuration details.

## 14 - 2017-05-25

- Report missing CSP header as LOW even if CSP Report header present.
- Added X-Debug-Token Scanner (Issue 2452).

## 13 - 2017-01-18

- Issue 3148: Only report HSTS on plain HTTP issue at Low threshold.

## 12 - 2016-10-24

- Refactoring the x-powered-by scanner to raise one alert if it finds repetitive headers.
- Update the CSP scanner to handle the Content-Security-Policy-Report-Only header.

## 11 - 2016-07-28

- Issue 2538: Strict-Transport-Security Header Scanner additional variants.
- Issue 2716: Implement a passive check for cookies without SameSite set.

## 10 - 2016-06-22

- XPoweredByHeaderInfoLeakScanner modify evidence (Issue 2575)
- ContentSecurityPolicyMissingScanner to only check for older CSP headers at Low threshold
- CacheableScanner: Add other information in attack and remove evidence (Issue 2573)

## 9 - 2016-06-02

- Add CWE and WASC IDs to passive scanners which may have been lacking those details.
- Fix exception when scanning with "User Controllable Charset" scanner.
- Fix exception when scanning with "Image Location Scanner" scanner.
- Strict-Transport-Security Header Scanner added support for max-age=0 per rfc6797.

## 8 - 2016-01-04

- Add passive scanner to identify info leaks via X-ChromeLogger-Data or X-ChromePhp-Data.

## 7 - 2015-12-04

- ImageLocationScanner detects more GPS tag varieties, scans png & tiff files, adds i18n.
- Fix exception when scanning with "Base64 Disclosure" (Issue 2037).

## 6 - 2015-09-07

- Minor code changes.

## 5 - 2015-04-13

- Tweaked "Source Code Disclosure" scanner to reduce false positives
- Added "Insecure Component" scanner
- Addressed issue 1262 (Risk & Confidence for 'User controllable HTML element attribute (potential XSS)' and 'Timestamp Disclosure')
- Add Big Redirect scanner (Issue 1257)
- Fixed an issue in detecting SHA-512 Crypt hashes, and other hashes beginning with "$"
- Detect Node.js source code
- Report Apache vulnerabilities on Red Hat and CentOS as False Positives
- Detect Directory Browsing / Listings on Microsoft IIS
- Added Cacheable Content scanner
- Added Retrieved From Cache scanner
- Updated Insecure Component scanner to support Squid
- Added Image Location Scanner passive scanner
- Updated Insecure Component scanner vulnerability database for all products
- Updated for ZAP 2.4

## 4 - 2014-06-14

- Added various checks per Issue 1169;
- Added "Heartbleed OpenSSL Vulnerability (Indicative)" scanner;
- Added "Directory Browsing" scanner;
- Added "Cross-Domain Misconfiguration" scanner;
- Improved "Source Code Disclosure" scanner;
- Improved "Base64 Disclosure" scanner;
- Improved "Hash Disclosure" scanner;
- Fixed duplicated plug-in IDs.

## 3 - 2014-04-03

- Changed help file structure to support internationalisation (Issue 981).
- Changed passive scanners to expose its IDs (Issue Issue 1101).
- Updated add-on dir structure (Issue 1113).
- Added example rules.

## 2 - 2013-09-11

- Updated for ZAP 2.2.0

## 1 - 2013-03-26

- v.1
- Added an alpha version of User Controlled Open Redirect passive rule ported from
- Watcher rule https://websecuritytool.codeplex.com/wikipage?title=Checks#user-controlled-redirect
- v.2
- Added an alpha version of User Controlled Cookie passive rule ported from
- Watcher rule https://websecuritytool.codeplex.com/wikipage?title=Checks#user-controlled-cookie
- Added an alpha version of User Controlled Charset passive rule ported from
- Watcher rule https://websecuritytool.codeplex.com/wikipage?title=Checks#user-controlled-charset
- v.3
- Updated User Controlled Open Redirect, Cookie and Charset rules after testing with
- http://www.testcases.org/watcher/ test pages.

[42]: https://github.com/zaproxy/zap-extensions/releases/pscanrulesAlpha-v42
[41]: https://github.com/zaproxy/zap-extensions/releases/pscanrulesAlpha-v41
[40]: https://github.com/zaproxy/zap-extensions/releases/pscanrulesAlpha-v40
[39]: https://github.com/zaproxy/zap-extensions/releases/pscanrulesAlpha-v39
[38]: https://github.com/zaproxy/zap-extensions/releases/pscanrulesAlpha-v38
[37]: https://github.com/zaproxy/zap-extensions/releases/pscanrulesAlpha-v37
[36]: https://github.com/zaproxy/zap-extensions/releases/pscanrulesAlpha-v36
[35]: https://github.com/zaproxy/zap-extensions/releases/pscanrulesAlpha-v35
[34]: https://github.com/zaproxy/zap-extensions/releases/pscanrulesAlpha-v34
[33]: https://github.com/zaproxy/zap-extensions/releases/pscanrulesAlpha-v33
[32]: https://github.com/zaproxy/zap-extensions/releases/pscanrulesAlpha-v32
[31]: https://github.com/zaproxy/zap-extensions/releases/pscanrulesAlpha-v31
[30]: https://github.com/zaproxy/zap-extensions/releases/pscanrulesAlpha-v30
[29]: https://github.com/zaproxy/zap-extensions/releases/pscanrulesAlpha-v29
[28]: https://github.com/zaproxy/zap-extensions/releases/pscanrulesAlpha-v28
[27]: https://github.com/zaproxy/zap-extensions/releases/pscanrulesAlpha-v27
[26]: https://github.com/zaproxy/zap-extensions/releases/pscanrulesAlpha-v26
[25]: https://github.com/zaproxy/zap-extensions/releases/pscanrulesAlpha-v25
[24]: https://github.com/zaproxy/zap-extensions/releases/pscanrulesAlpha-v24
