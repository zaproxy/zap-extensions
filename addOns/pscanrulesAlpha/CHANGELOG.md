# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased

- PiiScanner add word boundary checks to reduce false positives.
- HashDisclosureScanner prevent false positives on obvious jsessionid values (Issue 5215).
- Remove Cookie Same Site Scanner (promoted to beta Issue 4464).
- Remove Cross Domain Misconfiguration Scanner (promoted to beta Issue 4465).
- Remove Timestamp Scanner (promoted to beta Issue 4466).
- Remove Username IDOR Scanner (promoted to beta Issue 4467).
- Remove X AspNet Version Scanner (promoted to beta Issue 4468).
- Remove X Debug Token Scanner (promoted to beta Issue 4469).
- Remove X PoweredBy Scanner (promoted to beta Issue 4470).

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
- Addressed issue 1262 (Risk & Reliability for 'User controllable HTML element attribute (potential XSS)' and 'Timestamp Disclosure')
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

