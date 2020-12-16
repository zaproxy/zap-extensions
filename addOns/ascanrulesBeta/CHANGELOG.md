# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased


## [33] - 2020-12-15
### Changed
- Now targeting ZAP 2.10.
- The following scan rules now support Custom Page definitions:
  - Hidden Files
  - HTTPS as HTTP
  - Insecure HTTP Methods
  - Integer Overflow
  - Padding Oracle
  - Remove Code Execution CVE-2012-1823
  - Session Fixation
  - Source Code Disclosure CVE-2012-1823
  - Source Code Disclosure Git
  - Source Code Disclosure SVN

## [32] - 2020-11-26
### Changed
- XML External Entity Attack scan rule changed to parse response body irrespective of the HTTP response status code. (Issue 6203)
- XML External Entity Attack scan rule changed to skip only Remote File Inclusion Attack when Callback extension is not available.
- Maintenance changes.
- The Relative Path Confusion scan rule no longer treats 'href="#"' as a problematic use.

### Fixed
 - Terminology.
 - Correct reason shown when the XML External Entity Attack scan rule is skipped.
 - SocketTimeoutException in the Proxy Disclosure scan rule.

### Added
- The following scan rules were promoted to Beta: Cloud Meta Data, .env File, Hidden Files, XSLT Injection (Issue 6211).

### Removed
- The following scan rules were removed and promoted to Release: ELMAH Information Leak, .htaccess Information Leak (Issue 6211).

## [31] - 2020-09-02
### Changed
- ELMAH Information Leak ensure that test requests are appropriately rebuilt for this scan rule (Issue 6129).
- SQL rules changed to double check timing attacks
- Significantly reduced the number of attacks made by the SQLite rule

## [30] - 2020-07-23
### Changed
- Anti-CSRF Tokens Check address potential false positives by only analyzing HTML responses (Issue 6089).

## [29] - 2020-07-22
### Changed
- Maintenance Changes.
- Backup File Disclosure: don't raise issues for non-success codes unless at LOW threshold (Issue 6059).
- ELMAH Information Leak: don't raise issues unless content looks good unless at LOW threshold (Issue 6076).
- Session Fixation scan rule fix potential false positive on session cookie HttpOnly, and Secure flags (Issue 6082).

## [28] - 2020-06-01
### Added
- Add info and repo URLs.
- Add links to the code in the help.

### Changed
- Update minimum ZAP version to 2.9.0.
- Backup File Disclosure scan rule - updated CWE to 530, added reference links to alerts, made sure WASC and CWE identifiers are included in alerts.
- Maintenance changes.
- Updated owasp.org references (Issue 5962).

### Fixed
- Use correct risk (`INFO`) in User Agent Fuzzer, to run later in the scan.

## [27] - 2019-12-16

### Added
- The following scan rules were promoted from Alpha to Beta:
  - Apache Range Header DoS
  - Cookie Slack Detector
  - ELMAH Information Leak
  - GET for POST
  - .htaccess Information Leak
  - HTTP Only Site
  - Httpoxy - Proxy Header Misuse
  - HTTPS Content Available via HTTP
  - Proxy Disclosure
  - Relative Path Confusion
  - Source Code Disclosure - File Inclusion
  - Source Code Disclosure - Git
  - SQL Injection - MsSQL
  - SQL Injection - SQLite
  - Trace.axd Information Leak
  - User Agent Fuzzer

### Changed
- Add dependency on Custom Payloads add-on.
- Fixed ArrayIndexOutOfBoundsException issue in XML External Entity Attack scan rule.
  - Now removes original XML header in "Local File Reflection Attack".
- Maintenance changes.
- Update minimum ZAP version to 2.8.0.
- Elmah scan rule updated to include a response content check, and vary alert confidence values accordingly.

## [26] - 2019-07-11

- Fix FP in "Source Code Disclosure SVN" where the contents exactly matches, and only report issues with less evidence at a LOW threshold.
- Fix NPE in "Session Fixation" scan rule when the path of the request URI is null.
- Changed "Source Code Disclosure CVE20121823" to only analyze JS responses when a LOW alert threshold is used.

## [25] - 2019-06-07

- Correct HTTP message usage in Insecure HTTP Method scanner.
- Fix missing resource messages with Cross-Domain Misconfiguration scanner.
- Remove Source Code Disclosure WEB-INF Scanner (promoted to release Issue 4448).
- Report source code disclosure alerts at Medium instead of High 
- Bundle Diff Utils library instead of relying on core.

## 24 - 2018-07-31

- Maintenance changes.
- Issue 1142: Logic and alert risk ratings modified.
- Correct timeout per attack strength in Heartbleed OpenSSL Vulnerability scanner.
- Issue 174: Added further method checks to the Insecure HTTP Methods Scanner.
- Skip "Source Code Disclosure - /WEB-INF folder" on Java 9+ (Issue 4038).
- BackupFileDisclosure - Handle empty "backup" responses.

## 23 - 2018-01-19

- At HIGH threshold only perform CSRF checks for inScope messages (Issue 1354).

## 22 - 2017-11-24

- Fix FP in "Source Code Disclosure - /WEB-INF folder" on successful responses (Issue 3048).
- Fix FP in "Integer Overflow Error" on 500 error responses (Issue 3064).
- Support security annotations for forms that dont need anti-CSRF tokens.
- Changed XXE rule to use new callback extension.
- Notify of messages sent during Heartbleed scanning (Issue 2425).
- Fix false positive in Code Disclosure - CVE-2012-1823 on image content (Issue 3846).
- Fix false positive in Backup File Disclosure scanner on 403 responses (Issue 3911).
- CsrfTokenScan : Keep session cookies instead of deleting all of them

## 21 - 2016-10-24

- Support changing the length of time used in timing attacks via config options.
- Support ignoring specified forms when checking for CSRF vulnerabilities.
- Do not attempt to parse empty cross domain policy files.
- Correct creation of attack URL in Source Code Disclosure - CVE-2012-1823.
- Correct creation of attack URL in Remote Code Execution - CVE-2012-1823.
- Respect OS techs included when scanning with Remote Code Execution - CVE-2012-1823.
- Adjust log levels of some scanners, from INFO to DEBUG.

## 20 - 2016-06-02

- Prevent XXE vulnerability.
- Issue 2174: Adjust logging, catch specific exceptions.
- Issue 2178: SQLInjectionMySQL - adjust logging, catch specific exceptions.
- Issue 2179: SQLInjectionPostgresql - adjust logging, catch specific exceptions.
- Issue 2272: SQLInjectionHypersonic - adjust logging, catch specific exceptions.
- Issue 2177: SourceCodeDisclosureSVN - adjust logging.

## 19 - 2016-02-05

- Adding Integer Overflow Scanner.
- Issue 823: i18n (internationalise) beta active scan rules.
- Issue 1713: Source Code Disclosure SVN Throws False Positive - Fixed.
- Add CWE and WASC IDs to active scanners which may have been lacking those details.
- Create help for scanners which were missing entries.
- Issue 2180: Adjust logging, and implement plugin skip if runtime requirements not met.
- Security fixes, to be detailed later.

## 18 - 2015-12-04

- Removing Format String.
- Fix unloading issue (Issue 1972).
- Slightly improve performance of "LDAP Injection" and "Username Enumeration".
- Demoted LDAP rule due to performance issues

## 17 - 2015-09-07

- Moved Format String scanner from alpha to beta.
- Removing Buffer Overflow.

## 16 - 2015-08-24

- Minor code changes.
- Change scanners to honour the technologies enabled (Issue 1618).
- Added Buffer Overflow scanner to beta (Issue 1605).

## 15 - 2015-04-13

- Solved Comparison operator in XpathInjectionPlugin (Issue 1189).
- Promoted Backup File Disclosure to beta
- Promoted Cross Domain Scanner to beta
- Promoted HeartBleed to beta
- Promoted Insecure HTTP Method to beta
- Promoted Remote Code Execution - CVE2012-1823 to beta
- Promoted Shell shock to beta
- Promoted Source Code Disclosure - CVE2012-1823 to beta
- Promoted Source Code Disclosure - SVN to beta
- Promoted Source Code Disclosure - WEB-INF to beta
- Fixed minor regex escaping issue with Source Code Disclosure - SVN (Issue 1377)
- Updated for ZAP 2.4

## 14 - 2014-10-20

- Solved Comparison operator in XpathInjectionPlugin (Issue 1189).
- Promoted Backup File Disclosure to beta
- Promoted Cross Domain Scanner to beta
- Promoted HeartBleed to beta
- Promoted Insecure HTTP Method to beta
- Promoted Remote Code Execution - CVE2012-1823 to beta
- Promoted Shell shock to beta
- Promoted Source Code Disclosure - CVE2012-1823 to beta
- Promoted Source Code Disclosure - SVN to beta
- Promoted Source Code Disclosure - WEB-INF to beta

## 13 - 2014-04-10

- Promoted new XXE Plugin to test for remotr and local XML External Entity Vulnerability.
- Promoted new PaddingOracle plugin to test for possible encryption padding errors.
- Promoted PXSS tests to beta.
- Promoted Command Injection release.
- Promoted new Expression Language Plugin to test JSP EL Injection.
- Changed help file structure to support internationalisation (Issue 981).
- Added content-type to help pages (Issue 1080).
- Updated add-on dir structure (Issue 1113).

## 12 - 2014-02-15

- Fixed a ClassNotFoundException while installing the add-on.
- Removed the scanner "Server Side Code Injection Plugin" (promoted to "Active scanner rules" add-on).
- Changed the "LDAP Injection" scanner to scan the parameters defined in the "Active Scan" options.
- Updated the "LDAP Injection" scanner to perform logic-based LDAP injection vulnerability detection

## 11 - 2013-10-14

- Corrected IDs to prevent clash

## 10 - 2013-09-27

- Fixed various errors logged

## 9 - 2013-09-11

- Updated to be compatible with 2.2.0

## 5 - 2013-06-18

- Fixed NullPointerExceptions when scanning with "Anti CSRF tokens scanner"

## 4 - 2013-05-13

- Fixed a MissingResourceException when scanning with "Anti CSRF tokens scanner"

## 3 - 2013-01-25

- Moved SQL Injection to release, tweaked SQL timing rules names

## 2 - 2013-01-17

- Updated to support new addon format

[33]: https://github.com/zaproxy/zap-extensions/releases/ascanrulesBeta-v33
[32]: https://github.com/zaproxy/zap-extensions/releases/ascanrulesBeta-v32
[31]: https://github.com/zaproxy/zap-extensions/releases/ascanrulesBeta-v31
[30]: https://github.com/zaproxy/zap-extensions/releases/ascanrulesBeta-v30
[29]: https://github.com/zaproxy/zap-extensions/releases/ascanrulesBeta-v29
[28]: https://github.com/zaproxy/zap-extensions/releases/ascanrulesBeta-v28
[27]: https://github.com/zaproxy/zap-extensions/releases/ascanrulesBeta-v27
[26]: https://github.com/zaproxy/zap-extensions/releases/ascanrulesBeta-v26
[25]: https://github.com/zaproxy/zap-extensions/releases/ascanrulesBeta-v25
