# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased
### Changed
- Update minimum ZAP version to 2.15.0.

## [47] - 2024-03-28
### Changed
- References for the LDAP Injection scan rule's Alerts were updated (Issue 8262).

## [46] - 2024-01-26
### Changed
- Move MongoDB time based tests to its own scan rule, NoSQL Injection - MongoDB (Time Based) with ID 90039 (Issue 7341).
- Depend on newer version of Common Library add-on.

## [45] - 2024-01-16
### Changed
- Update minimum ZAP version to 2.14.0.
- Depend on newer version of Common Library add-on.
- Add website alert links to the help page (Issue 8189).

### Fixed
- Fix time-based false positives in NoSQL Injection - MongoDB scan rule.

## [44] - 2023-09-08
### Changed
- Maintenance changes.
- Remove the dependency on OAST add-on, no longer required.
- Depend on newer version of Common Library add-on.
- Use vulnerability data directly from Common Library add-on.

## [43] - 2023-07-20
### Changed
- Update minimum ZAP version to 2.13.0.
- Maintenance changes.

### Removed
- The following scan rules were removed, having been promoted to Beta:
  - Server Side Request Forgery
  - Text4shell (CVE-2022-42889)

## [42] - 2022-12-13
### Added
- LDAP protocol technology support.

### Fixed
- Preserve the HTTP version in Web Cache Deception scan rule.

### Added
- Server Side Request Forgery Scan Rule.

## [41] - 2022-10-27
### Changed
- Update minimum ZAP version to 2.12.0.
- The Text4shell scan rule now includes an alert tag for its CVE reference.

## [40] - 2022-10-19
### Added
- Text4shell (CVE-2022-42889) Scan Rule.

### Fixed
- Fix an exception in Bypassing 403 scan rule when creating example alerts.

### Changed
- Maintenance changes.

### Removed
- The following scan rules were removed, having been promoted to Beta:
    - CORS
    - Exponential Entity Expansion
    - Forbidden Bypass
    - Log4Shell
    - Out-of-Band XSS
    - Spring4Shell
    - Spring Actuator
    - Blind SSTI
    - SSTI

## [39] - 2022-09-22
### Changed
- Maintenance changes.
- Forbidden Bypass scan rule will now also try a bypass based on the use of a tab character.

### Fixed
- Fix an exception in Spring Actuator Information Leak scan rule when scanning responses without Content-Type header.
- Correct path composition in Web Cache Deception scan rule.

## [38] - 2022-04-08
### Added
- Scan rules for Server Side Template Injection ([Issue 2332](https://github.com/zaproxy/zaproxy/issues/2332)).

## [37] - 2022-04-04
### Added
- Spring4Shell (CVE-2022-22965) Scan Rule.

### Changed
- The Web Cache Deception scan rule now uses a comparison mechanism which should be more performant, and will no longer scan messages which had an error response to start with (Issue 6655).

## [36] - 2022-02-15
### Added
- Out-of-band XSS Scan Rule.
- Exponential Entity Expansion (Billion Laughs Attack) Scan Rule.

### Changed
- Improved performance of a Web Cache Deception scan rule (Issue 6655).

## [35] - 2022-01-07
### Fixed
- Log4Shell: Fixed the RMI Payloads (Issue 7002).
- Log4Shell: Continue with further payloads if one payload throws an error

### Changed
- Log4Shell: Added detection for CVE-2021-45046

## [34] - 2021-12-12
### Added
- Log4Shell (CVE-2021-44228) Scan Rule.

### Changed
- Update minimum ZAP version to 2.11.1.
- Depend on the OAST add-on.

## [33] - 2021-12-06
### Changed
- Fixed typo in payload in Forbidden (403) Bypass scan rule.

### Added
- OWASP Web Security Testing Guide v4.2 mappings where applicable.

## [32] - 2021-10-07
### Added
- Spring Boot Actuator Scan Rule.
- OWASP Top Ten 2021/2017 mappings.

### Changed
- Maintenance changes.
- Update minimum ZAP version to 2.11.0.

## [31] - 2021-06-17
### Changed
- Update links to zaproxy and zap-extensions repos.
- Target 2.10 core and use new logging infrastructure (Log4j 2.x).
- The LDAP Injection scan rule was modified to use:
  - The Dice algorithm for calculating the match percentage, thus improving its performance.
  - The URI in encoded form in alerts' other info field.
- Maintenance changes.

### Added
- CORS active scan rule.
- Forbidden (403) Bypass scan rule.
- Web Cache Deception scan rule.

### Removed
- Unused file, it was used by promoted scan rule.

### Fixed
- Correct Context check in NoSQL Injection - MongoDB scan rule.

## [30] - 2020-11-26
### Changed
- 'Hidden File Finder' ensure that test requests are appropriately rebuilt for this scan rule (Issue 6129).
- Maintenance changes.

### Fixed
 - Terminology.
 - SocketTimeoutException in the LDAP Injection scan rule.

### Removed
- The following scan rules were removed and promoted to Beta: Cloud Meta Data, .env File, Hidden Files, XSLT Injection (Issue 6211).

## [29] - 2020-08-13
### Changed
- Maintenance changes.
- 'Hidden File Finder' will raise fewer alerts at Thresholds other than High (Issue 6116).

### Fixed
- Fixed Mongo DB Injection false positive (Issue 6025).

### Added
- 'Hidden File Finder' added more patterns.

## [28] - 2020-06-01
### Added
- Add repo URL.
- Add links to the code in the help.
- Add scan rule for MongoDB (Issue 3480).
- 'Hidden File Finder' add pattern for vim_settings.xml (CVE-2019-14957).

### Changed
- Update minimum ZAP version to 2.9.0.
- Change info URL to link to the site.
- Update ZAP blog links.
- Updated owasp.org references (Issue 5962).

### Fixed
- Fix exception when scanning a message without path with Hidden File Finder.

## [27] - 2019-12-16

### Added
- Added Hidden Files Finder (issue 4585) largely based on Snallygaster by Hanno Böck, also supports use of the Custom Payloads addon.

### Removed
- The following scan rules were removed in being promoted from Alpha to Beta:
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

## [26] - 2019-10-31

### Added
- Add dependency on Custom Payloads add-on. The payloads of the Test User Agent scanner are now customizable.
- Added XSLT Injection Scanner (issue 3572).

### Changed
- Update minimum ZAP version to 2.8.0.

## [25] - 2019-07-11

### Fixed
- Fix FP in Cloud Metadata rule where no content returned.
- Fix FP in Ht Access Scanner where HTML, XML, JSON or empty response is returned (Issue 5433).

## [24] - 2019-06-07

### Fixed
- Fix typo in request header used by Apache Range Header DoS.

## 23 - 2019-02-06

- Update minimum ZAP version to 2.6.0.
- Added Cloud Metadata Scanner

## 22 - 2018-09-27

- Update minimum ZAP version to 2.5.0.
- Maintenance changes.
- Add active scan rule for .env files.

## 21 - 2018-03-20

- Add .htaccess scanner (Issue 3972).
- Modified trace.axd scanner to leverage new AbstractAppFilePlugin component.
- Remove unnecessary help entry.
- Sorted help content alphabetically, adjusted names to match scan rules, and added missing entries.

## 20 - 2017-11-24

- Code changes for Java 9 (Issue 2602).
- Correct handling of messages with empty path.
- Add Get for Post Scanner.

## 19 - 2017-05-25

- Improve error handling in some scanners.
- Add MsSQL specific Injection scanner.
- Issue 3441: Add proper reference links to Proxy Discovery scanner.
- Issue 3279: Add ELMAH scanner.
- Issue 3280: Add trace.axd scanner.

## 18 - 2016-10-24

- Added Apache Range Header DoS (CVE-2011-3192) scanner.
- Fix exception when raising a "Source Code Disclosure - File Inclusion" alert.
- Adjust log levels of some scanners, from INFO to DEBUG.

## 17 - 2016-07-21

- Added Httpoxy scanner.

## 16 - 2016-06-02

- Deleted Integer Overflow scanner.
- Issue 823: i18n (internationalise) alpha rules.
- Add CWE and WASC IDs to active scanners which may have been lacking those details.
- Issue 2207: Added Http Only Site Active scan rule.

## 15 - 2015-12-04

- Update add-on's info URL.
- Added Integer Overflow scanner.
- Added new scanner User Agent Fuzzer. The scanner checks for differences in response based on fuzzed User Agent.
- Slightly improve performance of "Source Code Disclosure - File Inclusion".
- Demoted LDAP rule due to performance issues

## 14 - 2015-09-07

- Deleted Format String.

## 13 - 2015-08-24

- Updated add-on's info URL.
- Minor code changes.
- Added a new scanner to search for format string errors in compiled code.
- Change scanners to honour the technologies enabled (1618).

## 12 - 2015-04-13

- Added "Relative Path Confusion" scanner
- Added "Proxy Disclosure" scanner
- Updated for ZAP 2.4

## 11 - 2014-10-20

- Promoted Backup File Disclosure to beta
- Promoted Cross Domain Scanner to beta
- Promoted HeartBleed to beta
- Promoted Insecure HTTP Method to beta
- Promoted Remote Code Execution - CVE2012-1823 to beta
- Promoted Shell shock to beta
- Promoted Source Code Disclosure - CVE2012-1823 to beta
- Promoted Source Code Disclosure - SVN to beta
- Promoted Source Code Disclosure - WEB-INF to beta

## 10 - 2014-09-29

- Improved "Shell Shock" scanner to also detect the vulnerability in PHP scripts.

## 9 - 2014-09-26

- Added "HTTPS Content Available via HTTP" scanner. (Issue 1295)
- Added "SQLite" SQL Injection scanner. (Issue 734).
- Added "ShellShock" scanner. (Issue 1347)
- Only show example alerts in dev mode (Issue 1349)

## 8 - 2014-07-24

- Added "Cookie Slack Detector" scanner.
- Added "Insecure HTTP Method" scanner.
- Added "Source Code Disclosure - WEB-INF folder" scanner.
- Added "Source Code Disclosure - CVE-2012-1823.
- Added "Remote Code Execution - CVE-2012-1823.
- Updated Source Code Disclosure - Git" scanner to not scan 404 URLs unless Attack Strength = High or Insane.
- Updated Source Code Disclosure - SVN" scanner to not scan 404 URLs unless Attack Strength = High or Insane.
- Updated Source Code Disclosure - CVE-2012-1823" scanner to not scan 404 URLs unless Attack Strength = High or Insane.

## 7 - 2014-06-14

- Added a Example File scanner;
- Added "Cross-Domain Misconfiguration" scanner.

## 6 - 2014-04-15

- Added a Heartbleed scanner

## 5 - 2014-04-03

- Promoted to beta XXE and Padding Oracle Plugins
- Added a new Expression Language Plugin
- Implemented Internationalization for ELInjection
- Added ExampleSimpleActiveScanner

## 2 - 2013-09-11

- Updated for ZAP 2.2.0

## 1 - 2013-05-07

- First version, including persistent XSS tests

[47]: https://github.com/zaproxy/zap-extensions/releases/ascanrulesAlpha-v47
[46]: https://github.com/zaproxy/zap-extensions/releases/ascanrulesAlpha-v46
[45]: https://github.com/zaproxy/zap-extensions/releases/ascanrulesAlpha-v45
[44]: https://github.com/zaproxy/zap-extensions/releases/ascanrulesAlpha-v44
[43]: https://github.com/zaproxy/zap-extensions/releases/ascanrulesAlpha-v43
[42]: https://github.com/zaproxy/zap-extensions/releases/ascanrulesAlpha-v42
[41]: https://github.com/zaproxy/zap-extensions/releases/ascanrulesAlpha-v41
[40]: https://github.com/zaproxy/zap-extensions/releases/ascanrulesAlpha-v40
[39]: https://github.com/zaproxy/zap-extensions/releases/ascanrulesAlpha-v39
[38]: https://github.com/zaproxy/zap-extensions/releases/ascanrulesAlpha-v38
[37]: https://github.com/zaproxy/zap-extensions/releases/ascanrulesAlpha-v37
[36]: https://github.com/zaproxy/zap-extensions/releases/ascanrulesAlpha-v36
[35]: https://github.com/zaproxy/zap-extensions/releases/ascanrulesAlpha-v35
[34]: https://github.com/zaproxy/zap-extensions/releases/ascanrulesAlpha-v34
[33]: https://github.com/zaproxy/zap-extensions/releases/ascanrulesAlpha-v33
[32]: https://github.com/zaproxy/zap-extensions/releases/ascanrulesAlpha-v32
[31]: https://github.com/zaproxy/zap-extensions/releases/ascanrulesAlpha-v31
[30]: https://github.com/zaproxy/zap-extensions/releases/ascanrulesAlpha-v30
[29]: https://github.com/zaproxy/zap-extensions/releases/ascanrulesAlpha-v29
[28]: https://github.com/zaproxy/zap-extensions/releases/ascanrulesAlpha-v28
[27]: https://github.com/zaproxy/zap-extensions/releases/ascanrulesAlpha-v27
[26]: https://github.com/zaproxy/zap-extensions/releases/ascanrulesAlpha-v26
[25]: https://github.com/zaproxy/zap-extensions/releases/ascanrulesAlpha-v25
[24]: https://github.com/zaproxy/zap-extensions/releases/ascanrulesAlpha-v24
