# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased
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
- Correct handling of messages with emtpy path.
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
- Implemented Internazionalization for ELInjection
- Added ExampleSimpleActiveScanner

## 2 - 2013-09-11

- Updated for ZAP 2.2.0

## 1 - 2013-05-07

- First version, including persistent XSS tests

[29]: https://github.com/zaproxy/zap-extensions/releases/ascanrulesAlpha-v29
[28]: https://github.com/zaproxy/zap-extensions/releases/ascanrulesAlpha-v28
[27]: https://github.com/zaproxy/zap-extensions/releases/ascanrulesAlpha-v27
[26]: https://github.com/zaproxy/zap-extensions/releases/ascanrulesAlpha-v26
[25]: https://github.com/zaproxy/zap-extensions/releases/ascanrulesAlpha-v25
[24]: https://github.com/zaproxy/zap-extensions/releases/ascanrulesAlpha-v24
