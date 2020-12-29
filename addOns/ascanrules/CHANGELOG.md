# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased
### Changed
- Now using 2.10 logging infrastructure (Log4j 2.x).

## [38] - 2020-12-15
### Changed
- Now targeting ZAP 2.10.
- The following scan rules now support Custom Page definitions:
  - Buffer Overflow
  - Directory Browsing
  - Format String
  - Parameter Tamper
  - Path Traversal
  - Remote File Include
  - Source Code Disclosure WEB-INF

## [37] - 2020-11-26
### Changed
- Maintenance changes.

### Fixed
- Terminology
 
### Added
- The following scan rules were promoted to Beta: ELMAH Information Leak, .htaccess Information Leak (Issue 6211).

## [36] - 2020-08-04
### Changed
- Maintenance changes.

## [35] - 2020-06-01
### Changed
- Update minimum ZAP version to 2.9.0.
- Command Injection, Test Path Traversal, Test Cross Site ScriptV2 and Remote File Include rules are updated to include payloads for Null Byte Injection (Issue 3877).
- Updated owasp.org references (Issue 5962).

### Fixed
- Fix typo in the help page.
- Use correct risk (`HIGH`) in External Redirect, to run earlier in the scan.
- Correct tech check in SQL Injection scan rule, which could cause it to be skipped with imported contexts (Issue 5918).

## [34] - 2020-01-17
### Added
- Add info and repo URLs.
- Add links to the code in the help.

### Changed
- Improved PowerShell injection control patterns to reduce false positives.
- Maintenance changes.
- Issue 5271: Fix SQLi false positive (and potential false negative) when response bodies contain injection strings.

## [33] - 2019-06-07

- Maintenance changes.
- Promote Source Code Disclosure WEB-INF (Issue 4448).
- Bundle Diff Utils library instead of relying on core. 

## 32 - 2018-10-04

- Maintenance changes.
- Persistent XSS scanner updated to address various false negatives (Issue 4692).
- Command Injection plugin updated to include payloads for Uninitialized environment variable WAF bypass (Issue 4968).
- Correct Remote OS Command Injection to use the expected time in all time based payloads.

## 31 - 2018-03-05

- Issue 1852: Fix reflected XSS false negative with poor quality HTML filtering.<br/>
- Issue 1640: Fix reflected XSS false negative with double decoded output.<br/>
- Issue 2290: Fix SQLi false negative with ODBC error message.<br/>

## 30 - 2018-02-06

- Issue 1366: Allow SSI detection patterns to include new lines, and pre-check the original response for detection patterns to reduce false positives.<br/>
- Issue 4168 and 4230: Pre-check the original response for detection patterns.<br/>

## 29 - 2018-01-19

- Issue 3979: Fix reflected XSS in PUT response.
- Issue 3978: Handle relfected XSS in JSON response.
- Issue 4211: Fix false positive in FormatString scanner.

## 28 - 2017-11-27

- Updated for 2.7.0.

## 27 - 2017-11-24

- Issue 1365: Additional Path Traversal detection.
- Correct alert's evidence/attack of Parameter Tampering (Issue 3524).
- Fix Path Traversal false positives when `etc` is a substring (Issue 3735).
- Code changes for Java 9 (Issue 2602).
- TestSQLInjection Modifications to improve handling of injected math expressions and reflected params (Issue 3139).

## 26 - 2017-04-06

- Issue 2973: Drop suffix on *Nix Blind Command Injection time based variants to maximize compatibility.
- Improve error handling in some scanners.
- Support changing the length of time used in timing attacks via config options.
- Issue 3065: Ensure active scanners perform initial status checks against the proper original message(s) to prevent False Negative and False Positive conditions.

## 25 - 2016-09-28

- Issue 1211 - SQLi Scanner may raise seemingly duplicate alerts (fixed).
- Use correct HTTP message and attack for alerts of "Format String Error".
- Fixed test for wrong tag in Reflected XSS rule.
- Issue 1632 - False Negative XSS on injection outside of HTML tags.

## 24 - 2016-07-15

- TestPathTraversal - catch InvalidRedirectLocationException and URIException.
- TestRemoteFileInclude - adjust logging (debug not error).
- Run SQL Injection if any DB tech is enabled but skip specific non-applicable error checks.
- Issue 2624: Improve Error Logging in PathTraversal Plugin.

## 23 - 2016-06-02

- Issue 823 - i18n (internationalise) release active scan rules.
- Issue 2001 - Add PowerShell variants to CommandInjection Plugin.
- Add CWE and WASC IDs to active scanners which may have been lacking those details.
- Add missing skip/stop checks to some scanners (Issue 1734).
- Remote File Include FP if original title includes 'Google' (Issue 2240).
- Issue 2264: TestPathTraversal - adjust logging, catch specific exceptions.
- Issue 2265: TestRemoteFileInclude - adjust logging, catch specific exceptions.
- Issue 2266: TestCrossSiteScriptV2 - adjust logging, catch specific exceptions.
- Issue 2267 & 1860: TestSQLInjection - adjust logging, catch specific exceptions.
- Issue 2268: CodeInjectionPlugin - adjust logging, catch specific exceptions.
- Issue 2269: BufferOverflow - adjust logging, catch specific exceptions.
- Issue 2270: FormatString - adjust logging, catch specific exceptions.
- Issue 2271: TestParameterTamper - adjust logging, catch specific exceptions.
- Issue 1550: CommandInjectionPlugin - adjust logging, catch specific exceptions.

## 21 - 2015-11-19

- Change Path Traversal scanner to also check HTML responses in decoded form.
- Move Format String from Beta to Release.
- Improve memory usage when scanning for persistent XSS vulnerabilities (Issue 1974).
- Fix False Positives in Buffer Overflow.
- Fixed False Positives in Format String.
- Fixed incorrect i18n string being used which caused the External Redirects code to fail.

## 20 - 2015-09-07

- Added Buffer Overflow scanner.

## 19 - 2015-08-24

- Issue 1146: variable 'param' is used instead of 'value'? in TestCrossSiteScriptV2.
- Handle cases where the response is the full XSS payload.

## 18 - 2015-07-30

- Improved "Path Traversal" scanner.
- Change scanners to honour the technologies enabled.

## 17 - 2015-04-13

- Changes to TestInjectionCRLF: address FindBugs issue, remove forced HTML elements in
- references, add proper WASC ID.
- Added blind command injection checks for CommandInjectionPlugin.
- Upgraded to ZAP 2.4.
- Issue 823: i18n active/passive scan rules.
- Issue 1529: TestExternalRedirect minor performance improvement, injection generation changed to reduce collisions or false positives.
- Issue 1569: TestExternalRedirect plugin ID changed from 30000 to 20019.
- Issue 1499: Replace active 'Client Browser Cache' with passive 'Cache Control' rule. TestClientBrowserCache removed.
- Issue 1592: CommandInjectionPlugin timing false positives

## 16 - 2014-07-22

- Fixed bug in Persistent XSS rule (Issue 1273)

## 15 - 2014-05-20

- Tweaked the SQLi rule to maximize vuln detection and minimize fps (Issue 1195)
- Fixed XSS false positive in non URL tag attributes (Issue 964)

## 14 - 2014-04-10

- Fix for TestRemoteFileInclude failing if Google return localized page.
- Moved PXXS tests from beta.
- Moved Command Injection from beta.
- Reviewed and enforced the External Redirect plugin.
- Removed duplicated TestRedirect plugin (it was a subset of the TestExternalRedirect one)
- Changed help file structure to support internationalisation (Issue 981).
- Added content-type to help pages (Issue 1080).
- Updated add-on dir structure (Issue 1113).

## 13 - 2013-12-11

- Fix for TestRemoteFileInclude failing if Google return localized page

## 12 - 2013-09-27

- Fixed various errors logged

## 11 - 2013-09-11

- Updated to be compatible with 2.2.0

## 9 - 2013-07-20

- Improved the "SQL Injection" scanner with detection of parameters used in the "ORDER BY" clause of the SQL select statement;
- Changed the "Session ID in URL rewrite" scanner to allow the characters "-" and "!" in "JSESSIONID" session token value.

## 8 - 2013-06-24

- Updated language files.

## 7 - 2013-05-27

- Updated language files.

## 6 - 2013-04-18

- Updated for ZAP 2.1.0

## 5 - 2013-03-18

- Modified the generic SQL Injection scanner to detect ".NET Framework Data Provider for OLE DB." error message fragments,
- added an error fragment for generic JDBC error messages,
- fixed an encoding issue with special argument values,
- and try both replacing and appending the parameter value when attempting to force SQL error messages.

## 4 - 2013-01-25

- Split out Remote File Inclusions to separate rule, moved SQL Injection from beta, added 'Reflected' to XSS test name

## 3 - 2013-01-17

- Updated to support new addon format

## 1 - 2012-12-10



[38]: https://github.com/zaproxy/zap-extensions/releases/ascanrules-v38
[37]: https://github.com/zaproxy/zap-extensions/releases/ascanrules-v37
[36]: https://github.com/zaproxy/zap-extensions/releases/ascanrules-v36
[35]: https://github.com/zaproxy/zap-extensions/releases/ascanrules-v35
[34]: https://github.com/zaproxy/zap-extensions/releases/ascanrules-v34
[33]: https://github.com/zaproxy/zap-extensions/releases/ascanrules-v33
