# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased


## [66] - 2024-05-07
### Changed
- Update minimum ZAP version to 2.15.0.

## [65] - 2024-03-28
### Changed
- Change link to use HTTPS in other info of SQL Injection - SQLite (Issue 8262).

## [64] - 2024-03-25
### Changed
- The following scan rules now include example alert functionality for documentation generation purposes (Issue 6119):
    - Source Code Disclosure - CVE-2012-1823
    - Remote Code Execution - CVE-2012-1823
    - Server Side Include
    - Cross Site Scripting (Reflected)
- The Alerts from the Remote Code Execution - CVE-2012-1823 scan rule no longer have evidence duplicated in the Other Info field.
- The GET for POST scan rule now uses a different comparison mechanism which should be more tolerant of unrelated response differences.

## [63] - 2024-02-12
### Changed
- Maintenance changes.

### Added
- The SQL Injection scan rule now includes a MySQL/MariaDB generic error message.

## [62] - 2024-01-26
### Changed
- The Source Code Disclosure - /WEB-INF Folder rule now includes example alert functionality for documentation generation purposes (Issue 6119).

## [61] - 2024-01-24
### Changed 
- Update reference for Server Side Include (Issue 8262) 
### Fixed
- False positives on redirects for:
  - Cloud Metadata (Issue 7710)
  - Hidden Files

## [60] - 2024-01-16
### Changed
- Leave data empty instead of adding "N/A" for the scan rules:
  - Cross Site Scripting (Persistent) - Prime
  - Cross Site Scripting (Persistent) - Spider
- Update reference for Server Side Code Injection (Issue 8262).
- Now depends on minimum Common Library version 1.21.0.

### Fixed
- Threshold handling in the Hidden File Finder scan rule.
- Improved the following scan rules by using time-based linear regression tests:
  - Server Side Template Injection (Blind)
  - SQL Injection - Hypersonic SQL
  - SQL Injection - MsSQL
  - SQL Injection - MySQL

### Added
- Help entry for the Spring Actuators scan rule (missed during previous promotion).
- Website alert links to the help page (Issue 8189).
- The following scan rules now include example alert functionality for documentation generation purposes (Issue 6119) and in some cases updated references (Issue 8262).
  - CRLF Injection
  - Remote OS Command Injection
  - GET for POST
  - ELMAH Information Leak
  - .env Information Leak
  - .htaccess Information Leak
  - Trace.axd Information Leak

## [59] - 2023-12-07
### Added
- Support for mutations in reflected XSS rule.

### Changed
- Depend on newer version of Common Library add-on.

### Fixed
- Use high and low delays for linear regression time-based tests to fix false positives from delays that were smaller than normal variance in application response times, which affected Command Injection scan rule.
- Improved SQL Injection - PostgreSQL (Time Based) scan rule by using time-based linear regression tests.
- Catch correct context while analysing attributes instead of the last attribute where eyecatcher was reflected.

## [58] - 2023-10-12
### Changed
- Update minimum ZAP version to 2.14.0.

## [57] - 2023-09-08
### Changed
- Maintenance changes.
- Depend on newer version of Common Library add-on.
- Use vulnerability data directly from Common Library add-on.

### Fixed
- False positive where linear regression time-based tests returned true when there were not enough requests for a statistically meaningful measurement.

## [56] - 2023-07-11
### Added
- The Format String Error scan rule now includes example alert functionality for documentation generation purposes (Issue 6119).
- Corrected Hidden File Finder scan rule Blazor WASM config file path.
- The following scan rules were added, having been promoted from Beta:
  - Log4Shell
  - Spring Actuator Information Leak
  - Spring4Shell
  - Server Side Template Injection
  - Server Side Template Injection (Blind)
  - XPath Injection

### Changed
- Update minimum ZAP version to 2.13.0.

## [55] - 2023-06-06
### Changed
- The Parameter Tamper Scan rule now includes example alert functionality for documentation generation purposes (Issue 6119)

### Fixed
- Fix typo in ASP payload of Server Side Code Injection scan rule.
- Include complete solution of Server Side Include scan rule.
- Ensure Custom Payloads support can be properly unloaded.

### Added
- The Hidden File Finder scan rule now check for Blazor WASM config files.

## [54] - 2023-05-03
### Changed
- Maintenance changes.

### Fixed
- Correct IP used for AWS/GCP in the Cloud Metadata Potentially Exposed scan rule (Issue 7829).

## [53] - 2023-03-03
### Changed
- Maintenance changes.
- The SQL Injection Scan Rule filters reflected payload containing escaped characters like '&amp;' and '&quot;' before response content comparison to reduce false negatives.

## [52] - 2023-02-03
### Changed
- The following scan rules now include example alert functionality for documentation generation purposes (Issue 6119 & 7100).
    - Buffer Overflow
    - Cloud Metadata
    - Code Injection
    - Path Traversal
    - Remote File Include
- The Path Traversal scan rule no longer populates the Other Info field with check information, as the Alert Reference now provides that detail.
- Maintenance changes.
- Update dependency.
- CVE-2012-1823 Remote Execution and Source Code Disclosure, and Heart Bleed scan rules now include Alert Tags for the applicable CVEs.

### Fixed
- A false positive that could occur in the External Redirect scan rule if the payload was included in the redirect as a param or portion of the value.

## [51] - 2023-01-03
### Changed
- Command Injection Scan Rule: Time-based blind detection heuristic has been replaced with linear regression.

### Fixed
- SQL rule should not target NoSQL Dbs.

### Changed
- Maintenance changes.

## [50] - 2022-12-13
### Changed
- The Directory Browsing scan rule now includes example alert functionality for documentation generation purposes (Issue 6119).
- Use lower case HTTP field names for compatibility with HTTP/2.
- Maintenance changes.

### Fixed
- False positive in case of javascript: protocol xss attacks, when attack payload is modified by the application (Issue 6013).
- Preserve the HTTP version in the scan rules:
  - Remote Code Execution - CVE-2012-1823
  - Source Code Disclosure - CVE-2012-1823
  - Source Code Disclosure - /WEB-INF folder

### Added
- The Hidden File Finder scan rule will now also check for "/_wpeprivate/config.json".

## [49] - 2022-10-27
### Added
- The following scan rules were added, having been promoted from Beta:
    - .env Information Leak
    - Cloud Metadata Attack
    - GET for POST
    - Heartbleed OpenSSL Vulnerability
    - Hidden File Finder
    - Padding Oracle
    - Remote Code Execution - CVE-2012-1823
    - Source Code Disclosure - CVE-2012-1823
    - SQL Injection - Hypersonic (Time Based)
    - SQL Injection - MsSQL (Time Based)
    - SQL Injection - MySQL (Time Based)
    - SQL Injection - Oracle (Time Based)
    - SQL Injection - PostgreSQL (Time Based)
    - SQL Injection - SQLite
    - Trace.axd Information Leak
    - User Agent Fuzzer
    - XSLT Injection
    - XXE

### Changed
- Update minimum ZAP version to 2.12.0.
- Maintenance changes.
- Rely on Network add-on to obtain more information about socket timeouts.

## [48] - 2022-09-22
### Changed
- Command Injection Scan Rule: Decode HTML entities in HTML responses before attempting to search for attack validation patterns.

## [47] - 2022-08-16
### Added
- Cross Site Scripting header splitting attacks.
- The External Redirect scan rule now includes alert references on Alerts, and has example alert functionality for documentation generation purposes.

### Changed
- Maintenance changes.
- Updated the External Redirect scan rule to be more accurate.
- The Reflected XSS scan rule now generates alerts for all content-types when alert threshold set to LOW. If alert threshold MEDIUM or HIGH, alerts are raised for HTML responses only.

### Fixed
- The Remote File Inclusion scan rule no longer follows redirects before checking the response for content indicating a vulnerability (Issue 5887).
- False positive where Cross Site Scripting payloads are safely rendered in a textarea tag.
- Unescaped tag end causing Cross Site Scripting rule to throw an exception.

## [46] - 2022-03-21
### Changed
- Maintenance changes.

### Fixed
- Fix Cross Site Scripting (Reflected) scan rule false negatives introduced in previous version.

## [45] - 2022-03-15
### Changed 
- Remote OS Command Injection rule now has more information in the Other Info field to differentiate feedback-based or time-based tests
- Path Traversal scan rule, updated the regex for case 5 to be case-insensitive when searching for Error or Exception in content body.
- Maintenance changes.

### Fixed
- Server Side Code Injection scan rule, prevent use of zero when injecting ASP multiplication to avoid false positives (Issue 7107).
- External Redirect scan rule to detect redirects with dots deny listed.
- Cross Site Scripting (Reflected) scan rule will no longer raise an alert for unsuccessful JavaScript string injections (Issue 1641).

## [44] - 2022-01-13
### Changed
- Update minimum ZAP version to 2.11.1.
- The XSS scan rule will try several different payloads if the payload is being reflected outside of any HTML tags (for example in a JSON response body).

## [43] - 2021-12-06
### Added
- OWASP Web Security Testing Guide v4.2 mappings where applicable.

## [42] - 2021-11-29
### Changed
- Command Injection scan rule will now initially attempt a simple injection without the original parameter value (Issue 6538).
- Reflected XSS rule: added a generic 'onerror' attack and tweaked the case of the script attack

## [41] - 2021-10-06
### Changed
- Added OWASP Top Ten 2021/2017 mappings.
- Update minimum ZAP version to 2.11.0.

## [40] - 2021-06-17
### Changed
- The SQL Injection scan rule will raise alerts with the URI field in encoded form.
- Update links to repository.

### Fixed
- Correct Context check in SQL Injection scan rule.
- "Source Code Disclosure - /WEB-INF folder" is no longer skipped on Java 9+ (Issue 4038).
- Fix ascan rules not enforcing MaxRuleDuration when getting IOExceptions (Issue 6647).

## [39] - 2021-05-10
### Changed
- Now using 2.10 logging infrastructure (Log4j 2.x).
- Maintenance changes.
- The Path Traversal scan rule should now be less False Positive prone at High Threshold, one of it's checks will now be excluded at High Threshold (Issues: 4209, 6030, 6219, 6372, and 6380).
  - The Other info field of Alerts will now include a reference indicating which check the triggered alert is caused by, in order to assist in future user inquiries.
- Added/updated the details of some alerts (some changes might break Alert Filters)
  - Buffer Overflow
    - Includes an Attack string
    - Evidence changed from the whole request header to the specific string sought
  - Code Injection
    - Includes evidence for PHP and ASP related alerts
  - CRLF Injection
    - Attack and Evidence are now more specific
  - Directory Browsing
    - Attack is now the URL of the request
    - Evidence added
- Parameter Tampering scan rule, adjusted regular expression related to VBScript errors.
- Code Injection scan rule is now using random numbers for the ASP related check.
- SQL Injection scan rule now has one more payload for error based checks, and an additional SQLite related check string (Issue 6588).

### Fixed
- Fix XSS false positive (Issue 5958).

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
- Issue 3978: Handle reflected XSS in JSON response.
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



[66]: https://github.com/zaproxy/zap-extensions/releases/ascanrules-v66
[65]: https://github.com/zaproxy/zap-extensions/releases/ascanrules-v65
[64]: https://github.com/zaproxy/zap-extensions/releases/ascanrules-v64
[63]: https://github.com/zaproxy/zap-extensions/releases/ascanrules-v63
[62]: https://github.com/zaproxy/zap-extensions/releases/ascanrules-v62
[61]: https://github.com/zaproxy/zap-extensions/releases/ascanrules-v61
[60]: https://github.com/zaproxy/zap-extensions/releases/ascanrules-v60
[59]: https://github.com/zaproxy/zap-extensions/releases/ascanrules-v59
[58]: https://github.com/zaproxy/zap-extensions/releases/ascanrules-v58
[57]: https://github.com/zaproxy/zap-extensions/releases/ascanrules-v57
[56]: https://github.com/zaproxy/zap-extensions/releases/ascanrules-v56
[55]: https://github.com/zaproxy/zap-extensions/releases/ascanrules-v55
[54]: https://github.com/zaproxy/zap-extensions/releases/ascanrules-v54
[53]: https://github.com/zaproxy/zap-extensions/releases/ascanrules-v53
[52]: https://github.com/zaproxy/zap-extensions/releases/ascanrules-v52
[51]: https://github.com/zaproxy/zap-extensions/releases/ascanrules-v51
[50]: https://github.com/zaproxy/zap-extensions/releases/ascanrules-v50
[49]: https://github.com/zaproxy/zap-extensions/releases/ascanrules-v49
[48]: https://github.com/zaproxy/zap-extensions/releases/ascanrules-v48
[47]: https://github.com/zaproxy/zap-extensions/releases/ascanrules-v47
[46]: https://github.com/zaproxy/zap-extensions/releases/ascanrules-v46
[45]: https://github.com/zaproxy/zap-extensions/releases/ascanrules-v45
[44]: https://github.com/zaproxy/zap-extensions/releases/ascanrules-v44
[43]: https://github.com/zaproxy/zap-extensions/releases/ascanrules-v43
[42]: https://github.com/zaproxy/zap-extensions/releases/ascanrules-v42
[41]: https://github.com/zaproxy/zap-extensions/releases/ascanrules-v41
[40]: https://github.com/zaproxy/zap-extensions/releases/ascanrules-v40
[39]: https://github.com/zaproxy/zap-extensions/releases/ascanrules-v39
[38]: https://github.com/zaproxy/zap-extensions/releases/ascanrules-v38
[37]: https://github.com/zaproxy/zap-extensions/releases/ascanrules-v37
[36]: https://github.com/zaproxy/zap-extensions/releases/ascanrules-v36
[35]: https://github.com/zaproxy/zap-extensions/releases/ascanrules-v35
[34]: https://github.com/zaproxy/zap-extensions/releases/ascanrules-v34
[33]: https://github.com/zaproxy/zap-extensions/releases/ascanrules-v33
