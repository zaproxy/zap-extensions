# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased


## [58] - 2024-05-07
### Changed
- Update minimum ZAP version to 2.15.0.
- The library (htmlunit-csp) used by the Content Security Policy scan rule was updated to v4.0.0, which includes support for the wasm-unsafe-eval source expression.

### Fixed
- A typo in the Other Info of one of the Retrieved from Cache Alerts.

## [57] - 2024-03-28
### Changed
- Use of HTTP for example URLs in the descriptions or other info details for the following rules have been updated to HTTPS (Issue 8262):
    - Cookie Poisoning
    - Open Redirect
    - X-Debug-Token Information Leak

## [56] - 2024-02-16

### Added
- Website alert links for Passive Scan Rules (Issue 8189).

### Changed
- Maintenance changes.
- The following rules now include example alert functionality for documentation generation purposes (Issue 6119):
    - Timestamp Disclosure - Unix
    - Hash Disclosure
    - Cross-Domain Misconfiguration
    - Weak Authentication Method
    - Reverse Tabnabbing
    - CSRF Countermeasures
- The following scan rules now have alert references (Issue 7100):
    - Weak Authentication Method
- The references for Alerts from the following rules were also updated (Issue 8262):
    - Timestamp Disclosure - Unix 
    - Hash Disclosure
    - View State Scan Rule 
    - Weak Authentication Method

## [55] - 2024-01-26
### Changed
- The Salvation2 library used by the CSP scan rule has been replaced by htmlunit-csp.
- The following rules now include example alert functionality for documentation generation purposes (Issue 6119):
    - HTTPS to HTTP Insecure Transition in Form Post
    - HTTP to HTTPS Insecure Transition in Form Post
    - Secure Pages Include Mixed Content
    - User Controllable JavaScript Event (XSS)
    - Cookie without SameSite Attribute
    - X-Debug-Token Information Leak
    - Retrieved from Cache
- The following scan rules now have alert references (Issue 7100):
    - Cookie without SameSite Attribute 
    - Retrieved from Cache (raw text was also trimmed from one Alert reference (Issue 8262))

### Fixed
- An issue where Other Info on alerts for the following rules may have been hard to read (missing spaces or new lines):
    - HTTPS to HTTP Insecure Transition in Form Post
    - HTTP to HTTPS Insecure Transition in Form Post
    - User Controllable JavaScript Event (XSS)

## [54] - 2024-01-16
### Changed
- The Big Redirect scan rule will now also alert on responses that have multiple HREFs (idea from xnl-h4ck3r).
- The references for the following scan rules are now all HTTPS (Issue 8262) and in some cases updated:
    - Loosely Scoped Cookie
    - Charset Mismatch
    - Strict-Transport-Security Header
    - Content Security Policy (CSP) Header Not Set
    - CSP
    - Session ID in URL Rewrite
    - HTTP Server Response Header
    - Cookie Poisoning
    - User Controllable HTML Element Attribute (Potential XSS)
    - X-Content-Type-Options Header Missing
    - Content-Type Header Missing
    - Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s)
    - Retrieved from Cache
- The Absence of Anti-CSRF Tokens scan rule now takes into account the Partial Match settings from the Anti-CSRF Options (Issue 8280).
- On Non-LOW threshold, PII Scan rule only evaluates HTML, JSON and XML responses (Issue 8264).
- Maintenance changes.
- The following rules now include example alert functionality for documentation generation and cross linking purposes (Issues 6119, and 8189).
    - Big Redirect
    - Information Disclosure: Debug Errors
    - Information Disclosure: In URL
    - Information Disclosure: Referrer
    - Cookie Poisoning
    - User Controllable Charset
    - Open Redirect
    - User Controllable HTML Element Attribute (Potential XSS)
    - Heartbleed OpenSSL Vulnerability (Indicative)
    - Strict-Transport-Security Header
    - Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s)
    - X-Content-Type-Options Header Missing
    - Content-Type Header Missing
- The CWE for the Cookie Poisoning scan rule was updated to a more specific one.
- The Strict-Transport-Security Header and Big Redirect scan rules now use alert references for their different types of alerts (Issue 7100).

## [53] - 2023-11-30
### Changed
- The Application Error Disclosure rule no longer considers responses that contain ISO control characters (those which are likely to be binary file types).
- The Time Stamp Disclosure rule now includes the header field name as Parameter in alerts when a time stamp is identified in a header value (Issue 8160).
- Maintenance changes.

## [52] - 2023-10-12
### Fixed
- The CSRF Countermeasures scan rule now skips responses that are not HTML (Issue 7890).
- A potential NullPointerException when a CSP declared via META tag was invalid.

### Changed
- Update minimum ZAP version to 2.14.0.
- CSP scan rule: Add deprecation warning for inclusion of prefetch-src (Issue 8077).

## [51] - 2023-09-08
### Added
- The following now include example alert functionality for documentation generation purposes (Issue 6119):
  - Loosely Scoped Cookie scan rule.

### Changed
- Dependency updates.
- Maintenance changes.
- The alerts of the Hash Disclosure scan rule no longer have the evidence duplicated in the Other Info field.
- Depend on newer version of Common Library add-on.
- Use vulnerability data directly from Common Library add-on.

## [50] - 2023-07-11
### Added
- The following now include example alert functionality for documentation generation purposes (Issue 6119):
    - Re-examine Cache-control Directives Scan Rule
    - X-Backend-Server Scan Rule
    - X-ChromeLogger-Data Header Information Leak Scan Rule

### Changed
- Update minimum ZAP version to 2.13.0.

## [49] - 2023-06-06
### Changed
- The X-AspNet-Version Response Header Scan Rule now includes example alert functionality for documentation generation purposes (Issue 6119).
- The Information Disclosure Suspicious Comments scan rule:
    - Now includes example alert functionality for documentation generation purposes (Issue 6119).
    - Now has a Alert Tag with a OWASP WSTG reference.
    - Added 'DEBUG' to list of suspicious comments.
    - Added custom payload support (via Custom Payloads add-on).
    - Removed suspicious-comments.txt file in favor of payload editing via Custom Payloads add-on.

### Fixed
- Ensure Custom Payloads support can be properly unloaded.

## [48] - 2023-05-03
### Added
- Added alert examples to Directory Browsing (Issue 6119).
- Added Trusted Domains in Cross-Domain JavaScript Source File Inclusion (Issue 7775).

### Changed
- Application Error Scan Rule no longer checks JavaScript or CSS responses unless threshold is Low (Issue 7724).
- The Cross-Domain JavaScript Source File Inclusion scan rule now includes example alert functionality for documentation generation purposes (Issue 6119).
- Adjust alert details of Directory Browsing, use same name and description, and use the other info field for the name of the web server identified.

## [47] - 2023-04-04
### Fixed
- Correct required version of Common Library add-on.
- Prevent error with the CSP scan rule when scanning `meta` elements with missing `http-equiv` attribute.

## [46] - 2023-03-03
### Changed
- The PII Disclosure scan rule:
    - Now includes a solution statement.
    - Now more specifically portrays alert Evidence.
    - Now includes example alert functionality for documentation generation purposes (Issue 6119).
    - Will now only consider PDFs at Low threshold.
- Maintenance changes.
- The HeartBleed scan rule alert now includes a CVE tag.
- Timestamp Disclosure scan rule now excludes values in "RateLimit-Reset", "X-RateLimit-Reset", and "X-Rate-Limit-Reset" headers (Issue 7747).

### Fixed
- The CSP Missing scan rule now alerts when the Content-Security-Policy header is missing, and when the obsolete X-Content-Security-Policy or X-WebKit-CSP are found (Issue 7653).

## [45] - 2023-01-03
### Changed
- The Private Address Disclosure and Session ID in URL Rewrite scan rules now include example alert functionality for documentation generation purposes (Issue 6119 and 7100).
- The Content Security Policy scan rule will now alert when "unsafe-eval" is allowed.
- Maintenance changes.
- The Salvation2 library used by the CSP scan rule was upgraded to v3.0.1. Alerts may now have an alert condition if the policy contains characters outside the accepted set.
- The CSP scan rule now includes handling for policies defined in META tags, as well as two new alerts pertaining to those policies (Issue 7303).

### Fixed
- The Modern App Detection scan rule now ignores non-HTML files (Issue 7617).

## [44] - 2022-10-27
### Added
- The following scan rules were added, having been promoted from Beta:
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

### Changed
- Update minimum ZAP version to 2.12.0.
- The Server Header Information Leak scan rule now has functionality to generate example alerts for documentation purposes (Issue 6119).
- Maintenance changes.

## [43] - 2022-09-15
### Changed
- Reduce Cache Control scan rule confidence to Low, and add new reference (Issue 6446).
- Added new Custom Payloads alert tag to the example alerts of the Username IDOR and Application Error scan rules.
- Maintenance changes.
- The Timestamp Disclosure scan rule is now scoped to a 10 year range with a cap at the Y2038 rollover point (Issue 6741).
- The Content Security Policy Header Not Set scan rule will no longer alert if CSP is specified via META tag (Issue 7303).

## [42] - 2022-07-15
### Changed
- The Content Security Policy scan rule will now raise alerts at High confidence, all alerts now include the appropriate header as the "parameter" value, and has functionality to generate example alerts for documentation purposes.
- The Content Security Policy scan rule will now raise an alert when the assessed policy contains non-ASCII characters (Issue 7379).

## [41] - 2022-06-24
### Changed
- Maintenance changes.
- The "Viewstate without MAC Signature (Unsure)" alert will now only be raised at Low Alert Threshold (Issue 7230).
- The Content Security Policy scan rule will now alert when "unsafe-hashes" are allowed.

### Fixed
-  Correct parameter and evidence for Cookie without SameSite Attribute when SAMESITE was set to None (Issue 7358).

## [40] - 2022-04-05
### Changed
- Clarify the alert solution for the Cache Control scan rule.

### Added
- Content Security Policy (CSP) Header Not Set scan rule promoted to release.

## [39] - 2022-03-07
### Added
- Alert refs for the alerts which use them (10020 and 10032).

### Changed
- Moved the detail information in Content Security Policy Rule to the otherInfo field and added alertRef ids.
- Address false positive condition for Timestamp Disclosure scan rule when values are percentages (Issue 7057).
- Update Cache-control scan rule name, description, and solution to make it more clear that there are cases in which caching is reasonable. Reduced risk to Info (Issue 6462).
- Maintenance changes.
- The CSRF Token scan rule will now raise alerts as Medium risk and Low confidence (Issue 7021).

### Fixed
- CSP scan rule will now alert in situations where default-src contains 'unsafe-inline' or is not defined (Issue 7120). In certain situations this may mean a marked increase in CSP related Alerts.
- A typo was corrected in the CSP scan rule which was causing invalid assessment of "connect-src" directives.

## [38] - 2022-01-07
### Changed
- Update minimum ZAP version to 2.11.1.
- Renamed 'X-Frame-Options Header Not Set' alert to 'Missing Anti-clickjacking Header', and associated scan rule 'X-Frame-Options Header' to 'Anti-clickjacking Header'. The rule already considered Content-Security-Policy 'frame-ancestors' which is a more modern solution to the same concern. Updated associated solution text. (Issue 6937)
- Content Security Policy scan rule will no longer classify "require-trusted-types-for" or "trusted-types" directives as unknown (Issue 6602).

## [37] - 2021-12-01
### Added
- OWASP Top Ten 2021/2017 mappings for Insecure Authentication scan rule.
- OWASP Web Security Testing Guide v4.2 mappings where applicable.

### Changed
- Timestamp Disclosure scan rule now excludes values in "Expect-CT" headers (Issue 6725), as well as zero strings (Issue 6761).
- Dependency updates.
- Maintenance changes.

## [36] - 2021-10-06
### Added
- OWASP Top Ten 2021/2017 mappings.

### Changed
- Update minimum ZAP version to 2.11.0.

### Fixed
- Fixed reference URL on CORS misconfiguration.
- Reduce false positives from Private IP Disclosure scan rule (Issue 6749).

## [35] - 2021-07-06
### Changed
- Maintenance changes.

### Fixed
- Correct dependency requirements.

## [34] - 2021-06-17
### Changed
- Cache-control scan rule no longer checks if Pragma is set or not.
- Maintenance changes.
- The Timestamp Disclosure scan rule now excludes values in "Report-To" or "NEL" headers (Issue 6493).
- The Timestamp Disclosure scan rule no longer considers font type requests or responses when looking for possible timestamps (Issue 6274).
- X-Frame-Options scan rule CWE ID changed from 16 to 1021.
- Discontinued use of CWE-16 and switched to more specific weaknesses in the following scan rules:
  - Character Set Mismatch
  - Content Security Policy
  - Cookie HttpOnly
  - Cookie SameSite
  - JSF ViewState
  - MS ViewState
  - X-Content-Type-Options
- Cache-control scan rule no longer checks CSS messages unless threshold is Low (Issue 6596).
- Cookie SameSite Attribute scan rule now handles the value "none" (Issue 6482).
- Content Security Policy rule has been upgraded to use version 3 of the Salvation library.
  - Messages with multiple CSPs are no longer merged/intersected instead the policies are analyzed individually.
- Update links to repository.

## [33] - 2021-01-29
### Added
- Added Express error string pattern (Issue 6412).
- Added sort to form field names that are displayed in Anti-CSRF alert other info field, duplicate names (arrays) are combined and not repeated.

### Changed
- X-Frame-Options (XFO) scan rule no longer suggests the use of "ALLOW-FROM", and also includes CSP "frame-ancestors" as an alternative.
  - XFO headers implementing "ALLOW-FROM" will now be considered malformed.
- The Suspicious Comments scan rule will raise one alert per pattern per page and use more suitable evidence.

## [32] - 2021-01-20
### Changed
- The Suspicious Comments scan rule will include the offending line as evidence.
- The Suspicious Comments scan rule will raise one alert per finding, instead of one aggregated alert per HTTP message.

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



[58]: https://github.com/zaproxy/zap-extensions/releases/pscanrules-v58
[57]: https://github.com/zaproxy/zap-extensions/releases/pscanrules-v57
[56]: https://github.com/zaproxy/zap-extensions/releases/pscanrules-v56
[55]: https://github.com/zaproxy/zap-extensions/releases/pscanrules-v55
[54]: https://github.com/zaproxy/zap-extensions/releases/pscanrules-v54
[53]: https://github.com/zaproxy/zap-extensions/releases/pscanrules-v53
[52]: https://github.com/zaproxy/zap-extensions/releases/pscanrules-v52
[51]: https://github.com/zaproxy/zap-extensions/releases/pscanrules-v51
[50]: https://github.com/zaproxy/zap-extensions/releases/pscanrules-v50
[49]: https://github.com/zaproxy/zap-extensions/releases/pscanrules-v49
[48]: https://github.com/zaproxy/zap-extensions/releases/pscanrules-v48
[47]: https://github.com/zaproxy/zap-extensions/releases/pscanrules-v47
[46]: https://github.com/zaproxy/zap-extensions/releases/pscanrules-v46
[45]: https://github.com/zaproxy/zap-extensions/releases/pscanrules-v45
[44]: https://github.com/zaproxy/zap-extensions/releases/pscanrules-v44
[43]: https://github.com/zaproxy/zap-extensions/releases/pscanrules-v43
[42]: https://github.com/zaproxy/zap-extensions/releases/pscanrules-v42
[41]: https://github.com/zaproxy/zap-extensions/releases/pscanrules-v41
[40]: https://github.com/zaproxy/zap-extensions/releases/pscanrules-v40
[39]: https://github.com/zaproxy/zap-extensions/releases/pscanrules-v39
[38]: https://github.com/zaproxy/zap-extensions/releases/pscanrules-v38
[37]: https://github.com/zaproxy/zap-extensions/releases/pscanrules-v37
[36]: https://github.com/zaproxy/zap-extensions/releases/pscanrules-v36
[35]: https://github.com/zaproxy/zap-extensions/releases/pscanrules-v35
[34]: https://github.com/zaproxy/zap-extensions/releases/pscanrules-v34
[33]: https://github.com/zaproxy/zap-extensions/releases/pscanrules-v33
[32]: https://github.com/zaproxy/zap-extensions/releases/pscanrules-v32
[31]: https://github.com/zaproxy/zap-extensions/releases/pscanrules-v31
[30]: https://github.com/zaproxy/zap-extensions/releases/pscanrules-v30
[29]: https://github.com/zaproxy/zap-extensions/releases/pscanrules-v29
[28]: https://github.com/zaproxy/zap-extensions/releases/pscanrules-v28
[27]: https://github.com/zaproxy/zap-extensions/releases/pscanrules-v27
[26]: https://github.com/zaproxy/zap-extensions/releases/pscanrules-v26
[25]: https://github.com/zaproxy/zap-extensions/releases/pscanrules-v25
[24]: https://github.com/zaproxy/zap-extensions/releases/pscanrules-v24
