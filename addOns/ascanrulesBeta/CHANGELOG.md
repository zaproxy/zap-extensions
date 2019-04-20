# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased

- Correct HTTP message usage in Insecure HTTP Method scanner.
- Fix missing resource messages with Cross-Domain Misconfiguration scanner.
- Remove Source Code Disclosure WEB-INF Scanner (promoted to release Issue 4448).

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

