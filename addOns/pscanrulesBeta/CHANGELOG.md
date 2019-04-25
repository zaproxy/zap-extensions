# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased

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

