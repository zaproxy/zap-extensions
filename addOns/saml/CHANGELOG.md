# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased
### Added
- Add help.
- Add info and repo URLs.

### Changed
- Update minimum ZAP version to 2.9.0.
- Maintenance changes.

## [8] - 2019-08-30

- Update minimum ZAP version to 2.5.0.
- Compressed SAMLMessage is not required
- Possibility to disable compression when sending
- Added SAML Passive Scanner
- Dynamically unload the add-on.
- Fix exception with Java 9+ (Issue 5032).
- Replaced joda.time.datetime with java.time.localtime (Java8).

## 7 - 2017-11-24

- Minor code change to work with ZAP 2.5.0.

## 6 - 2016-06-02

- Use ZAP's home directory for SAML configuration file.

## 5 - 2016-02-05

- Internationalise and show 'SAML Actions' menu.
- Security fixes, to be detailed later.

## 4 - 2015-09-07

- Updated add-on's info URL.

## 3 - 2015-04-13

- Updated for ZAP 2.4

## 2 - 2014-04-03

- Updated to latest core changes and other minor code changes (Issue 609).
- Updated add-on dir structure (Issue 1113).

## 1 - 2013-10-08

- First version

[8]: https://github.com/zaproxy/zap-extensions/releases/saml-v8
