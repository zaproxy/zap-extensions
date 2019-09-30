# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased


## [9] - 2019-09-30

- Added support for parameter regex, attack and evidence strings and regexes (Issue 5574)
- Added support for global alert filters (Issue 5575)
- Added option to create alert filters from alert
- Added options to test which alerts will apply to and to actually apply them
- Removed the "Context" from the add-on name
- Promote Alert Filters addon to release status

## [8] - 2019-06-07

- Correct required state of an API parameter.
- Add description to API endpoints.

## 7 - 2018-02-15

- Fix an exception when running ZAP in daemon mode (Issue 4405).

## 6 - 2017-11-27

- Updated for 2.7.0.

## 5 - 2017-11-24

- Dynamically unload the add-on.
- Clear filters on session changes (Issue 3683).

## 4 - 2017-04-03

- Minor functional improvement.

## 3 - 2016-06-02

- Various minor UI improvements

## 2 - 2016-03-22

- Updated to use alertIds from 2.4.3+
- Misc minor bug fixes
- HTML report reports the filtered false positives as true results (Issue 2311)
- Promoted to beta and added icon
- Various minor UI improvements

## 1 - 2015-09-07

- First version

[9]: https://github.com/zaproxy/zap-extensions/releases/alertFilters-v9
[8]: https://github.com/zaproxy/zap-extensions/releases/alertFilters-v8
