# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased


## [14] - 2020-12-15
### Added
- Add info and repo URLs.

### Changed
- Update minimum ZAP version to 2.10.0.
- Improve permissions and space handling when saving.

## [13] - 2019-07-15

- Maintenance changes.
- Address problem from v12 where analysis dialog wasn't being shown after collection (this was due to a build issue).

## 12 - 2018-05-17

- Stop the test and clear the panel on session changes.
- Respect the current mode and react to changes.
- Inform of running test (e.g. on session change, add-on uninstall).
- Allow to configure the number of threads.
- Allow to delay the requests.
- Update minimum ZAP version to 2.6.0.
- Deletes the cookie in question before sending the request.

## 11 - 2017-11-24

- Use custom HTTP Sender initiator ID.
- Show same cookies once in Generate Tokens dialogue (Issue 2116).
- Fix exception when no tokens are found (Issue 2116).
- Added help file.
- Issue 2338: Allow dynamic timeout adjustment to combat read timeout issues.
- Ensure initial dialog is properly sized.
- Issue 2000: Title caps adjustments.
- Code changes for Java 9 (Issue 2602).
- Ensure Analyse Token dialogue is shown in front of main window.

## 10 - 2015-09-07

- Change active Pause Button to a Play button (Issue 1802).

## 9 - 2015-07-24

- Allow the user to specify the number of requests (Issue 1711)

## 8 - 2015-04-13

- Updated for ZAP 2.4

## 7 - 2014-04-10

- Updated to use the latest core changes (Issues 609 and 1104).
- Changed to display the messages generated in a table (Issue 503).
- Updated add-on dir structure (Issue 1113).

## 6 - 2013-12-13

- Updated for 2.2.0

## 5 - 2013-05-27

- Updated language files.

## 4 - 2013-05-13

- Changed to unload all components when uninstalling.
- Changed the messages keys prefix.
- Changed to use the messages automatically loaded by ZAP.
- Updated for ZAP 2.1.0

## 3 - 2013-01-17

- Updated to support new addon format

## 2 - 2012-11-23



[14]: https://github.com/zaproxy/zap-extensions/releases/tokengen-v14
[13]: https://github.com/zaproxy/zap-extensions/releases/tokengen-v13
