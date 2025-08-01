# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased

### Fixed
- Error logs to always include stack trace.

## [33] - 2025-06-20
### Changed
- Add website alert links to the help page (Issue 8189).
- Replace usage of CWE-200 for the following rules (Issue 8712):
    - Email Disclosure.
    - Debug Error Disclosure.

## [32] - 2025-01-10
### Changed
- Update minimum ZAP version to 2.16.0.

### Fixed
- Correct location/function of New Context context menu item.

## [31] - 2024-05-07
### Added
- Support for menu weights (Issue 8369)
### Changed
- Update minimum ZAP version to 2.15.0.
- Maintenance changes.

## [30] - 2023-10-12
### Changed
- Update minimum ZAP version to 2.14.0.
- Maintenance changes.

## [29] - 2023-07-11
### Changed
- Update minimum ZAP version to 2.13.0.
- Maintenance changes.
- Replace usage of singletons with injected variables (e.g. `model`, `control`) in scripts.

## [28] - 2023-01-03
### Changed
- Maintenance changes.

### Fixed
- Prevent exception if no display (Issue 3978).

## [27] - 2022-10-27
### Changed
- Update minimum ZAP version to 2.12.0.
- Maintenance changes.
- Use the Requester add-on for the WebSocket Message Editor dialogues.

### Fixed
- Correctly handle no message in the WebSocket message panel.

## [26] - 2022-05-20
### Changed
- Maintenance changes.
- Cache WebSocket Passive Rules scripts for better performance with all script engines.

### Fixed
- Handle errors caused by WebSocket Passive Rules scripts, which would break the passive scan.

## [25] - 2022-03-14
### Changed
- Update minimum ZAP version to 2.11.1.
- Update the reference links used in the Username IDOR passive scan script.
- Reset the name of the connection threads when not actively used.

### Fixed
- Fix exception when manually reconnecting to the server.
- Stop properly when shutting down.

## [24] - 2021-10-06
### Changed
- Now using 2.10 logging infrastructure (Log4j 2.x).
- Maintenance changes (some changes impact the visibility of variables and add getters/setters, which may impact third party add-ons or scripts).
- Update links to repository.
- Support passive scan alert examples so they can be added to the website
- Missing default scripts will always be added and enabled on start up.
- Update minimum ZAP version to 2.11.0.

## [23] - 2020-12-18
### Changed
- Update minimum ZAP version to 2.10.0.

### Fixed
 - Fix exception when handling breakpoints with ZAP 2.10.0.
 - Terminology

## [22] - 2020-08-17
### Changed
- Update minimum ZAP version to 2.9.0.
- Allow to use newer versions of Fuzzer add-on.
- Maintenance changes.

### Fixed
- Correctly handle API request without parameters.
- Fixed an exception which was occurring when the tab was shown when a handshake response was first encountered during a ZAP session.

## [21] - 2020-01-17
### Added
- Add info and repo URLs.

### Changed
- Maintenance changes.
- Disable table sort in WebSockets panel, not working properly (Issue 1661).

## [20] - 2019-07-23

- Add WebSocket passive scan infrastructure.
  - Add WebSocket Passive scan script plugin.
    - Template scripts for:
      - Python
      - Javascript
    - Default scripts for (loaded and enabled by default):
      - Base64 disclosure
      - Email disclosure
      - Error Application disclosure
      - Private IP disclosure
      - Credit Card disclosure
      - Username disclosure
      - Debug Error disclosure
      - Suspicious XML Comments disclosure
    - Help content for the default scripts.
- Add stats for websocket frames sent and time taken for passive scanning.

## [19] - 2019-06-07

- Fix exceptions when handling/dispatching events.
- Add wrapper to websocket API responses.
- Fix exception when handling API request with no API implementor.
- Correct output stream used in server mode.
- Add support for 'other' API operations.
- Handle API options.
- Validate the Origin for API connections.
- Generate websocket events.
- Add break API endpoints.
- Scale fonts and icons correctly

## 18 - 2018-08-01

- Allow to reopen WebSocket connection to (re)send messages (Issue 4290).

## 17 - 2018-07-13

- Register WebSocket Sender script type also in daemon mode.
- Fix an exception when dispatching events.
- Fix an exception while uninstalling the add-on with no GUI (Issue 4815).
- Remove event consumers when channel is no longer in expected state.

## 16 - 2018-06-05

- Tweak About help page.
- Remove event consumers when the channel is closed.
- Don't enable the sender scripts by default.
- Fix send of CLOSE messages with message editor (Issue 4657).
- Add missing error message.
- Fix removal of pop up menu items.
- Allow to filter by payload in WebSocket tab (Issue 1382).
- Show string representation of binary payloads in WebSocket tab and message panels.

## 15 - 2018-02-21

- Remove usage of core filter functionality.
- Do not set messages when switching views if text view shows an error message (Issue 4108)
- Add rewind to fix issue #4149
- Added Websocket Sender script interface
- Added API support

## 14 - 2017-11-27

- Updated for 2.7.0.

## 13 - 2017-11-24

- Fix context include/exclude pop up menu items.
- Fix/correct help buttons.
- Set fuzzer script type enabled by default (Issue 2997).
- Normalise the Session Properties panel Exclude from WebSockets.
- Implements WebSocketSenderListener.
- Use JRE decoder for UTF-8 conversions and log (debug) invalid payloads (related to Issue 3324).
- Focus WebSockets tab just once (Issue 3747).
- Minor code adjustment to align with core changes.
- Code changes for Java 9 (Issue 2602).
- Remove header Sec-WebSocket-Extensions (Issue 3324).
- Add description to Fuzzer WebSocket Processor script type.
- Update fuzzer template (use JSDoc and fix typos).

## 12 - 2017-04-06

- Make breakpoint dialogues modal.
- Fix exception during the unload of the add-on, when in daemon mode.
- Correct fuzz location overlap detection with same start index.

## 11 - 2016-06-02

- Unload WebSockets components during uninstallation.
- Use hostname/port of the handshake message to build the name of the channel.
- Adjust log levels, from INFO to DEBUG.

## 10 - 2015-12-04

- Fix issue with length of handshake's url (Issue 2097).
- Restore fuzzing capabilities (Issue 1905).

## 9 - 2015-04-13

- Minor code changes and fix of exception.
- Removed fuzzing code - will need to be re-implemented for new adv fuzzing

## 8 - 2014-04-10

- Minor code changes (Issues 503, 609, 1104 and 1105).
- Changed help file structure to support internationalisation (Issue 981).
- Added content-type to help pages (Issue 1080).
- Updated add-on dir structure (Issue 1113).
- Restored the rendering of a custom icon for "handshake" messages shown in "Sites" tab.

## 7 - 2013-09-11

- Updated for 2.2.0.

## 6 - 2013-05-27

- Updated language files

## 5 - 2013-05-13

- Fixed a NullPointerException while starting ZAP with ExtensionBreak disabled

## 4 - 2013-04-26

- Fix Issue 2: setting payload for modified WebSocket messages was erroneous

## 3 - 2013-04-18

- Updated for ZAP 2.1.0

## 2 - 2013-02-24



[33]: https://github.com/zaproxy/zap-extensions/releases/websocket-v33
[32]: https://github.com/zaproxy/zap-extensions/releases/websocket-v32
[31]: https://github.com/zaproxy/zap-extensions/releases/websocket-v31
[30]: https://github.com/zaproxy/zap-extensions/releases/websocket-v30
[29]: https://github.com/zaproxy/zap-extensions/releases/websocket-v29
[28]: https://github.com/zaproxy/zap-extensions/releases/websocket-v28
[27]: https://github.com/zaproxy/zap-extensions/releases/websocket-v27
[26]: https://github.com/zaproxy/zap-extensions/releases/websocket-v26
[25]: https://github.com/zaproxy/zap-extensions/releases/websocket-v25
[24]: https://github.com/zaproxy/zap-extensions/releases/websocket-v24
[23]: https://github.com/zaproxy/zap-extensions/releases/websocket-v23
[22]: https://github.com/zaproxy/zap-extensions/releases/websocket-v22
[21]: https://github.com/zaproxy/zap-extensions/releases/websocket-v21
[20]: https://github.com/zaproxy/zap-extensions/releases/websocket-v20
[19]: https://github.com/zaproxy/zap-extensions/releases/websocket-v19
