# Changelog

All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased


## [0.18.0] - 2024-05-07
### Changed
- Update minimum ZAP version to 2.15.0.
- Maintenance changes.

## [0.17.0] - 2023-10-12
### Changed
- Update minimum ZAP version to 2.14.0.
- Maintenance changes.

## [0.16.0] - 2023-07-11
### Changed
- Update minimum ZAP version to 2.13.0.
- Replace usage of singletons with injected variables (e.g. `model`, `control`) in scripts.

## [0.15.0] - 2023-03-13
### Added 
- A context menu to paste payloads from all the supported OAST services (Issue 7665).

## [0.14.0] - 2022-12-13
### Changed
- Maintenance changes.
- Do not include the Connection header in Callback responses for HTTP/2.

### Added
- Allow getting both the payload and canary values for OAST services.

### Fixed
- Interactsh canary values were reversed in the UI.

## [0.13.0] - 2022-10-27
### Changed
- Update minimum ZAP version to 2.12.0.

### Added
- BOAST Payloads are persisted in the permanent database, and polled in future ZAP sessions.

## [0.12.0] - 2022-10-19
### Fixed
- Deregister the Interactsh service even in case of error (Issue 7504).
- Clear Interactsh payloads from the GUI when the service is deregistered.
- Error logged when interactsh server returns null data.

## [0.11.0] - 2022-09-23
### Changed
- Maintenance changes.
- Rename the `OAST Register Request Handler.js` script template to `OAST Request Handler.js`
  and use the Extender script type for it. The request handler is now removed when the
  script is disabled.
- Promoted to Beta status.

### Added
- Default services notes in the help documents.
- Extension description and UI name.
- Allow unregistering specific OAST Request handlers.

### Fixed
- Synchronized alerts cache access to avoid locks

## [0.10.0] - 2022-02-18
### Added
- The following two statistics for each OAST service:
  - `stats.oast.<service>.payloadsGenerated`
  - `stats.oast.<service>.interactions`

### Changed
- Use Network add-on to serve callback requests.
- Maintenance changes.

## [0.9.0] - 2022-01-31
### Added
- Status indicators for external OAST services.

### Changed
- Close callback connections gracefully.
- Maintenance changes.
- Make Interactsh payloads more robust by adding a further char with a dot before the actual correlationId (Issue 7003)

## [0.8.0] - 2022-01-10
### Changed
- Set HttpSender's initiator to `OAST_INITIATOR`, value 16.

### Fixed
- Fixed Interactsh multi threading issue during register and deregister (Issue 6997) 
- Interactsh: server URL change in Options deregisters old server URL and registers new server URL
- OAST Interactsh Options Dialog: If host or token config changed the 'New Payload' Button generates the Payload still with the old config. 
Button is disabled in that case.

## [0.7.0] - 2021-12-12
### Changed
- Update minimum ZAP version to 2.11.1.
- Maintenance changes.
- Add a link to the OAST help in the alert tag value.

## [0.6.0] - 2021-12-06
### Added
- An option to allow selecting the OAST service which will be used in active scan rules.
- An alert tag ("OUT_OF_BAND") for alerts raised by scan rules that make use of out-of-band services.

### Changed
- Depend on Network add-on.

### Fixed
- Interactsh:
  - Polling did not start automatically when a new payload was generated.
  - The deregistration request did not include the secret key.

## [0.5.0] - 2021-10-06
### Changed
- Updated the default Interactsh server URL to https://interactsh.com.
- Update minimum ZAP version to 2.11.0.

## [0.4.0] - 2021-09-22
### Added
- Interactsh support.

### Changed
- The _OAST Register Request Handler.js_ script template now also prints the raw request sent to the server.

## [0.3.0] - 2021-08-26
### Added
- A "Poll Now" button to the OAST tab.

## [0.2.2] - 2021-08-23
### Fixed
- The add-on did not stop when ZAP did, which led to ZAP hanging.

### Changed
- Minor script and help updates.

## [0.2.1] - 2021-08-19
### Changed
- Renamed the "OAST Callbacks" tab to "OAST".
- Updated help pages.

### Fixed
- Script templates were being loaded twice, resulting in a warning.

## [0.2.0] - 2021-08-17
### Added
- An option to allow changing the polling frequency of BOAST servers.
- A table that lists the payloads and canary values of all registered BOAST servers.
- Two new scripts that demonstrate how to interact with this add-on:
  - OAST Register Request Handler.js (Template)
  - OAST Get BOAST Servers.js

### Removed
- The _ID_ and the _Canary Value_ fields, in favour of the _Active Servers_ table in the BOAST options window.

## [0.1.1] - 2021-08-04
### Fixed
- Requests were not showing up in the OAST Callbacks panel.
- BOAST servers were not being polled after registration.

## [0.1.0] - 2021-08-04

[0.18.0]: https://github.com/zaproxy/zap-extensions/releases/oast-v0.18.0
[0.17.0]: https://github.com/zaproxy/zap-extensions/releases/oast-v0.17.0
[0.16.0]: https://github.com/zaproxy/zap-extensions/releases/oast-v0.16.0
[0.15.0]: https://github.com/zaproxy/zap-extensions/releases/oast-v0.15.0
[0.14.0]: https://github.com/zaproxy/zap-extensions/releases/oast-v0.14.0
[0.13.0]: https://github.com/zaproxy/zap-extensions/releases/oast-v0.13.0
[0.12.0]: https://github.com/zaproxy/zap-extensions/releases/oast-v0.12.0
[0.11.0]: https://github.com/zaproxy/zap-extensions/releases/oast-v0.11.0
[0.10.0]: https://github.com/zaproxy/zap-extensions/releases/oast-v0.10.0
[0.9.0]: https://github.com/zaproxy/zap-extensions/releases/oast-v0.9.0
[0.8.0]: https://github.com/zaproxy/zap-extensions/releases/oast-v0.8.0
[0.7.0]: https://github.com/zaproxy/zap-extensions/releases/oast-v0.7.0
[0.6.0]: https://github.com/zaproxy/zap-extensions/releases/oast-v0.6.0
[0.5.0]: https://github.com/zaproxy/zap-extensions/releases/oast-v0.5.0
[0.4.0]: https://github.com/zaproxy/zap-extensions/releases/oast-v0.4.0
[0.3.0]: https://github.com/zaproxy/zap-extensions/releases/oast-v0.3.0
[0.2.2]: https://github.com/zaproxy/zap-extensions/releases/oast-v0.2.2
[0.2.1]: https://github.com/zaproxy/zap-extensions/releases/oast-v0.2.1
[0.2.0]: https://github.com/zaproxy/zap-extensions/releases/oast-v0.2.0
[0.1.1]: https://github.com/zaproxy/zap-extensions/releases/oast-v0.1.1
[0.1.0]: https://github.com/zaproxy/zap-extensions/releases/oast-v0.1.0
