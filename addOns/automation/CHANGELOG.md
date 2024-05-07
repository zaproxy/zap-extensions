# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased


## [0.40.0] - 2024-05-07
### Changed
- Update minimum ZAP version to 2.15.0.

## [0.39.0] - 2024-04-23
### Added
- Allow reports to know the number of Sites tree nodes actively scanned (Issue 7022).

### Changed
- Allow to run remote plans through the command line.

## [0.38.0] - 2024-04-11
### Fixed
- Correctly expose all information in the `planProgress` API view (Issue 8433). This might break existing clients as the format has changed.
  - JSON changed to, e.g.:
  ```json
  {
    "warn" : [ ],
    "planId" : 0,
    "started" : "2024-04-08T00:00:00.615Z",
    "finished" : "2024-04-08T00:00:00.702Z",
    "error" : [ ],
    "info" : [ "Job requestor started", "Job requestor finished, time taken: 00:00:00" ]
  }
  ```
  - XML changed to, e.g.:
  ```xml
   <planProgress type="set">
     <planId>0</planId>
     <started>2024-04-08T00:00:00.615Z</started>
     <finished>2024-04-08T00:00:00.702Z</finished>
     <info type="list">
       <message>Job requestor started</message>
       <message>Job requestor finished, time taken: 00:00:00</message>
     </info>
     <warn type="list"/>
     <error type="list"/>
   </planProgress>
  ```

## [0.37.0] - 2024-03-28
### Changed
- Allow to use variables composed of multiple variables.

## [0.36.0] - 2024-03-25
### Added
- Support for upstream proxy in environment (Issue 8360).

### Changed
- Maintenance changes.
- Cut down env data when generating min template.

### Fixed
- Correct parsing of attack strength and alert threshold in some locales.

## [0.35.0] - 2024-01-16
### Added
- Video links in help for Automation Framework jobs.

### Changed
- Allow to include techs in a context.

### Fixed
- Show method and URL when outputting the status code mismatch of `requestor` job.

## [0.34.0] - 2023-11-16
### Added
- Show column control in the Automation tab to allow to show/hide columns and auto resize them (`Pack All Columns`).

### Fixed
- Save context.

## [0.33.0] - 2023-10-12
### Changed
- Update minimum ZAP version to 2.14.0.

## [0.32.0] - 2023-10-04
### Fixed
- Correct output of array values set to the jobs.

## [0.31.0] - 2023-09-07
### Added
- Add support for max alerts per rule in the Active Scan job (Issue 7784).

### Changed
- Maintenance changes.
- Depend on newer version of Common Library add-on (Related to Issue 7961).
- Clarify authentication docs.

### Removed
- The SnakeYAML Engine dependency was removed.

### Fixed
- Address error logged when using the Active Scan job.
- Do not fail to load plans without jobs.
- Support converting Lists to arrays when updating objects.

## [0.30.0] - 2023-07-11
### Changed
- Update minimum ZAP version to 2.13.0.
- Dependency updates.

### Fixed
- Address exception when creating a new context through the UI.
- Allow to test alerts of Directory Browsing (ID 0), previously would report as a missing ID.

## [0.29.0] - 2023-06-06
### Added
- Statistic name to test summary.

### Fixed
- Test taking into account previous statistic values.
- Clear Output tab on new plan.

## [0.28.0] - 2023-05-04
### Added
- Support for verification type of "autodetect" (post 2.12).

## [0.27.0] - 2023-04-28
### Added
- Support for dynamically added auto-detect authentication.
- Support for dynamically added auto-detect session management.
- Show job time taken in panel and output.

### Fixed
- Correct file path resolution with environment variables.

## [0.26.0] - 2023-03-18
### Added
- Support for dynamically added browser based authentication.

### Changed
- Environment help page to clarify use of variables.

## [0.25.1] - 2023-03-03
### Fixed
- NPE when accessing active scan job.

## [0.25.0] - 2023-02-28
### Added
- Support for dynamically added header based session management method.

### Fixed
- Active scan would fail if threadsPerHost set to zero.

### Changed
- Maintenance changes.

## [0.24.0] - 2023-02-09
### Added
- Support for relative file paths and ones including vars.
- Option to disable all of the passive scan rules.

### Fixed
- NPE when adding a context to an existing plan.

## [0.23.0] - 2023-02-06
### Changed
- Maintenance changes.
### Fixed
- Added workaround for core bug which meant auth header env vars were not being applied.

## [0.22.0] - 2023-01-06
### Added
- Method to get running plans - can be used by scripts to interact with the plans.

## [0.21.0] - 2023-01-03
### Changed
- Maintenance changes.

### Added
- Warning if unexpected element under `activeScan` job (e.g. misplaced `rules`).
- Help details warning against specifying default ports (80/443) (Issue 7649).

## [0.20.0] - 2022-12-14
### Added
- Allow to specify the HTTP version for requests in the `requestor` job.
- Support for context technology (Issue 7127).

### Changed
- Maintenance changes.

### Fixed
- Prevent exception if no display.

## [0.19.0] - 2022-10-27
### Changed
- Update minimum ZAP version to 2.12.0.

### Removed
- The spider job was removed, it is provided by the Spider add-on (Issue 3113).

## [0.18.0] - 2022-10-12
### Added
- Add support for headers in the requestor job (Issue 6917).

### Changed
- Maintenance changes.

### Fixed
- Allow spider to run if no OK response (Issue 7510).
- Bug in passive scan reporting code which prevented specified alerts from being read.
- NPE when adding users to more than one context.

## [0.17.0] - 2022-09-09
### Added
- Add Save As button that allows user to save the automation plan to a different file (Issue 7178).
- Support for monitor tests.

### Changed
- Maintenance changes.
- Rely on spider add-on (Issue 3113).
- passiveScan-config job resets the state, as scanOnlyInScope is often confusing in the GUI. 
- Deprecated the addOns job.

### Fixed
- Correct loading of custom scripts (e.g. Zest).
- The activeScan and spider jobs no longer switch tabs when they run.

## [0.16.0] - 2022-06-22
### Changed
- Maintenance changes.

### Fixed
- Show each context URL in its own line when editing in the GUI (Issue 7241).
- Correct error messages.
- Wrong API end point reference in help
- Fix exception when alerts found during active scan no longer exist when creating the data for the report.

## [0.15.0] - 2022-04-25
### Added
- Test type to check for presence of a URL.

### Changed
- Maintenance changes.

### Fixed
- Use correct authentication verification method for `request`.
- Exceptions when using the GUI.

## [0.14.0] - 2022-04-05
### Added
- Import Job profile (Issue 7078).

### Changed
- The ascan job 'Scan All Header' GUI label

### Fixed
- Register plans run by -autorun to prevent NPEs when editing them
- Issue when turning off specific active scan rules

## [0.13.0] - 2022-02-25
### Fixed
- Issue when adding or removing add-ons via the UI (Issue 7075)
- Issue when creating a script session management with parameters from an existing context

## [0.12.0] - 2022-02-01
### Added
- Script authentication support

### Fixed
- When a Job is loaded via yaml and edited via UI Dialog then the saved changes will be applied on the next job run
- DelayJob will be verified on yaml load

### Changed
- When a Job is edited via UI Dialog then the status will be set to Not started

## [0.11.0] - 2022-01-19
### Added
- Support for generating stats
- Form and JSON-based authentication support

### Changed
- Promoted to beta

## [0.10.1] - 2022-01-05
### Fixed
- Ensure system environment variables take precedence over configuration variables (Issue 7000).

## [0.10.0] - 2021-12-13
### Changed
- Update minimum ZAP version to 2.11.1.

### Fixed
- Setting delay job parameters from the commandline

## [0.9.0] - 2021-12-06

### Changed
- Disabled addOns job updateAddOns option due to problems updating the framework and jobs while they are running

## [0.8.0] - 2021-11-02
### Added
- Delay job
- Session management support
- User and HTTP authentication support
- Authentication verification support
- Set ZAP exit code when "-cmd" and "-autorun" options used
- Requestor, Spider and ActiveScan jobs changed to support an authenticated user
- Support for site specific statistics

### Changed
- Dependency updates.

### Fixed
- Plans saved without default ".yaml" extension.
- Env vars in context names replaced on load, so lost if the plan saved again via the GUI.

## [0.7.0] - 2021-10-06
### Added
 - API support: runplan action and planprogress view.
### Changed
 - Maintenance changes.
- Update minimum ZAP version to 2.11.0.

### Fixed
 - "Unexpected obj object java.lang.String" error shown during initialization

## [0.6.0] - 2021-09-16
### Changed
 - Maintenance changes.

## [0.5.0] - 2021-08-23
### Fixed
 - Address errors when running an automation plan with spiders and passive scan config.
 - Fixed var support in URLs ([Issue #6726](https://github.com/zaproxy/zaproxy/issues/6726))
 - Always enable the Save button on changes and prompt user when opening a plan if the current one has changes.

### Changed
 - Changes to support the Retest add-on.

## [0.4.1] - 2021-08-07
### Added
- Missing icons

## [0.4.0] - 2021-08-05
### Added
- Support for alert tests
- First phase of GUI

### Changed
- Infrastructure changes to support planned GUI.

## [0.3.0] - 2021-06-28
### Added
- Support for using variables in the config.
- Support for data jobs.
- Support for multiple top level URLs in a context.
- Passive scan config enableTags parameter
- Support for include/exclude regexes.
- Support for param data job
- Support for job tests.
- A new Requestor job to make specific requests.

### Changed
- Update links to repository.
- Maintenance changes.

### Fixed
- NPE in pscan config job when rule specified with no id (as per template).

### Deprecated
- Spider job parameters `failIfFoundUrlsLessThan` and `warnIfFoundUrlsLessThan` in favour of the
`automation.spider.urls.added` statistic test.

## [0.2.0] - 2021-04-12
### Added
- Support for job result data
- Support for passive scan rule configuration

## [0.1.0] - 2021-03-24
### Changed
- Added support for enum parameters.
- Added a new parameter "handleParameters" for the *spider* job.

### Fixed
- A bug where the plan did not stop when it encountered an error or warning and env:parameters:failOnError or env:parameters:failOnWarning was set to true.

## [0.0.1] - 2021-03-09

- First version.

[0.40.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.40.0
[0.39.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.39.0
[0.38.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.38.0
[0.37.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.37.0
[0.36.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.36.0
[0.35.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.35.0
[0.34.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.34.0
[0.33.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.33.0
[0.32.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.32.0
[0.31.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.31.0
[0.30.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.30.0
[0.29.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.29.0
[0.28.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.28.0
[0.27.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.27.0
[0.26.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.26.0
[0.25.1]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.25.1
[0.25.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.25.0
[0.24.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.24.0
[0.23.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.23.0
[0.22.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.22.0
[0.21.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.21.0
[0.20.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.20.0
[0.19.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.19.0
[0.18.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.18.0
[0.17.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.17.0
[0.16.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.16.0
[0.15.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.15.0
[0.14.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.14.0
[0.13.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.13.0
[0.12.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.12.0
[0.11.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.11.0
[0.10.1]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.10.1
[0.10.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.10.0
[0.9.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.9.0
[0.8.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.8.0
[0.7.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.7.0
[0.6.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.6.0
[0.5.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.5.0
[0.4.1]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.4.1
[0.4.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.4.0
[0.3.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.3.0
[0.2.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.2.0
[0.1.0]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.1.0
[0.0.1]: https://github.com/zaproxy/zap-extensions/releases/automation-v0.0.1
