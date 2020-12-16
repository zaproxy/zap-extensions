# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased


## [13.1.0] - 2020-12-15
### Changed
- Maintenance changes.
- Prevent adding null fuzz handlers, which would cause exceptions when selecting the fuzz message.
- Update minimum ZAP version to 2.10.0.

## [13.0.1] - 2020-09-08
### Fixed
 - Fix exception when saving the options with no default category selected (Issue 6136).

## [13.0.0] - 2020-08-17
### Added
 - Allow to add fuzz specific message components and views to fuzzer dialogue.

### Fixed
 - Correctly handle other HTTP message locations.
 - Fixed error when missing getRequiredParamsNames and getOptionalParamsNames
 
### Changed
- Update minimum ZAP version to 2.9.0.
- Use semantic versioning.
- Maintenance changes.

## [12] - 2020-01-17
### Added
- Add repo URL.

### Changed
- Change info URL to link to the site.

## [11] - 2019-06-07

- Enable the extensions for all DB types.
- Use Monospaced font in payload text areas.
- Possibility to enforce a random order in the RegexPayloadGenerator.
- Make the default step in the Numberzz generator one.
- Add json fuzzer.
- Add parameters to Fuzzer HTTP Processor script.

## 10 - 2017-11-27

- Updated for 2.7.0.

## 9 - 2017-11-24

- Code changes for Java 9 (Issue 2602).
- Ignore empty payloads when highlighting or detecting reflections.
- Contains new number generator payload.
- Add null/empty payload generator.
- Issue 3557: Backport export changes.
- Set fuzzer script types enabled by default (Issue 2997).
- Add description to script types.

## 8 - 2017-04-03

- Show help button in fuzzer dialogues.
- Correct method name in HTTP processor JavaScript template.
- Fix exception when adding file fuzzers with selected empty "Custom Fuzzers".
- Fix typos in the help pages.
- Automatically add Anti-CSRF Token Refresher, if available.
- Render custom states, always (Issue 3166).

## 7 - 2016-09-05

- Fix exception during the unload of the add-on, when in daemon mode.
- Update Content-Length for all request methods, not just POST (Issue 2766).

## 6 - 2016-07-14

- Added Export button to export results as CSV file.
- Enable "Limit maximum errors" by default and increase the default number.
- Improve error handling when reading/writing files from/to fuzzers directory.
- Add SHA-512 Hash payload processor (Issue 2643).
- Allow to search the fuzzer file names when selecting them.

## 5 - 2016-06-02

- Fix modification of file and file fuzzers in Windows.
- Correctly inform when the fuzzers directory is not writable.

## 4 - 2015-12-04

- Add HTTP processor for tagging fuzz results.
- Fix an error that prevented the use of empty strings as payloads (Issue 1948).
- Fix exception while closing ZAP with running fuzz processes.
- Show the correct Payload Generator script when showing modify dialogue.
- Correctly use the number of payloads from script for calculation of progress (Issue 1881).
- Show the number of payloads from the script in Fuzzer dialogue (Issue 1887).
- Improve memory usage (Issue 2051).
- Correct the delay used when sending messages.
- Improve stop time.
- Fix (potential) thread leak after stopping a paused fuzzer.
- Allow to preview payloads generated or from external sources (Issue 1896)
- Fix the location where the characters are added in expand payload processor.
- Allow to modify the selected Payload Processor script.
- Show current payloads when adding/modifying processors (Issue 1898).
- Allow to preview processing of payloads (Issue 1931).
- Allow to save (to file) String, Regex, File and Script payloads (Issue 1932).
- Fix issues in generation of payloads from regular expressions (Issue 1884).
- Add support for regex repetitions (Issue 1885).
- Allow to modify the payloads of File and File Fuzzers (Issue 1897).
- Show the correct Fuzzer HTTP Processor script when showing modify dialogue.

## 3 - 2015-09-07

- Update add-on's info URL.

## 2 - 2015-08-23

- Fix the help button in the Fuzzer dialogue and broken link in Fuzzer dialogue help page.
- Properly load the 'Fuzzer HTTP Processor' templates.
- Keep focus on results table, even if there's a payload reflection in the response (Issue 1442).
- Update POST request's Content-Length by default.
- Remove status icon when uninstalling.
- Fuzzers can't be expanded on OS X (Issue 1677)
- Other code changes.

## 1 - 2015-04-13

- First version.

[13.1.0]: https://github.com/zaproxy/zap-extensions/releases/fuzz-v13.1.0
[13.0.1]: https://github.com/zaproxy/zap-extensions/releases/fuzz-v13.0.1
[13.0.0]: https://github.com/zaproxy/zap-extensions/releases/fuzz-v13.0.0
[12]: https://github.com/zaproxy/zap-extensions/releases/fuzz-v12
[11]: https://github.com/zaproxy/zap-extensions/releases/fuzz-v11
