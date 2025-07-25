# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased
### Changed
- Update help with newer JavaScript engine and links.

### Fixed
- Error logs to always include stack trace.

## [45.12.0] - 2025-06-20
### Changed
- Maintenance changes.

### Fixed
- Loop when trying to extract an underlying script exception.

## [45.11.0] - 2025-04-11
### Fixed
- NPE when using scripts with no UI.

## [45.10.0] - 2025-04-09
### Fixed
- NPE when using some scripts after re-installing the scripts add-on.
- Correct error message of the Automation Framework job.
- Templates and Zest scripts were not being shown in the editor (Issue 8922).

### Added
- Standardized Policy Tags to the base Scripts Passive Scanner.

### Changed
- Depends on an updated version of the Common Library add-on.

## [45.9.0] - 2025-03-25
### Fixed
- Remove unnecessary custom parameter handling.

### Changed
- Use the main Output panel for script output.

## [45.8.0] - 2025-01-10
### Added
- Report indirect script errors while the Automation Framework plans are running (Issue 8586).
- Standardized Policy Tags to the base Scripts Active Scanner.

### Changed
- Update minimum ZAP version to 2.16.0.
- Fields with default or missing values are omitted for the `script` job in saved Automation Framework plans.
- Depends on an updated version of the Common Library add-on.
- Depend on Passive Scanner add-on (Issue 7959).

### Fixed
- Correct auto-complete suggestions for parameters of Passive Rules.
- Some script errors were not being propagated to the output correctly.

## [45.7.0] - 2024-10-07
### Fixed
- Reuse script cache for all passive scan threads to avoid recompilation of Passive Rules scripts.
- Address a concurrency issue when using Graal.js Passive Rules scripts as first-class scan rules.
- Handle gracefully the inability to force stop the running standalone script in newer Java versions.

## [45.6.0] - 2024-09-02
### Removed
- Remove the active and passive script templates, superseded by the ones provided by the GraalVM JavaScript add-on.

## [45.5.0] - 2024-07-22
### Added
- Provide the `script` API on newer ZAP versions.

### Fixed
- Handle missing "references" field in the script metadata correctly.

## [45.4.0] - 2024-05-16
### Added
- Support for Automation Framework loaddir action, which loads all of the scripts under the specified directory.

### Changed
- File parameter to `source`, `file` will still work.

## [45.3.0] - 2024-05-07
### Added
- Support for code and help links for script scan rules.

### Changed
- Update minimum ZAP version to 2.15.0.
- Allow to set raw parameter values from Active Rules, by calling `as.setEscapedParam(HttpMessage msg, String param, String value)`.

## [45.2.0] - 2024-04-11
### Added
- Active and Passive Scripts with a `getMetadata()` function are now treated as first-class scan rules (Issue 7105).

### Fixed
- Error when trying to run an unsupported script type through the Automation Framework.
- The "Scripts Passive Scanner" scan rule was being loaded twice.

## [45.1.0] - 2024-03-25
### Added
- Support for menu weights (Issue 8369)

### Fixed
- Propagate script errors to the Automation Framework when running them.

## [45.0.0] - 2024-02-12
### Added
- The scan rule functionality of scripts was moved from the ZAP core to this add-on (Related to Issue 7105).

### Changed
- Maintenance changes.

### Fixed
- The save button was not enabled for new scripts upon creation.

## [44] - 2023-12-19
### Changed
- Rename "Script Console" in the Options panel list to "Console".

### Fixed
- Prevent GUI initialization in daemon mode when installing the add-on.

## [43] - 2023-11-13
### Added
- Allow setting the tab size and whether to use tabs or spaces for indentation in the console.
  The old defaults were to use the tab character with a tab size of 5.
  The new defaults are to use spaces with a tab size of 4.
- A gear button to the console toolbar to open the Script Console options screen.
- An enable / disable script button to the console toolbar to toggle enabling the open script.
- Options to allow editing the font name and size used in the console (Issue 8065).
- The shortcut `ctrl+S` (`cmd+S` on macOS) to save the script in the console.

### Changed
- The "Save Script" button was moved to the console toolbar.

### Fixed
- Saving the script was causing the "Keep or Replace" dialog to show, even when no external changes were made to the script.

## [42] - 2023-10-12
### Changed
- Update minimum ZAP version to 2.14.0.

## [41] - 2023-10-04
### Added
- Allow selecting a default behaviour when a script in the console changes on disk (Issues 5463, 7582). The allowed
  options are "Ask Each Time", "Keep Script", and "Replace Script".

### Changed
- Update extender template scripts to also work with Graal.js engine.

## [40] - 2023-09-11
### Changed
- Allow to select a script node without focusing on it.
- Allow to display script without focusing on it.
- Maintenance changes.
- Depend on newer version of Automation Framework add-on (Related to Issue 7961).

## [39] - 2023-07-11
### Changed
- Update minimum ZAP version to 2.13.0.

## [38] - 2023-03-29
### Fixed
- extender/Copy as curl command menu.js - prevent and warn on local file inclusion when generating the command.
  Thanks to James Kettle (@albinowax) for reporting.

## [37] - 2023-03-18
### Fixed
- Do not require a name if file provided when adding script with automation job.

## [36] - 2023-03-17
### Added
- Support for inline scripts in the Automation Framework.

### Changed
- Maintenance changes.

## [35] - 2023-02-09
### Added
- Help explaining how to interact with Automation Framework plans.
- Support for relative file paths and ones including vars in the Automation Framework job.

### Changed
- Maintenance changes.

## [34] - 2023-01-03
### Fixed
- Prevent exception if no display (Issue 3978).

### Changed
- Maintenance changes.

## [33] - 2022-10-27
### Changed
- Update minimum ZAP version to 2.12.0.

## [32] - 2022-10-12
### Changed
- Maintenance changes.

### Fixed
- Don't print twice to std out when running without view and executing scripts (Issue 7455).

## [31] - 2022-09-23
### Added
- Automation ScriptJob - Enable or Disable any script and run a targeted script (Issue 7025).
- Promoted to Release status.

### Changed
- 'Copy as curl command menu.js' added change that prevents curl from adding User-Agent when no User-Agent should be present.
- Maintenance changes.

## [30] - 2022-02-25
### Added
- Automation ScriptJob - Add or remove any script and run a standalone script

### Changed
- Update minimum ZAP version to 2.11.1.
- Maintenance changes.

## [29] - 2021-10-06
### Added
- Allow to choose Kotlin for syntax highlighting.

### Changed
- Do not show `Null` script engine in Edit Script dialogue.
- Now using 2.10 logging infrastructure (Log4j 2.x).
- Update links to zaproxy and community-scripts repo.
- Maintenance Changes.
- 'Copy as curl command menu.js' is now preceded by a separator, and the Title Caps of the menu item were fixed (Issue 2000).
- 'Copy as curl command menu.js' is now available in safe mode.
- Update minimum ZAP version to 2.11.0.

## [28] - 2020-12-18

### Fixed
 - GUI could hang when lots of print statements are used.

## [27] - 2020-12-15
### Changed
- Update minimum ZAP version to 2.10.0.
- Tweak help content.
- Show script engine when editing the script.
- Fixed case where script print statements could deadlock ZAP.
- Maintenance changes.
- Support dark mode and dynamic Look and Feel switching

### Fixed
 - Terminology
 - Do not show the Enable/Disable Script menu item if the script can't be enabled/disabled, in some
 look and feels it could show an empty menu item (Issue 6256).

## [26] - 2020-01-17
### Added
- Add repo URL.

### Changed
- Update minimum ZAP version to 2.8.0.
- Update help to mention custom script/global variables (Issue 3402).
- Move empty template entry to the top, for consistency with other fields in New Script dialogue.
- Save cursor position when switching between scripts.
- Change info URL to link to the site.
- Provide information on how to create scripts from templates (Issue 5746).

### Fixed
- Fix links in script templates.

## [25] - 2019-06-07

- Fix typo in help page.
- Execute Targeted scripts in other thread than GUI thread.
- Clear highlighting syntax when a non-script node is selected.
- Warn of script changed by another program (post 2.7.0).
- Script console is disabled if script size > 1MB and highlight behavior is disabled if script size > 0.5MB.
- Allow to select the file path in the Edit Script dialogue.
- Allow to add selection listener to Scripts tree.

## 24 - 2018-01-25

- Fix GUI freeze on script addition/removal through the API (Issue 4302).
- Prompt for a charset when failed to read the script file (Issue 3383).

## 23 - 2018-01-19

- Correct extender script, Add history record menu.js, to show the info dialogue.
- Invoke script on selected message(s) (Issue 4085).
- Update extender scripts to use just Nashorn (Java 8).
- Do not show empty choice when the script engine requires a template.
- Confirm overwrite of existing script file.
- Support 'external' scripts.

## 22 - 2017-11-27

- Updated for 2.7.0.

## 21 - 2017-11-24

- Show script types in alphabetical order in dialogues New and Load Script.
- Fix an exception when installing extender scripts with errors.
- Correct state of Enabled checkbox when creating a script from templates.
- Allow to enable code folding in script text area.

## 20 - 2017-10-27

- Added extender script type and examples.

## 19 - 2017-10-13

- Code changes for Java 9 (Issue 2602).
- Inform when the script contains invalid char sequences (related to Issue 3377).
- Invoke Scripts tree context menu once.
- Title caps adjustments (related to Issue 2000).
- Allow to configure the enabled state of new/loaded scripts (Issue 2996).
- Use selected font in script text area.
- Fix UI hang when installing/uninstalling script engines (Issue 3945).
- Support basic auto-completion

## 18 - 2017-04-03

- Remove unused resource messages (Issue 2386).
- Update help page to mention HTTP Sender scripts.
- Allow to save scripts through the context menu.
- Reset Console Output panel on session changes.
- If there is only one script engine available, make it the default when creating a new script.

## 17 - 2016-09-07

- Discard undoable edits after setting a script (Issue 2675).

## 16 - 2016-06-02

- Fix exceptions when installing/uninstalling script engines, with no script selected.

## 15 - 2015-08-23

- Issue 1653: Support context menu key for trees.
- Updated add-on's info URL.

## 14 - 2015-04-13

- Make sure all script engines are shown when creating a script from type (Issue 1503).
- Warn about missing script engines (Issue 1504).
- Unload all components when uninstalling (Issue 1507).
- Updated for ZAP 2.4

## 13 - 2014-09-10

- Issue 1327: Support drag and drop in the scripts tree.
- Issue 1330: Add menu for duplicating a script.
- Issue 1278: Safe menu items not available in protected and safe modes.

## 12 - 2014-05-21

- Disabled "Word Wrap" by default to avoid scrolling performance degradation due to long lines (Issue 1160).

## 11 - 2014-04-10

- Updated to use the latest core changes, other minor code changes (Issues 609, 1085, 1104 and 1105).
- Fixed an InvalidParameterException during add-on uninstallation (Issue 967).
- Changed help file structure to support internationalisation (Issue 981).
- Fixed inconsistencies in run/stop buttons (Issue 1023).
- Fixed a NullPointerException (Issue 1025).
- Added content-type to help pages (Issue 1080).
- Changed to allow to clear the output panel even if "clear on run" is enabled (Issue 1103).
- Updated add-on dir structure (Issue 1113).

## 10 - 2013-12-17

- Changed to add an output console toolbar, depend on core ExtensionScript to avoid NullPointerException (Issue 847)

## 9 - 2013-09-11

- Moved script support into the core and added targeted scripts

## 7 - 2013-05-27

- Updated language files.

## 6 - 2013-05-13

- Changed to unload all components when uninstalling.
- Changed to use the new version of the RSyntaxTextArea library.

## 5 - 2013-01-21

- Updated language files

## 4 - 2013-01-17

- Updated to support new addon format

## 3 - 2012-11-23



[45.12.0]: https://github.com/zaproxy/zap-extensions/releases/scripts-v45.12.0
[45.11.0]: https://github.com/zaproxy/zap-extensions/releases/scripts-v45.11.0
[45.10.0]: https://github.com/zaproxy/zap-extensions/releases/scripts-v45.10.0
[45.9.0]: https://github.com/zaproxy/zap-extensions/releases/scripts-v45.9.0
[45.8.0]: https://github.com/zaproxy/zap-extensions/releases/scripts-v45.8.0
[45.7.0]: https://github.com/zaproxy/zap-extensions/releases/scripts-v45.7.0
[45.6.0]: https://github.com/zaproxy/zap-extensions/releases/scripts-v45.6.0
[45.5.0]: https://github.com/zaproxy/zap-extensions/releases/scripts-v45.5.0
[45.4.0]: https://github.com/zaproxy/zap-extensions/releases/scripts-v45.4.0
[45.3.0]: https://github.com/zaproxy/zap-extensions/releases/scripts-v45.3.0
[45.2.0]: https://github.com/zaproxy/zap-extensions/releases/scripts-v45.2.0
[45.1.0]: https://github.com/zaproxy/zap-extensions/releases/scripts-v45.1.0
[45.0.0]: https://github.com/zaproxy/zap-extensions/releases/scripts-v45.0.0
[44]: https://github.com/zaproxy/zap-extensions/releases/scripts-v44
[43]: https://github.com/zaproxy/zap-extensions/releases/scripts-v43
[42]: https://github.com/zaproxy/zap-extensions/releases/scripts-v42
[41]: https://github.com/zaproxy/zap-extensions/releases/scripts-v41
[40]: https://github.com/zaproxy/zap-extensions/releases/scripts-v40
[39]: https://github.com/zaproxy/zap-extensions/releases/scripts-v39
[38]: https://github.com/zaproxy/zap-extensions/releases/scripts-v38
[37]: https://github.com/zaproxy/zap-extensions/releases/scripts-v37
[36]: https://github.com/zaproxy/zap-extensions/releases/scripts-v36
[35]: https://github.com/zaproxy/zap-extensions/releases/scripts-v35
[34]: https://github.com/zaproxy/zap-extensions/releases/scripts-v34
[33]: https://github.com/zaproxy/zap-extensions/releases/scripts-v33
[32]: https://github.com/zaproxy/zap-extensions/releases/scripts-v32
[31]: https://github.com/zaproxy/zap-extensions/releases/scripts-v31
[30]: https://github.com/zaproxy/zap-extensions/releases/scripts-v30
[29]: https://github.com/zaproxy/zap-extensions/releases/scripts-v29
[28]: https://github.com/zaproxy/zap-extensions/releases/scripts-v28
[27]: https://github.com/zaproxy/zap-extensions/releases/scripts-v27
[26]: https://github.com/zaproxy/zap-extensions/releases/scripts-v26
[25]: https://github.com/zaproxy/zap-extensions/releases/scripts-v25
