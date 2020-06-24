# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased
### Changed
- Update minimum ZAP version to 2.9.0.
- Tweak help content.
- Show script engine when editing the script.

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



[26]: https://github.com/zaproxy/zap-extensions/releases/scripts-v26
[25]: https://github.com/zaproxy/zap-extensions/releases/scripts-v25
