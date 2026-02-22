# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased

### Added
- Basic stats
- Support for Anthropic (Claude).
- Support for Google Gemini.
- Support for OpenAI.
- Support for OpenRouter.
- Integration points for other add-ons.
- Support for logging all LLM comms to a sub-tab of the main Output tab.
- An LLM Chat panel.
- Buttons in the chat panel to append alerts summary and ZAP logs.
- An option to automatically include project context with the first chat message (per session).
- User-approved "actions" to set notes/tags on History entries (for example, when triaging findings).

### Changed
- Chat now maintains recent conversation context for follow-up questions.
- Split the chat input area into separate context and question panes.
- LLM Chat tabs now behave like Requester tabs (plus tab, close button, and rename on double-click).
