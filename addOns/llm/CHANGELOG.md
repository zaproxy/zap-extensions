# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased
### Fixed
- Use ZAP's networking instead of Java's when importing OpenAPI definitions from URLs (Issue 8987).

## [0.1.0] - 2026-10-15
### Added
- Automation Framework support, the `llm-config` job configures the LLM providers.

### Changed
- Update dependencies.

## [0.0.1] - 2026-08-07

### Added
- Basic stats
- Support for Ollama, Azure OpenAI, Google Gemini, Claude (Anthropic), and OpenAI Compatible endpoints.
- Integration points for other add-ons.
- A tabbed LLM Chat panel.
- Integration with the MCP add-on.

[0.1.0]: https://github.com/zaproxy/zap-extensions/releases/llm-v0.1.0
[0.0.1]: https://github.com/zaproxy/zap-extensions/releases/llm-v0.0.1
