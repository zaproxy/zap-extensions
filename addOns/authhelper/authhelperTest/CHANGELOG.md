# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## 2026-10-21
### Added
- A multi-step login test app (`/auth/multi-step-auth`) for the LLM assisted authentication.
- A mock LLM rule set (`/llm/mock/authhelper/v1`) which completes the multi-step login.
- A mock LLM rule set (`/llm/mock/authhelper-wrong-domain/v1`) which selects the wrong domain, for a failing login.
- Automation Framework plans which test LLM assisted authentication succeeds and fails with the above.
