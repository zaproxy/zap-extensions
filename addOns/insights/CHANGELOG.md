# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased
### Added
- Report data now exposes `stoppedByInsights` and `stoppingInsight` so pipelines can detect Insights-driven stops from the report alone.

### Changed
- The Automation Framework stop message now identifies the triggering insight (key, reason, site, value) instead of a generic string. The same details are appended to the daemon-mode exit reason so headless pipelines can see which insight stopped the scan.

## [0.4.0] - 2026-04-23
### Changed
- Elevated insight.auth.failure from Medium to High severity so that exitAutoOnHigh can stop scans with persistent auth failures.
- Reduced minimum auth request threshold from 10 to 5 to detect browser-based auth failures earlier.

## [0.3.0] - 2026-03-31
### Fixed
- Correct check of memory usage.

## [0.2.0] - 2026-03-02
### Fixed
- Do not attempt to prompt when exiting on high insight and headless.

## [0.1.0] - 2025-12-31
### Fixed
- Address concurrency issue while generating report with insights.

## [0.0.1] - 2025-12-15

- First version.

[0.4.0]: https://github.com/zaproxy/zap-extensions/releases/insights-v0.4.0
[0.3.0]: https://github.com/zaproxy/zap-extensions/releases/insights-v0.3.0
[0.2.0]: https://github.com/zaproxy/zap-extensions/releases/insights-v0.2.0
[0.1.0]: https://github.com/zaproxy/zap-extensions/releases/insights-v0.1.0
[0.0.1]: https://github.com/zaproxy/zap-extensions/releases/insights-v0.0.1
