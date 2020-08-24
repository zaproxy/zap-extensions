# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
### Changed
- AbstractAppFilePlugin > ensure that test requests are appropriately rebuilt for this type of scan rule (Issue 6129). This will make the following Alpha and Beta active scan rules slightly more accurate:
  - Trace.axd, .env File, .htaccess file

## [1.1.0] - 2020-08-04
### Changed
- AbstractAppFilePlugin > don't raise issues for responses other than 200 - Ok unless at LOW threshold (Issue 6077). This will make the following Alpha and Beta active scan rules slightly less False Positive prone:
  - Trace.axd, .env File, .htaccess file

## [1.0.0] - 2020-05-21

First version.

[1.1.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.1.0
[1.0.0]: https://github.com/zaproxy/zap-extensions/releases/commonlib-v1.0.0
