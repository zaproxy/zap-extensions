# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
### Added
- Server certificates management on newer ZAP versions.
- Handle command line arguments `-certload`, `-certpubdump`, and `-certfulldump` on newer ZAP versions.
- Options panel to manage the root CA certificate and issued certificates on newer ZAP versions.
- API endpoints to generate, import, obtain, and to configure the validity of the root CA
certificate and issued certificates (Issue 4673).
