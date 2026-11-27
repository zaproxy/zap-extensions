# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## 2026-11-16
### Added
- Test apps moved from the Dev add-on: the simple OpenAPI specs, one unauthenticated (`/api/openapi/simple-unauth`) and one with an authenticated endpoint (`/api/openapi/simple-auth`).
- Automation Framework plans which test importing the unauthenticated and authenticated OpenAPI definitions.
- Fixed the path of the endpoint in the unauthenticated definition and added a GET operation to it.
- Automation Framework plan which tests importing the authenticated OpenAPI definition with invalid credentials, and generates an authentication report.
- A simple OpenAPI test app (`/api/openapi/simple-token`) with an endpoint protected by a fixed security token in a header, and an Automation Framework plan which imports it using manual authentication and a replacer rule.
- Automation Framework plan which imports the token protected OpenAPI definition with a wrong token, and checks the authentication report fails.
- A simple OpenAPI test app (`/api/openapi/simple-oauth2`) with an endpoint protected by OAuth2 (password grant), and Automation Framework plans which import it with valid and invalid credentials.
