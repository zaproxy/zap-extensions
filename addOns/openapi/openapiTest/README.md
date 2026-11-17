# OpenAPI test add-on

Test apps and integration tests for the OpenAPI Support add-on. The build configures it from its
location (`addOns/openapi/openapiTest`), see the Dev add-on help for how test add-ons work.

## Test apps

Served by the Dev add-on's test server (by default `http://localhost:9091`):

* `/api/openapi/simple-unauth/` - a simple OpenAPI spec, with no authentication.
* `/api/openapi/simple-token/` - a simple OpenAPI spec, the spec is unauthenticated but the endpoint it describes needs the fixed header `X-Security-Token: zap-test-security-token`.
* `/api/openapi/simple-oauth2/` - a simple OpenAPI spec, the spec is unauthenticated but the endpoint it describes needs a bearer token from the `token` endpoint (OAuth2 password grant, client `test-client` / `test-secret`, user `test@test.com` / `password123`).
* `/api/openapi/simple-auth/` - a simple OpenAPI spec, the spec is unauthenticated but the endpoint it describes needs a valid token from the login endpoint.

## Integration tests

`src/main/zapHomeFiles/integration-tests/openapi/plans/*.yaml` are Automation Framework plans which are
installed with this add-on to `integration-tests/openapi/plans` in the ZAP home. Run them in dev mode, for example:

    zap.sh -dev -cmd -autorun <ZAP home>/integration-tests/openapi/plans/import-unauth.yaml

* `import-unauth.yaml` - imports the unauthenticated definition and checks its GET endpoint is in the Sites tree.
* `import-auth.yaml` - logs in as the test user, imports the authenticated definition as that user and checks its endpoint is in the Sites tree and the request made by the import succeeded (200 rather than 403).
* `import-auth-fail.yaml` - the same with the wrong password: authentication fails, so the import's request is forbidden (403) and the diagnostics job records the attempt, and an `auth-report-json` authentication report is generated and checked (the `auth` summary item must have failed).
* `import-token.yaml` - imports the definition of the token protected app, using manual authentication with a replacer rule which adds the security token header and verification regexes. The diagnostics job records the requests and an `auth-report-json` authentication report is generated.
* `import-token-fail.yaml` - the same with the wrong token: the import's request is forbidden (403) and the generated authentication report is checked (2 responses received, no connection failures, and the 2 requests recorded by the diagnostics job).
* `import-oauth2.yaml` - imports the definition of the OAuth2 protected app as a user authenticated with the OAuth2 method (password grant) and checks the endpoint is in the Sites tree and the request succeeded (200 rather than 401).
* `import-oauth2-fail.yaml` - the same with the wrong password, using the OAuth2 method diagnostics: the import's request is unauthorized (401) and the generated authentication report is checked (the `auth` summary item must have failed).
