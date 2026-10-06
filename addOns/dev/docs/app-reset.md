# Plan for Resetting Test Apps

Date: 2026/10/06

Model: Claude / Sonnet 5.5

---

## Summary

The dev add-on's test apps kept their state (issued tokens, cookies, counters) for as long as ZAP was
running, so a later session or Automation Framework (AF) plan was affected by an earlier one. Three
things changed:

1. **State is reset when the ZAP session changes.**
2. **The OAuth2 mock domains are served by the dev server**, not by a response listener, so ZAP sees
   the mock's real responses.
3. **The OAuth2 mock has more test-only token request params.**

Two smaller fixes are included: a double-escaped URL, and CSRF pages that were never reset.

## 1. Resetting state

**Why:** a plan that needed "the first token request succeeds, later ones fail" (`fail_after`) failed
on its first request when another plan had run earlier in the same ZAP process. The tokens and counts
were in `OAuth2RootDir`, which lives as long as the add-on.

**How:**

- `TestNode` (new, abstract) is the base class of `TestDirectory` and `TestPage`. It holds what they
  share (`name`, `server`, `parent`) and a registry of state.
- A node registers its state where it creates it:
  `private final Set<String> tokens = state(new HashSet<>());` for collections and maps, and
  `onReset(() -> field = null)` for anything else.
- `TestNode.reset()` clears the registered state. `TestDirectory.reset()` also resets its sub
  directories and pages.
- `ExtensionDev` has a `SessionChangedListener` (`ResetTestAppsOnSessionChange`) which calls
  `TestProxyServer.reset()`, so everything is reset on a session change. It also fires at startup,
  which does nothing as the state is empty.

**State that is registered:** `TestAuthDirectory.sessions` (so all the auth apps), the tokens and
cookies of the SSO1, SSO2, SSO-MS, SSO-MS popup, UUID login, JSON multiple cookies and diff cookies
apps, all of `OAuth2RootDir`'s maps, `SequencePage.seqMap` and `BasicCsrfPage.csrfToken`.

**Not reset, on purpose:** settings, for example the static options of `SequencePage` and `SimpleDir`'s
page and link counts (it has its own manual reset).

**Adding a new app:** if it keeps state while running, create it with `state(...)` or `onReset(...)`.
Nothing else is needed. Do not register settings.

## 2. Serving the OAuth2 mock domains from the dev server

**Why:** ZAP's `HttpSenderParos.sendAuthenticated` sends a request made as a user, asks the
verification method if the response looks authenticated, and if not authenticates again and sends the
request again. The old mocks (`addDomainListener`) did not answer the request: it was redirected to the
dev server, which returned a `404`, and the mock's response was put in place by a response listener
*after* that check. ZAP therefore checked the 404 (recorded as `stats.auth.state.unknown`), and a mock
`401` never caused a re-authentication or a retry. This is why re-authentication could not be tested.

**How:**

- `DomainHandler` (new): `void handle(HttpMessage msg)` sets the response for a request to a fake
  domain.
- `TestProxyServer.addDomainHandler(domain, handler)` registers it. `AltDomainListener` still
  redirects the request to the dev server and adds the `zap-dev-sso` header with the original (escaped)
  URL. `TestProxyServer.TestListener` uses that header to find the handler, restores the original URI
  and `Host` on the server's copy of the message, and calls it. If the handler sets no response the
  result is a `404`, and if it throws a `500`.
- `OAuth2RootDir` uses it for `authserver.oauth2.zap`, `api.oauth2.zap` and `app.oauth2.zap`
  (`handleAuthServerRequest`, `handleUserInfo`, `handleAppRequest`). Their logic did not change.
- The other domain mocks (SSO1, SSO2, SSO-MS, the popup, UUID login) still use `addDomainListener`, so
  they still have the blind spot. Moving one is mechanical: turn its `onHttpResponseReceive` body into a
  `DomainHandler`.

**Consequence:** a retried request is the same `HttpMessage`, so ZAP's History has one entry for it,
with the retry's response and `Authorization` header, after the new token request(s).

## 3. OAuth2 mock test params

Sent as form params with the token request, for example via the `oauth2` method's `extraTokenParams`.
Documented in the javadoc of `OAuth2RootDir`.

| Param | Effect |
|---|---|
| `expires_in`, `require_client_auth_method`, `simulate_error`, `field_style` | Already existed. |
| `refresh_error` | `invalid_grant`: a `refresh_token` grant is rejected (400) and its token used up. `server_error`: it fails with a 500, the token is still valid. Other grants are not affected. |
| `revoke_refreshed` | `true`, or a number N: the access tokens from `refresh_token` grants (all, or the first N per client) are reported as issued but rejected by the API. |
| `fail_after` | After N tokens were issued to a client every token request fails with a 500. |
| `omit_expires_in` | `true` leaves `expires_in` out of the token response, though the token still expires. |

They exist to test how the authhelper add-on refreshes OAuth2 tokens and re-authenticates, which the real
servers it is used with can not be told to do on demand.

## Fixes made on the way

- `AltDomainListener` and the new dispatch parsed the escaped URL in the `zap-dev-sso` header with
  `new URI(url, false)`, which double escapes it (`%3A` became `%253A`). Query params then did not match,
  for example the `/authorize` page returned an error, and the URL restored on History entries was
  wrong. Use `new URI(url, true)`.
- `BasicCsrfSubDir.getPage()` returns its own page, which was never added to the directory's pages, so
  reset never reached it and an old CSRF token was still accepted. It is now added with `addPage`.

## Decisions and rejected alternatives

- **No reflection in the tests.** An earlier approach was a test that used reflection to find every
  collection in every app and check `reset()` emptied it. It was replaced by the registry. The cost,
  accepted, is that a collection which is created without `state(...)` is not detected. It will show up
  when the app is used in tests, as its state would carry over.
- **Common base class (`TestNode`)**, not a helper used by both, as it also removes the duplicated
  `name`/`server`/`parent` code.
- **OAuth2 only** for the move to domain handlers, to limit the scope.
- **Per-app tests** were dropped where they only repeated `TestNodeUnitTest`. Behavioural tests are used
  where the state has an observable effect, such as the CSRF token.

## Verification

- Unit tests: `TestNodeUnitTest` (registry, reset, recursion), `TestProxyServerUnitTest` (dispatch,
  escaped query params, 404 and 500 fallbacks), `BasicCsrfDirUnitTest`, and additions to
  `OAuth2RootDirUnitTest` (handlers, each test param, reset).
- Run in a real ZAP in dev mode, with AF plans (in the zaproxy repo,
  `docker/integration_tests/configs/plans`) written to test OAuth2 token refresh in authhelper: the
  re-authentication and retry on a `401`, and the reset between sessions with a script calling
  `newSession()`. The full `authorization_code` + PKCE flow was checked over HTTP.

## Gotchas

- A running ZAP owns the dev test port (default `9091`). A second ZAP fails to start its dev server
  (`WARN TestProxyServer - An error occurred while starting the server`) and its requests go to the
  first one. Use `-config dev.testPort=<port>`.
- Plans run in one ZAP process share the apps' state until the session changes, so start a new session
  between them.

## Not covered

- The `authorization_code` flow in a real browser, only over HTTP.
- Partially unregistered state, see above.
- `reset()` does not lock, so a request being handled while the session changes could see state
  disappear. Acceptable for a test app.

## Related work

- The authhelper add-on's OAuth2 token refresh and re-authentication. It is tested with the params in
  section 3, and relies on the handlers in section 2 so that ZAP sees the `401`s.
