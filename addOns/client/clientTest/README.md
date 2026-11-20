# Client test add-on

Test apps and integration tests for the Client add-on. The build configures it from its location
(`addOns/client/clientTest`), see the Dev add-on help for how test add-ons work.

## Slow loading page

`http://localhost:9091/client/slow-load/` has a page, `page`, which only responds after the delay given
by the `delay` parameter in milliseconds (default 3000, maximum 30000). A browser which does not wait
for page loads, for example with the `none` page load strategy, returns from the navigation straight
away. It is still on the initial page (`about:home` or `about:blank`) until the page has loaded, and in
Firefox `localStorage` is not usable there.

## Launch check

`org.zaproxy.addon.clienttest.LaunchCheck.check(browserId, pageLoadStrategy, slowPageUrl)` launches a
browser the way the Client Spider does, with the given page load strategy, and checks that the ZAP
browser extension was configured by the launch. It throws if it was not, and otherwise returns a report.
If given the URL of the slow page it also loads it, and reports the URL and the state of `localStorage`
when the navigation returned.

## Integration tests

`src/main/zapHomeFiles/integration-tests/client/plans/*.yaml` are Automation Framework plans which are
installed with this add-on to `integration-tests/client/plans` in the ZAP home. They need the Automation
Framework and Graal.js add-ons, a Firefox browser, and ZAP to be run in dev mode, for example:

    zap.sh -dev -cmd -autorun <ZAP home>/integration-tests/client/plans/firefox-callback-none.yaml

* `firefox-callback-none.yaml` - launches Firefox with the `none` page load strategy. The launch must
  configure the ZAP browser extension, so the Client add-on has to wait for the callback page to load. It
  used to fail with `The command does not support browsing contexts in privileged scope`, from
  `RedirectScript.browserLaunched`, which wrote to `localStorage` while the browser was still on its
  initial page.
* `firefox-callback-normal.yaml` - the control, the same launch with the `normal` strategy, which waits
  for the callback page.
