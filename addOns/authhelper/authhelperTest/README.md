# Authhelper test add-on

Test apps and integration tests for the Authentication Helper add-on. The build configures it from its
location (`addOns/authhelper/authhelperTest`), see the Dev add-on help for how test add-ons work.
It depends on the LLM test add-on for the mock LLM.

## Multi-step auth

`http://localhost:9091/auth/multi-step-auth/` is a login with 3 steps: username and domain, department,
then password. It only succeeds if the domain `Project1` is selected, so LLM assisted authentication needs
the user hint `The domain pulldown needs to be set to Project1`.

## Mock LLM rule set

`http://localhost:9091/llm/mock/authhelper/v1` replies with the actions needed to complete the multi-step
login, based on the URL in each turn. Add an `OpenAI Compatible` provider to the LLM add-on with that endpoint,
any model name and no API key. The rules are in `llm/mock/authhelper/rules.json` in `addOnData/dev/server`.

## Integration tests

`src/main/zapHomeFiles/integration-tests/authhelper/plans/*.yaml` are Automation Framework plans which are
installed with this add-on to `integration-tests/authhelper/plans` in the ZAP home. The multi-step ones need a browser, for example:

    zap.sh -dev -cmd -autorun <ZAP home>/integration-tests/authhelper/plans/ai-auth-multi-step.yaml

* `ai-auth-multi-step.yaml` - LLM assisted authentication against the multi-step login, using the mock LLM.
* `ai-auth-wrong-domain.yaml` - the same, with a rule set that selects the wrong domain; authentication must fail.

The `authhelper-wrong-domain` rule set (`/llm/mock/authhelper-wrong-domain/v1`) selects the wrong domain, and returns `FAILURE` when the login form is shown again.

### Authentication report

These use the OAuth2 mock server of the Dev add-on (`authserver.oauth2.zap` and `api.oauth2.zap`). 
The token endpoint is on a different host to the target site, and they check the summary of the generated `auth-report-json` 
report with a Graal.js script. 
The report is written next to the plan, and the script finds it from the running plan, so the plans can be run from anywhere:

    zap.sh -dev -cmd -autorun <path to>/oauth2-report-pass.yaml

* `oauth2-report-pass.yaml` - OAuth2 authentication succeeds, the `auth` summary item must have passed.
* `oauth2-report-fail.yaml` - OAuth2 authentication fails (wrong password), the `auth` summary item must have failed.

Both also check that the `session` and `verif` summary items have passed.
