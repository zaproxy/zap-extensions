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
installed with this add-on to `integration-tests/authhelper/plans` in the ZAP home. They need a browser, for example:

    zap.sh -dev -cmd -autorun <ZAP home>/integration-tests/authhelper/plans/ai-auth-multi-step.yaml

* `ai-auth-multi-step.yaml` - LLM assisted authentication against the multi-step login, using the mock LLM.
* `ai-auth-wrong-domain.yaml` - the same, with a rule set that selects the wrong domain; authentication must fail.

The `authhelper-wrong-domain` rule set (`/llm/mock/authhelper-wrong-domain/v1`) selects the wrong domain, and returns `FAILURE` when the login form is shown again.
