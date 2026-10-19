# LLM test add-on

Test apps and integration tests for the LLM add-on. The build configures it from its location (`addOns/llm/llmTest`), with
`llmTest.gradle.kts` for any overrides. See the Dev add-on help for how test add-ons work.

## Mock LLM

An OpenAI compatible endpoint, `http://localhost:9091/llm/mock/v1`, which replies using regex rules.
Add an `OpenAI Compatible` provider to the LLM add-on with that endpoint, any model name and no API
key.

The rules are in `llm/mock/rules.json` in the `addOnData/dev/server` directory under the ZAP home. It is a JSON
array of `match` (a case insensitive regex, searched for in the last user message) and `reply`
(a string, or a JSON object which is sent as a string). The first match wins. The file is re-read
on every request.

### Rule sets for other add-ons

An add-on's test add-on can provide its own rules, which do not affect other users of the mock LLM.
A rule set called `name` is used with the endpoint `http://localhost:9091/llm/mock/<name>/v1`, and
an unknown name gets a 404. There are two ways to provide one:

* Include the file `src/main/zapHomeFiles/addOnData/dev/server/llm/mock/<name>/rules.json`, no code needed.
* Get `MockLlmDir` from `ExtensionLlmTest#getMockLlm()` (the test add-on must depend on `llmTest`) and
  call `addRuleSet(name, supplier)`, and `removeRuleSet(name)` when unloaded. A rule set added this
  way takes precedence over a file with the same name.

Rule set names can only contain letters, digits, `_` and `-`. The `example` rule set is an example.

## Integration tests

`src/main/zapHomeFiles/integration-tests/llm/plans/*.yaml` are Automation Framework plans which are
installed with this add-on to `integration-tests/llm/plans` in the ZAP home, for example:

    zap.sh -dev -cmd -autorun <ZAP home>/integration-tests/llm/plans/mock-llm.yaml
