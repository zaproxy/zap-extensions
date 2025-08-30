/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.addon.automation.jobs;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

import com.fasterxml.jackson.core.JsonProcessingException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractPlugin;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.parosproxy.paros.core.scanner.PluginFactory;
import org.parosproxy.paros.core.scanner.PluginFactoryTestHelper;
import org.parosproxy.paros.core.scanner.PluginTestHelper;
import org.yaml.snakeyaml.Yaml;
import org.zaproxy.addon.automation.AutomationPlan;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.jobs.PolicyDefinition.AlertTagRuleConfig;
import org.zaproxy.addon.automation.jobs.PolicyDefinition.Rule;
import org.zaproxy.zap.extension.ascan.ScanPolicy;
import org.zaproxy.zap.utils.I18N;

class PolicyDefinitionUnitTest {

    private PolicyDefinition policyDefinition;

    private static MockedStatic<CommandLine> mockedCmdLine;
    private static AbstractPlugin plugin;

    @TempDir static Path tempDir;

    @BeforeAll
    static void init() throws IOException {
        mockedCmdLine = Mockito.mockStatic(CommandLine.class);

        Constant.setZapHome(
                Files.createDirectory(tempDir.resolve("home")).toAbsolutePath().toString());

        PluginFactoryTestHelper.init();
        plugin = new PluginTestHelper();
        PluginFactory.loadedPlugin(plugin);
    }

    @AfterAll
    static void close() {
        mockedCmdLine.close();

        if (plugin != null) {
            PluginFactory.unloadedPlugin(plugin);
        }
    }

    @BeforeEach
    void setUp() throws Exception {
        Constant.messages = new I18N(Locale.ENGLISH);
        policyDefinition = new PolicyDefinition();
    }

    @Test
    void shouldSetDefaultStrength() {
        // Given / When
        policyDefinition.setDefaultStrength("test");

        // Then
        assertThat(policyDefinition.getDefaultStrength(), is(equalTo("test")));
    }

    @Test
    void shouldSetDefaultThreshold() {
        // Given / When
        policyDefinition.setDefaultThreshold("test");

        // Then
        assertThat(policyDefinition.getDefaultThreshold(), is(equalTo("test")));
    }

    @Test
    void shouldDefaultToNoRules() {
        // Given / When / Then
        assertThat(policyDefinition.getRules().size(), is(equalTo(0)));
    }

    @Test
    void shouldSetRulesRules() {
        // Given
        List<Rule> rules = List.of(new Rule(1, "testrule", "low", "medium"));

        // When
        policyDefinition.setRules(rules);

        // Then
        assertThat(policyDefinition.getRules().size(), is(equalTo(1)));
        assertThat(policyDefinition.getRules().get(0).getId(), is(equalTo(1)));
        assertThat(policyDefinition.getRules().get(0).getName(), is(equalTo("testrule")));
    }

    @Test
    void shouldAddARule() {
        // Given
        Rule rule = new Rule(1, "testrule", "low", "medium");

        // When
        policyDefinition.addRule(rule);

        // Then
        assertThat(policyDefinition.getRules().size(), is(equalTo(1)));
        assertThat(policyDefinition.getRules().get(0).getId(), is(equalTo(1)));
        assertThat(policyDefinition.getRules().get(0).getName(), is(equalTo("testrule")));
    }

    @Test
    void shouldRemoveRule() {
        // Given
        Rule rule1 = new Rule(1, "testrule1", "low", "medium");
        Rule rule2 = new Rule(2, "testrule2", "low", "medium");
        Rule rule3 = new Rule(3, "testrule3", "low", "medium");

        policyDefinition.addRule(rule1);
        policyDefinition.addRule(rule2);
        policyDefinition.addRule(rule3);

        // When
        policyDefinition.removeRule(rule1);
        policyDefinition.removeRule(rule2);

        // Then
        assertThat(policyDefinition.getRules().size(), is(equalTo(1)));
        assertThat(policyDefinition.getRules().get(0).getId(), is(equalTo(3)));
        assertThat(policyDefinition.getRules().get(0).getName(), is(equalTo("testrule3")));
    }

    @Test
    void shouldSetRuleFields() {
        // Given
        Rule rule = new Rule();

        // When
        rule.setId(2);
        rule.setName("test");
        rule.setStrength("strength");
        rule.setThreshold("threshold");

        // Then
        assertThat(rule.getId(), is(equalTo(2)));
        assertThat(rule.getName(), is(equalTo("test")));
        assertThat(rule.getStrength(), is(equalTo("strength")));
        assertThat(rule.getThreshold(), is(equalTo("threshold")));
    }

    @Test
    void shouldParseValidDefinition() {
        // Given
        String yamlStr =
                "  defaultStrength: low\n"
                        + "  defaultThreshold: 'off'\n"
                        + "  rules:\n"
                        + "  - id: 50000\n"
                        + "    name: rule1\n"
                        + "    strength: insane\n"
                        + "    threshold: high";
        AutomationProgress progress = new AutomationProgress();
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);

        // When
        policyDefinition.parsePolicyDefinition(data, "test", progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(policyDefinition.getDefaultStrength(), is(equalTo("low")));
        assertThat(policyDefinition.getDefaultThreshold(), is(equalTo("off")));
        assertThat(policyDefinition.getRules().size(), is(equalTo(1)));
        assertThat(policyDefinition.getRules().get(0).getId(), is(equalTo(50000)));
        assertThat(policyDefinition.getRules().get(0).getName(), is(equalTo("PluginTestHelper")));
        assertThat(policyDefinition.getRules().get(0).getStrength(), is(equalTo("insane")));
        assertThat(policyDefinition.getRules().get(0).getThreshold(), is(equalTo("high")));
    }

    @Test
    void shouldWarnIfUnknownRule() {
        // Given
        String yamlStr =
                "  defaultStrength: low\n"
                        + "  defaultThreshold: 'off'\n"
                        + "  rules:\n"
                        + "  - id: 50000\n"
                        + "    name: rule1\n"
                        + "    strength: insane\n"
                        + "    threshold: high\n"
                        + "  - id: 1\n"
                        + "    name: unknownrule\n"
                        + "    strength: medium\n"
                        + "    threshold: low";
        AutomationProgress progress = new AutomationProgress();
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);

        // When
        policyDefinition.parsePolicyDefinition(data, "test", progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.getWarnings().size(), is(equalTo(1)));
        assertThat(
                progress.getWarnings().get(0),
                is(equalTo("!automation.error.ascan.rule.unknown!")));
        assertThat(policyDefinition.getDefaultStrength(), is(equalTo("low")));
        assertThat(policyDefinition.getDefaultThreshold(), is(equalTo("off")));
        assertThat(policyDefinition.getRules().size(), is(equalTo(1)));
        assertThat(policyDefinition.getRules().get(0).getId(), is(equalTo(50000)));
        assertThat(policyDefinition.getRules().get(0).getName(), is(equalTo("PluginTestHelper")));
        assertThat(policyDefinition.getRules().get(0).getStrength(), is(equalTo("insane")));
        assertThat(policyDefinition.getRules().get(0).getThreshold(), is(equalTo("high")));
    }

    @Test
    void shouldWarnIfDefnNotList() {
        // Given
        String yamlStr = "Not a list";
        AutomationProgress progress = new AutomationProgress();
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);

        // When
        policyDefinition.parsePolicyDefinition(data, "test", progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.getWarnings().size(), is(equalTo(1)));
        assertThat(
                progress.getWarnings().get(0), is(equalTo("!automation.error.options.badlist!")));
    }

    @Test
    void shouldWarnIfRulesNotList() {
        // Given
        String yamlStr =
                "  defaultStrength: low\n" + "  defaultThreshold: 'off'\n" + "  rules: Not a list";
        AutomationProgress progress = new AutomationProgress();
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);

        // When
        policyDefinition.parsePolicyDefinition(data, "test", progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.getWarnings().size(), is(equalTo(1)));
        assertThat(
                progress.getWarnings().get(0), is(equalTo("!automation.error.options.badlist!")));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "  defaultStrength: \n" + "  defaultThreshold: \n" + "  rules: ",
                "defaultStrength:",
                "defaultThreshold:"
            })
    void shouldReturnPolicyWithDefaultsIfDefinitionYamlContainsUndefinedStrengthThreshold(
            String defnYamlStr) {
        // Given
        AutomationProgress progress = new AutomationProgress();
        Yaml yaml = new Yaml();
        Object data = yaml.load(defnYamlStr);

        // When
        policyDefinition.parsePolicyDefinition(data, "test", progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        ScanPolicy policy = policyDefinition.getScanPolicy("test", progress);
        assertThat(policy, is(notNullValue()));
        assertThat(policy.getDefaultStrength(), is(equalTo(AttackStrength.MEDIUM)));
        assertThat(policy.getDefaultThreshold(), is(equalTo(AlertThreshold.MEDIUM)));
        List<Plugin> rules = policy.getPluginFactory().getAllPlugin();
        assertValueAppliedToRules(
                rules.get(0),
                rules.get(rules.size() - 1),
                AttackStrength.MEDIUM,
                AlertThreshold.MEDIUM);
    }

    private static void assertValueAppliedToRules(
            Plugin first, Plugin last, AttackStrength expectedStr, AlertThreshold expectedThold) {
        assertThat(first.getAttackStrength(), is(equalTo(expectedStr)));
        assertThat(last.getAttackStrength(), is(equalTo(expectedStr)));
        assertThat(first.getAlertThreshold(), is(equalTo(expectedThold)));
        assertThat(last.getAlertThreshold(), is(equalTo(expectedThold)));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "{}",
                "",
                "rules: \n",
            })
    void shouldReturnNullPolicyIfDefinitionYamlIsEmptyOrNullObject(String defnYamlStr) {
        // Given
        AutomationProgress progress = new AutomationProgress();
        Yaml yaml = new Yaml();
        Object data = yaml.load(defnYamlStr);

        // When
        policyDefinition.parsePolicyDefinition(data, "test", progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(policyDefinition.getScanPolicy("test", progress), is(nullValue()));
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 50000, 99999})
    void shouldAlwaysIncludeIdWhenSerializingARule(int id) throws JsonProcessingException {
        // Given
        Rule rule =
                new Rule(
                        id,
                        "Test Rule",
                        AttackStrength.MEDIUM.name(),
                        AlertThreshold.MEDIUM.name());
        // When
        String ruleYaml = AutomationPlan.writeObjectAsString(rule);
        // Then
        assertThat(ruleYaml, containsString("id: " + id));
    }

    @ParameterizedTest
    @ValueSource(strings = {"TEST_TAG", "TEST_.*"})
    void shouldAddRuleUsingAlertTags(String tagPattern) {
        // Given
        String yamlStr =
                String.format(
                        """
                defaultStrength: low
                defaultThreshold: 'off'
                alertTags:
                  include:
                    - %s
                  exclude: []
                  strength: insane
                  threshold: high
                """,
                        tagPattern);
        AutomationProgress progress = new AutomationProgress();
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);

        // When
        policyDefinition.parsePolicyDefinition(data, "test", progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(policyDefinition.getDefaultStrength(), is(equalTo("low")));
        assertThat(policyDefinition.getDefaultThreshold(), is(equalTo("off")));
        List<Rule> rules = policyDefinition.getEffectiveRules();
        assertThat(rules.size(), is(equalTo(1)));
        assertThat(rules.get(0).getId(), is(equalTo(50000)));
        assertThat(rules.get(0).getName(), is(equalTo("PluginTestHelper")));
        assertThat(rules.get(0).getStrength(), is(equalTo("insane")));
        assertThat(rules.get(0).getThreshold(), is(equalTo("high")));
    }

    @ParameterizedTest
    @ValueSource(strings = {"TEST_TAG", "TEST_.*"})
    void shouldExcludeIncludedRulesUsingAlertTags(String tagPattern) {
        // Given
        String yamlStr =
                String.format(
                        """
                defaultStrength: low
                defaultThreshold: medium
                alertTags:
                  include:
                  - .*
                  exclude:
                  - %s
                """,
                        tagPattern);
        AutomationProgress progress = new AutomationProgress();
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);

        // When
        policyDefinition.parsePolicyDefinition(data, "test", progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(policyDefinition.getEffectiveRules().isEmpty(), is(equalTo(true)));
    }

    @Test
    void shouldNotAddSameRuleTwice() {
        // Given
        String yamlStr =
                """
                defaultStrength: low
                defaultThreshold: 'off'
                rules:
                - id: 50000
                  name: rule1
                  strength: insane
                  threshold: high
                alertTags:
                  include:
                    - TEST_TAG
                  exclude: []
                  strength: low
                  threshold: medium
                """;
        AutomationProgress progress = new AutomationProgress();
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);

        // When
        policyDefinition.parsePolicyDefinition(data, "test", progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        List<Rule> rules = policyDefinition.getEffectiveRules();
        assertThat(rules.size(), is(equalTo(1)));
        assertThat(rules.get(0).getId(), is(equalTo(50000)));
        assertThat(rules.get(0).getName(), is(equalTo("PluginTestHelper")));
        assertThat(rules.get(0).getStrength(), is(equalTo("insane")));
        assertThat(rules.get(0).getThreshold(), is(equalTo("high")));
    }

    @Test
    void shouldLoadPlansWithNullAlertTagFields() {
        // Given
        String yamlStr =
                """
                defaultStrength: low
                defaultThreshold: medium
                alertTags:
                  include: null
                  exclude: null
                  strength: null
                  threshold: null
                """;
        AutomationProgress progress = new AutomationProgress();
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);

        // When
        policyDefinition.parsePolicyDefinition(data, "test", progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(policyDefinition.getAlertTagRule(), is(equalTo(new AlertTagRuleConfig())));
    }

    @Test
    void shouldHandleInvalidThresholdValue() {
        // Given
        String yamlStr =
                """
                defaultStrength: low
                defaultThreshold: 'off'
                alertTags:
                  include:
                    - TEST_TAG
                  exclude: []
                  strength: medium
                  threshold: invalidThreshold
                """;
        AutomationProgress progress = new AutomationProgress();
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);

        // When
        policyDefinition.parsePolicyDefinition(data, "test", progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(
                progress.getWarnings().get(0), is(equalTo("!automation.error.ascan.threshold!")));
    }

    @Test
    void shouldHandleInvalidStrengthValue() {
        // Given
        String yamlStr =
                """
                defaultStrength: low
                defaultThreshold: 'off'
                alertTags:
                  include:
                    - TEST_TAG
                  exclude: []
                  strength: invalidStrength
                  threshold: medium
                """;
        AutomationProgress progress = new AutomationProgress();
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);

        // When
        policyDefinition.parsePolicyDefinition(data, "test", progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.getWarnings().get(0), is(equalTo("!automation.error.ascan.strength!")));
    }
}
