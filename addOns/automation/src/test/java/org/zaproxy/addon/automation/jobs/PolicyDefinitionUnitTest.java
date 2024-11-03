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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

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
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractPlugin;
import org.parosproxy.paros.core.scanner.PluginFactory;
import org.parosproxy.paros.core.scanner.PluginFactoryTestHelper;
import org.parosproxy.paros.core.scanner.PluginTestHelper;
import org.yaml.snakeyaml.Yaml;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.jobs.PolicyDefinition.Rule;
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
        PolicyDefinition.parsePolicyDefinition(data, policyDefinition, "test", progress);

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
        PolicyDefinition.parsePolicyDefinition(data, policyDefinition, "test", progress);

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
        PolicyDefinition.parsePolicyDefinition(data, policyDefinition, "test", progress);

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
        PolicyDefinition.parsePolicyDefinition(data, policyDefinition, "test", progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.getWarnings().size(), is(equalTo(1)));
        assertThat(
                progress.getWarnings().get(0), is(equalTo("!automation.error.options.badlist!")));
    }
}
