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
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.AbstractPlugin;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.parosproxy.paros.core.scanner.PluginFactory;
import org.parosproxy.paros.core.scanner.PluginFactoryTestHelper;
import org.parosproxy.paros.core.scanner.PluginTestHelper;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.yaml.snakeyaml.Yaml;
import org.zaproxy.addon.automation.AutomationJob.Order;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.extension.ascan.ScanPolicy;
import org.zaproxy.zap.utils.I18N;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class ActiveScanPolicyJobUnitTest {

    private static MockedStatic<CommandLine> mockedCmdLine;
    private ExtensionActiveScan extAScan;
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

        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
        ExtensionLoader extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        extAScan = mock(ExtensionActiveScan.class, withSettings().strictness(Strictness.LENIENT));
        given(extensionLoader.getExtension(ExtensionActiveScan.class)).willReturn(extAScan);

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
        Model.getSingleton().getOptionsParam().load(new ZapXmlConfiguration());
    }

    @Test
    void shouldReturnDefaultFields() {
        // Given / When
        ActiveScanPolicyJob job = new ActiveScanPolicyJob();

        // Then
        assertThat(job.getType(), is(equalTo("activeScan-policy")));
        assertThat(job.getName(), is(equalTo("activeScan-policy")));
        assertThat(job.getOrder(), is(equalTo(Order.CONFIGS)));
        assertThat(job.getParamMethodObject(), is(nullValue()));
        assertThat(job.getParamMethodName(), is(nullValue()));
    }

    @Test
    void shouldReturnCustomConfigParams() {
        // Given
        ActiveScanPolicyJob job = new ActiveScanPolicyJob();

        // When
        Map<String, String> params = job.getCustomConfigParameters();

        // Then
        assertThat(params.size(), is(equalTo(1)));
        assertThat(params.get("name"), is(equalTo("")));
    }

    @Test
    void shouldFailWithUnknownConfigParam() {
        // Given
        String yamlStr = "parameters:\n" + "  blah: 12\n" + "  name: testPolicy";
        AutomationProgress progress = new AutomationProgress();
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);

        ActiveScanPolicyJob job = new ActiveScanPolicyJob();
        job.setJobData(((LinkedHashMap<?, ?>) data));

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.getWarnings().size(), is(equalTo(1)));
        assertThat(
                progress.getWarnings().get(0), is(equalTo("!automation.error.options.unknown!")));
    }

    @Test
    void shouldReturnWarningOnUnexpectedElement() throws MalformedURLException {
        // Given
        ActiveScanPolicyJob job = new ActiveScanPolicyJob();
        AutomationProgress progress = new AutomationProgress();
        LinkedHashMap<String, String> data = new LinkedHashMap<>();
        data.put("tests", "");
        // The only invalid one
        data.put("unexpected", "data");

        // When
        job.setJobData(data);
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.getWarnings().size(), is(equalTo(1)));
        assertThat(
                progress.getWarnings().get(0), is(equalTo("!automation.error.element.unknown!")));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldReturnScanPolicyForDefaultData() throws MalformedURLException {
        // Given
        ActiveScanPolicyJob job = new ActiveScanPolicyJob();
        AutomationProgress progress = new AutomationProgress();
        LinkedHashMap<String, LinkedHashMap<?, ?>> data = new LinkedHashMap<>();
        data.put("policyDefinition", new LinkedHashMap<>());

        // When
        job.setJobData(data);
        job.verifyParameters(progress);
        ScanPolicy policy = job.getScanPolicy(progress);

        // Then
        assertThat(policy, is(notNullValue()));
        assertThat(policy.getDefaultStrength(), is(AttackStrength.MEDIUM));
        assertThat(policy.getDefaultThreshold(), is(AlertThreshold.MEDIUM));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldSetScanPolicyDefaults() throws MalformedURLException {
        // Given
        ActiveScanPolicyJob job = new ActiveScanPolicyJob();
        AutomationProgress progress = new AutomationProgress();
        LinkedHashMap<String, String> policyDefn = new LinkedHashMap<>();
        policyDefn.put("defaultStrength", "LOW");
        policyDefn.put("defaultThreshold", "high");
        LinkedHashMap<String, LinkedHashMap<?, ?>> data = new LinkedHashMap<>();
        data.put("policyDefinition", policyDefn);

        // When
        job.setJobData(data);
        job.verifyParameters(progress);
        ScanPolicy policy = job.getScanPolicy(progress);

        // Then
        assertThat(policy, is(notNullValue()));
        assertThat(policy.getDefaultStrength(), is(AttackStrength.LOW));
        assertThat(policy.getDefaultThreshold(), is(AlertThreshold.HIGH));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldDisableAllRulesWithString() throws MalformedURLException {
        // Given
        ActiveScanPolicyJob job = new ActiveScanPolicyJob();
        AutomationProgress progress = new AutomationProgress();
        LinkedHashMap<String, String> policyDefn = new LinkedHashMap<>();
        policyDefn.put("defaultThreshold", "off");
        LinkedHashMap<String, LinkedHashMap<?, ?>> data = new LinkedHashMap<>();
        data.put("policyDefinition", policyDefn);

        // When
        job.setJobData(data);
        job.verifyParameters(progress);
        ScanPolicy policy = job.getScanPolicy(progress);

        // Then
        assertThat(policy, is(notNullValue()));
        assertThat(policy.getPluginFactory(), is(notNullValue()));
        assertThat(policy.getPluginFactory().getAllPlugin(), is(notNullValue()));
        assertThat(policy.getPluginFactory().getAllPlugin().size(), is(1));
        assertThat(policy.getPluginFactory().getAllPlugin().get(0), is(notNullValue()));
        assertThat(policy.getPluginFactory().getAllPlugin().get(0).isEnabled(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldSetSpecifiedRuleConfigs() throws MalformedURLException {
        // Given
        ActiveScanPolicyJob job = new ActiveScanPolicyJob();
        AutomationProgress progress = new AutomationProgress();

        LinkedHashMap<String, Object> ruleDefn = new LinkedHashMap<>();
        ruleDefn.put("id", 50000);
        ruleDefn.put("strength", "iNsaNe");
        ruleDefn.put("threshold", "high");

        LinkedHashMap<String, List<?>> policyDefn = new LinkedHashMap<>();

        ArrayList<LinkedHashMap<?, ?>> rulesDefn = new ArrayList<>();
        rulesDefn.add(ruleDefn);
        policyDefn.put("rules", rulesDefn);

        LinkedHashMap<String, LinkedHashMap<?, ?>> data = new LinkedHashMap<>();
        data.put("policyDefinition", policyDefn);

        // When
        job.setJobData(data);
        job.verifyParameters(progress);
        ScanPolicy policy = job.getScanPolicy(progress);

        // Then
        assertThat(policy, is(notNullValue()));
        assertThat(policy.getPluginFactory(), is(notNullValue()));
        assertThat(policy.getPluginFactory().getAllPlugin(), is(notNullValue()));
        assertThat(policy.getPluginFactory().getAllPlugin().size(), is(1));
        assertThat(policy.getPluginFactory().getAllPlugin().get(0), is(notNullValue()));
        assertThat(policy.getPluginFactory().getAllPlugin().get(0).isEnabled(), is(equalTo(true)));
        assertThat(policy.getPluginFactory().getAllPlugin().get(0).getId(), is(equalTo(50000)));
        assertThat(
                policy.getPluginFactory().getAllPlugin().get(0).getAttackStrength(),
                is(equalTo(AttackStrength.INSANE)));
        assertThat(
                policy.getPluginFactory().getAllPlugin().get(0).getAlertThreshold(),
                is(equalTo(AlertThreshold.HIGH)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldTurnOffSpecifiedRule() throws MalformedURLException {
        // Given
        ActiveScanPolicyJob job = new ActiveScanPolicyJob();
        AutomationProgress progress = new AutomationProgress();

        LinkedHashMap<String, Object> ruleDefn = new LinkedHashMap<>();
        ruleDefn.put("id", 50000);
        ruleDefn.put("strength", "medium");
        ruleDefn.put("threshold", "oFF");

        LinkedHashMap<String, List<?>> policyDefn = new LinkedHashMap<>();

        ArrayList<LinkedHashMap<?, ?>> rulesDefn = new ArrayList<>();
        rulesDefn.add(ruleDefn);
        policyDefn.put("rules", rulesDefn);

        LinkedHashMap<String, LinkedHashMap<?, ?>> data = new LinkedHashMap<>();
        data.put("policyDefinition", policyDefn);

        // When
        job.setJobData(data);
        job.verifyParameters(progress);
        ScanPolicy policy = job.getScanPolicy(progress);

        // Then
        assertThat(policy, is(notNullValue()));
        assertThat(policy.getPluginFactory(), is(notNullValue()));
        assertThat(policy.getPluginFactory().getAllPlugin(), is(notNullValue()));
        assertThat(policy.getPluginFactory().getAllPlugin().size(), is(1));
        assertThat(policy.getPluginFactory().getAllPlugin().get(0), is(notNullValue()));
        assertThat(policy.getPluginFactory().getAllPlugin().get(0).isEnabled(), is(equalTo(false)));
        assertThat(policy.getPluginFactory().getAllPlugin().get(0).getId(), is(equalTo(50000)));
        assertThat(
                policy.getPluginFactory().getAllPlugin().get(0).getAttackStrength(),
                is(equalTo(AttackStrength.MEDIUM)));
        assertThat(
                policy.getPluginFactory().getAllPlugin().get(0).getAlertThreshold(),
                is(equalTo(AlertThreshold.OFF)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldWarnOnUnknownRule() throws MalformedURLException {
        // Given
        ActiveScanPolicyJob job = new ActiveScanPolicyJob();
        AutomationProgress progress = new AutomationProgress();

        LinkedHashMap<String, Object> ruleDefn = new LinkedHashMap<>();
        ruleDefn.put("id", 1377);
        ruleDefn.put("threshold", "medium");

        LinkedHashMap<String, List<?>> policyDefn = new LinkedHashMap<>();

        ArrayList<LinkedHashMap<?, ?>> rulesDefn = new ArrayList<>();
        rulesDefn.add(ruleDefn);
        policyDefn.put("rules", rulesDefn);

        LinkedHashMap<String, LinkedHashMap<?, ?>> data = new LinkedHashMap<>();
        data.put("policyDefinition", policyDefn);

        // When
        job.setJobData(data);
        job.verifyParameters(progress);
        job.getScanPolicy(progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(
                progress.getWarnings().get(0),
                is(equalTo("!automation.error.ascan.rule.unknown!")));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldWarnOnInvalidStringStrength() throws MalformedURLException {
        // Given
        ActiveScanPolicyJob job = new ActiveScanPolicyJob();
        AutomationProgress progress = new AutomationProgress();

        LinkedHashMap<String, Object> ruleDefn = new LinkedHashMap<>();
        ruleDefn.put("id", 50000);
        ruleDefn.put("strength", "poor");

        LinkedHashMap<String, List<?>> policyDefn = new LinkedHashMap<>();

        ArrayList<LinkedHashMap<?, ?>> rulesDefn = new ArrayList<>();
        rulesDefn.add(ruleDefn);
        policyDefn.put("rules", rulesDefn);

        LinkedHashMap<String, LinkedHashMap<?, ?>> data = new LinkedHashMap<>();
        data.put("policyDefinition", policyDefn);

        // When
        job.setJobData(data);
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.getWarnings().get(0), is(equalTo("!automation.error.ascan.strength!")));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldWarnOnInvalidIntStrength() throws MalformedURLException {
        // Given
        ActiveScanPolicyJob job = new ActiveScanPolicyJob();
        AutomationProgress progress = new AutomationProgress();

        LinkedHashMap<String, Object> ruleDefn = new LinkedHashMap<>();
        ruleDefn.put("id", 50000);
        ruleDefn.put("strength", 1);

        LinkedHashMap<String, List<?>> policyDefn = new LinkedHashMap<>();

        ArrayList<LinkedHashMap<?, ?>> rulesDefn = new ArrayList<>();
        rulesDefn.add(ruleDefn);
        policyDefn.put("rules", rulesDefn);

        LinkedHashMap<String, LinkedHashMap<?, ?>> data = new LinkedHashMap<>();
        data.put("policyDefinition", policyDefn);

        // When
        job.setJobData(data);
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.getWarnings().get(0), is(equalTo("!automation.error.ascan.strength!")));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldWarnOnInvalidStringThreshold() throws MalformedURLException {
        // Given
        ActiveScanPolicyJob job = new ActiveScanPolicyJob();
        AutomationProgress progress = new AutomationProgress();

        LinkedHashMap<String, Object> ruleDefn = new LinkedHashMap<>();
        ruleDefn.put("id", 50000);
        ruleDefn.put("threshold", "poor");

        LinkedHashMap<String, List<?>> policyDefn = new LinkedHashMap<>();

        ArrayList<LinkedHashMap<?, ?>> rulesDefn = new ArrayList<>();
        rulesDefn.add(ruleDefn);
        policyDefn.put("rules", rulesDefn);

        LinkedHashMap<String, LinkedHashMap<?, ?>> data = new LinkedHashMap<>();
        data.put("policyDefinition", policyDefn);

        // When
        job.setJobData(data);
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(
                progress.getWarnings().get(0), is(equalTo("!automation.error.ascan.threshold!")));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldWarnOnInvalidIntThreshold() throws MalformedURLException {
        // Given
        ActiveScanPolicyJob job = new ActiveScanPolicyJob();
        AutomationProgress progress = new AutomationProgress();

        LinkedHashMap<String, Object> ruleDefn = new LinkedHashMap<>();
        ruleDefn.put("id", 50000);
        ruleDefn.put("threshold", 1);

        LinkedHashMap<String, List<?>> policyDefn = new LinkedHashMap<>();

        ArrayList<LinkedHashMap<?, ?>> rulesDefn = new ArrayList<>();
        rulesDefn.add(ruleDefn);
        policyDefn.put("rules", rulesDefn);

        LinkedHashMap<String, LinkedHashMap<?, ?>> data = new LinkedHashMap<>();
        data.put("policyDefinition", policyDefn);

        // When
        job.setJobData(data);
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(
                progress.getWarnings().get(0), is(equalTo("!automation.error.ascan.threshold!")));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }
}
