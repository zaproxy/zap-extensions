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
import static org.hamcrest.Matchers.startsWith;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import java.net.MalformedURLException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.ResourceBundle;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
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
import org.zaproxy.addon.commonlib.gspm.GspmCategory;
import org.zaproxy.addon.commonlib.gspm.GspmPhase;
import org.zaproxy.addon.commonlib.gspm.GspmPolicy;
import org.zaproxy.addon.commonlib.gspm.GspmRegistry;
import org.zaproxy.addon.commonlib.gspm.GspmRule;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.extension.ascan.PolicyManager;
import org.zaproxy.zap.extension.ascan.ScanPolicy;
import org.zaproxy.zap.utils.I18N;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class ActiveScanPolicyJobUnitTest {

    private static MockedStatic<CommandLine> mockedCmdLine;
    @TempDir java.nio.file.Path zapHomeDir;

    private String zapHome;
    private ExtensionActiveScan extAScan;
    private static AbstractPlugin plugin;

    @BeforeAll
    static void init() {
        mockedCmdLine = Mockito.mockStatic(CommandLine.class);

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
        zapHome = Constant.getZapHome();
        Constant.setZapHome(zapHomeDir.toString());

        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
        ExtensionLoader extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        extAScan = mock(ExtensionActiveScan.class, withSettings().strictness(Strictness.LENIENT));
        given(extensionLoader.getExtension(ExtensionActiveScan.class)).willReturn(extAScan);

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
        Model.getSingleton().getOptionsParam().load(new ZapXmlConfiguration());
    }

    @AfterEach
    void restoreZapHome() {
        if (zapHome != null) {
            Constant.setZapHome(zapHome);
        }
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

    @Test
    void shouldAddPolicyAndRuleSettingsToGlobalScanPolicyInDevMode() throws Exception {
        // Given
        Constant.setDevMode(true);
        try {
            GspmRegistry registry = registryWithRules(50000, 50001);
            ActiveScanPolicyJob job = policyJob("Test", "high", "low", ruleDefn(50000));
            job.setGspmRegistrySupplier(() -> registry);
            AutomationProgress progress = new AutomationProgress();
            // When
            job.runJob(null, progress);
            // Then
            assertThat(progress.hasWarnings(), is(equalTo(false)));
            assertThat(progress.hasErrors(), is(equalTo(false)));
            assertThat(registry.getPolicy("Test"), is(notNullValue()));
            GspmRule configured = rule(registry, "Test", 50000);
            assertThat(configured.getAlertThreshold(), is(equalTo(AlertThreshold.HIGH)));
            assertThat(configured.getAttackStrength(), is(equalTo(AttackStrength.INSANE)));
            assertThat(configured.isEnabled(), is(equalTo(true)));
            GspmRule other = rule(registry, "Test", 50001);
            assertThat(other.getAlertThreshold(), is(equalTo(AlertThreshold.LOW)));
            assertThat(other.getAttackStrength(), is(equalTo(AttackStrength.HIGH)));
            verify(extAScan, never()).getPolicyManager();
        } finally {
            Constant.setDevMode(false);
        }
    }

    @Test
    void shouldEnableRuleWithStrengthIfDefaultThresholdIsOffInGlobalScanPolicy() throws Exception {
        // Given
        Constant.setDevMode(true);
        try {
            GspmRegistry registry = registryWithRules(50000, 50001);
            LinkedHashMap<String, Object> rule = ruleDefn(50000);
            rule.remove("threshold");
            ActiveScanPolicyJob job = policyJob("Test", "high", "off", rule);
            job.setGspmRegistrySupplier(() -> registry);
            // When
            job.runJob(null, new AutomationProgress());
            // Then
            assertThat(rule(registry, "Test", 50000).isEnabled(), is(equalTo(true)));
            assertThat(rule(registry, "Test", 50001).isEnabled(), is(equalTo(false)));
        } finally {
            Constant.setDevMode(false);
        }
    }

    @Test
    void shouldAddPolicyWithDefaultsAndNoRulesToGlobalScanPolicyIfNoPolicyDefinition()
            throws Exception {
        // Given
        Constant.setDevMode(true);
        try {
            GspmRegistry registry = registryWithRules(50000);
            ActiveScanPolicyJob job = new ActiveScanPolicyJob();
            LinkedHashMap<String, Object> data = new LinkedHashMap<>();
            data.put("parameters", new LinkedHashMap<>(Map.of("name", "Test")));
            job.setJobData(data);
            AutomationProgress progress = new AutomationProgress();
            job.verifyParameters(progress);
            job.setGspmRegistrySupplier(() -> registry);
            // When
            job.runJob(null, progress);
            // Then
            assertThat(progress.hasWarnings(), is(equalTo(false)));
            assertThat(progress.hasErrors(), is(equalTo(false)));
            GspmRule rule = rule(registry, "Test", 50000);
            assertThat(rule.getAlertThreshold(), is(equalTo(AlertThreshold.MEDIUM)));
            assertThat(rule.getAttackStrength(), is(equalTo(AttackStrength.MEDIUM)));
        } finally {
            Constant.setDevMode(false);
        }
    }

    @Test
    void shouldWarnIfPolicyAlreadyExistsInGlobalScanPolicy() throws Exception {
        // Given
        Constant.setDevMode(true);
        try {
            GspmRegistry registry = registryWithRules(50000);
            registry.addPolicy(new GspmPolicy("Test"));
            ActiveScanPolicyJob job = policyJob("Test", "high", "low", ruleDefn(50000));
            job.setGspmRegistrySupplier(() -> registry);
            AutomationProgress progress = new AutomationProgress();
            // When
            job.runJob(null, progress);
            // Then
            assertThat(progress.hasWarnings(), is(equalTo(true)));
            assertThat(progress.hasErrors(), is(equalTo(false)));
            assertThat(registry.getPolicy("Test").getRuleSets().isEmpty(), is(equalTo(true)));
        } finally {
            Constant.setDevMode(false);
        }
    }

    @Test
    void shouldWarnOnUnknownRuleInGlobalScanPolicy() throws Exception {
        // Given
        Constant.setDevMode(true);
        try {
            GspmRegistry registry = registryWithRules(50001);
            ActiveScanPolicyJob job = policyJob("Test", "high", "low", ruleDefn(50000));
            job.setGspmRegistrySupplier(() -> registry);
            AutomationProgress progress = new AutomationProgress();
            // When
            job.runJob(null, progress);
            // Then
            assertThat(progress.hasWarnings(), is(equalTo(true)));
            assertThat(progress.hasErrors(), is(equalTo(false)));
        } finally {
            Constant.setDevMode(false);
        }
    }

    @Test
    void shouldReportErrorsCreatingPolicyInGlobalScanPolicy() throws Exception {
        // Given
        useAutomationMessages();
        Constant.setDevMode(true);
        try {
            GspmRegistry registry = registryWithRules(50000);
            ActiveScanPolicyJob job = policyJob("a/b", "high", "low", ruleDefn(50000));
            job.setGspmRegistrySupplier(() -> registry);
            AutomationProgress progress = new AutomationProgress();
            // When
            job.runJob(null, progress);
            // Then
            assertThat(progress.getErrors().size(), is(equalTo(1)));
            assertThat(
                    progress.getErrors().get(0),
                    startsWith("Job activeScan-policy failed to create scan policy a/b: "));
            assertThat(registry.getPolicy("a/b"), is(nullValue()));
        } finally {
            Constant.setDevMode(false);
        }
    }

    @Test
    void shouldReportErrorsConfiguringRuleInGlobalScanPolicy() throws Exception {
        // Given
        useAutomationMessages();
        Constant.setDevMode(true);
        try {
            GspmRegistry registry = spy(registryWithRules(50000));
            doThrow(new IllegalStateException("failure"))
                    .when(registry)
                    .getRulesByTool(anyString(), anyString());
            ActiveScanPolicyJob job = policyJob("Test", "high", "low", ruleDefn(50000));
            job.setGspmRegistrySupplier(() -> registry);
            AutomationProgress progress = new AutomationProgress();
            // When
            job.runJob(null, progress);
            // Then
            assertThat(progress.getErrors().size(), is(equalTo(1)));
            assertThat(
                    progress.getErrors().get(0),
                    is(
                            equalTo(
                                    "Job activeScan-policy failed to configure rule 50000 of scan"
                                            + " policy Test: failure")));
        } finally {
            Constant.setDevMode(false);
        }
    }

    @Test
    void shouldFailIfGlobalScanPolicyManagerNotAvailableInDevMode() throws Exception {
        // Given
        useAutomationMessages();
        Constant.setDevMode(true);
        try {
            ActiveScanPolicyJob job = policyJob("Test", "high", "low", ruleDefn(50000));
            job.setGspmRegistrySupplier(() -> null);
            AutomationProgress progress = new AutomationProgress();
            // When
            job.runJob(null, progress);
            // Then
            assertThat(progress.hasErrors(), is(equalTo(true)));
            assertThat(
                    progress.getErrors().get(0),
                    is(
                            equalTo(
                                    "Job activeScan-policy could not create scan policy Test, the"
                                            + " Global Scan Policy Manager is not available")));
            verify(extAScan, never()).getPolicyManager();
        } finally {
            Constant.setDevMode(false);
        }
    }

    @Test
    void shouldSavePolicyWithPolicyManagerIfNotInDevMode() throws Exception {
        // Given
        String version = Constant.PROGRAM_VERSION;
        Constant.PROGRAM_VERSION = "2.18.0";
        Constant.setDevMode(false);
        try {
            PolicyManager policyManager = mock(PolicyManager.class);
            given(policyManager.getAllPolicyNames()).willReturn(List.of());
            given(extAScan.getPolicyManager()).willReturn(policyManager);
            GspmRegistry registry = registryWithRules(50000);
            ActiveScanPolicyJob job = policyJob("Test", "high", "low", ruleDefn(50000));
            job.setGspmRegistrySupplier(() -> registry);
            AutomationProgress progress = new AutomationProgress();
            // When
            job.runJob(null, progress);
            // Then
            verify(policyManager).savePolicy(any(ScanPolicy.class));
            assertThat(registry.getPolicy("Test"), is(nullValue()));
        } finally {
            Constant.PROGRAM_VERSION = version;
        }
    }

    private GspmRegistry registryWithRules(int... ruleIds) throws Exception {
        Files.createDirectories(Constant.getPoliciesDir().toPath());
        GspmRegistry registry = new GspmRegistry();
        for (int id : ruleIds) {
            registry.registerRule(new TestRule(id));
        }
        return registry;
    }

    private static GspmRule rule(GspmRegistry registry, String policy, int id) {
        return registry.getRulesByTool("ascan", policy).stream()
                .filter(r -> r.getId() == id)
                .findFirst()
                .get();
    }

    private static final class TestRule implements GspmRule {

        private final int id;

        TestRule(int id) {
            this.id = id;
        }

        @Override
        public int getId() {
            return id;
        }

        @Override
        public String getName() {
            return "Rule " + id;
        }

        @Override
        public String getTool() {
            return "ascan";
        }

        @Override
        public GspmPhase getPhase() {
            return GspmPhase.ACTIVE;
        }

        @Override
        public List<GspmCategory> getCategories() {
            return List.of(new GspmCategory("server", "Server"));
        }

        @Override
        public Map<String, String> getAlertTags() {
            return Map.of();
        }

        @Override
        public boolean isEnabled() {
            return true;
        }

        @Override
        public void setEnabled(boolean enabled) {}

        @Override
        public AlertThreshold getAlertThreshold() {
            return AlertThreshold.MEDIUM;
        }

        @Override
        public void setAlertThreshold(AlertThreshold threshold) {}

        @Override
        public AttackStrength getAttackStrength() {
            return AttackStrength.MEDIUM;
        }

        @Override
        public void setAttackStrength(AttackStrength strength) {}
    }

    private static void useAutomationMessages() {
        Constant.messages.addMessageBundle(
                "automation",
                ResourceBundle.getBundle(
                        "org.zaproxy.addon.automation.resources.Messages", Locale.ENGLISH));
    }

    private static LinkedHashMap<String, Object> ruleDefn(int id) {
        LinkedHashMap<String, Object> ruleDefn = new LinkedHashMap<>();
        ruleDefn.put("id", id);
        ruleDefn.put("strength", "insane");
        ruleDefn.put("threshold", "high");
        return ruleDefn;
    }

    private static ActiveScanPolicyJob policyJob(
            String name, String strength, String threshold, LinkedHashMap<String, Object> rule) {
        ActiveScanPolicyJob job = new ActiveScanPolicyJob();
        LinkedHashMap<String, Object> policyDefn = new LinkedHashMap<>();
        policyDefn.put("defaultStrength", strength);
        policyDefn.put("defaultThreshold", threshold);
        policyDefn.put("rules", new ArrayList<>(List.of(rule)));
        LinkedHashMap<String, Object> data = new LinkedHashMap<>();
        data.put("parameters", new LinkedHashMap<>(Map.of("name", name)));
        data.put("policyDefinition", policyDefn);
        job.setJobData(data);
        job.verifyParameters(new AutomationProgress());
        return job;
    }
}
