/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
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
import java.util.Objects;
import org.apache.commons.configuration.ConfigurationException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.ArgumentMatcher;
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
import org.parosproxy.paros.core.scanner.ScannerParam;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.yaml.snakeyaml.Yaml;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob.Order;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.ContextWrapper;
import org.zaproxy.zap.extension.ascan.ActiveScan;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.extension.ascan.PolicyManager;
import org.zaproxy.zap.extension.ascan.ScanPolicy;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.Target;
import org.zaproxy.zap.utils.I18N;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class ActiveScanJobUnitTest {

    private static MockedStatic<CommandLine> mockedCmdLine;
    private PolicyManager policyManager;
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

        policyManager = mock();
        given(extAScan.getPolicyManager()).willReturn(policyManager);

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
        Model.getSingleton().getOptionsParam().load(new ZapXmlConfiguration());
    }

    @Test
    void shouldReturnDefaultFields() {
        // Given

        // When
        ActiveScanJob job = new ActiveScanJob();

        // Then
        assertThat(job.getType(), is(equalTo("activeScan")));
        assertThat(job.getName(), is(equalTo("activeScan")));
        assertThat(job.getOrder(), is(equalTo(Order.ATTACK)));
        assertThat(job.getParamMethodObject(), is(extAScan));
        assertThat(job.getParamMethodName(), is("getScannerParam"));
    }

    @Test
    void shouldReturnCustomConfigParams() {
        // Given
        ActiveScanJob job = new ActiveScanJob();

        // When
        Map<String, String> params = job.getCustomConfigParameters();

        // Then
        assertThat(params.size(), is(equalTo(1)));
        assertThat(params.get("context"), is(equalTo("")));
    }

    @Test
    void shouldFailWithUnknownConfigParam() {
        // Given
        String yamlStr =
                """
                parameters:
                  blah: 12
                """;
        AutomationProgress progress = new AutomationProgress();
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);

        ActiveScanJob job = new ActiveScanJob();
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
    void shouldReturnConfigParams() throws MalformedURLException {
        // Given
        ActiveScanJob job = new ActiveScanJob();

        // When
        Map<String, String> params =
                job.getConfigParameters(new ScannerParamWrapper(), job.getParamMethodName());

        // Then
        assertThat(
                params.keySet(),
                containsInAnyOrder(
                        "excludeAntiCsrfTokens",
                        "encodeCookieValues",
                        "addQueryParam",
                        "defaultPolicy",
                        "delayInMs",
                        "handleAntiCSRFTokens",
                        "injectPluginIdInHeader",
                        "maxRuleDurationInMins",
                        "maxScanDurationInMins",
                        "scanHeadersAllRequests",
                        "threadPerHost",
                        "scanNullJsonValues",
                        "maxAlertsPerRule"));
    }

    @Test
    void shouldNotReturnZeroThreads() throws MalformedURLException {
        // Given
        ActiveScanJob job = new ActiveScanJob();
        job.getParameters().setThreadPerHost(0);

        // When
        Map<String, String> params =
                job.getConfigParameters(new ScannerParamWrapper(), job.getParamMethodName());

        // Then
        assertThat(params.containsKey("threadPerHost"), is(equalTo(true)));
        assertTrue(Integer.parseInt(params.get("threadPerHost")) > 0);
    }

    private static class ScannerParamWrapper {
        @SuppressWarnings("unused")
        public ScannerParam getScannerParam() {
            ScannerParam param = new ScannerParam();
            param.load(new ZapXmlConfiguration());
            return param;
        }
    }

    @Test
    void shouldRunValidJob() throws Exception {
        // Given
        Constant.messages = new I18N(Locale.ENGLISH);
        Context context = mock(Context.class);
        ContextWrapper contextWrapper =
                new ContextWrapper(context, mock(AutomationEnvironment.class));

        given(extAScan.startScan(any(), any(), any())).willReturn(1);

        ActiveScan activeScan = mock(ActiveScan.class);
        given(activeScan.isStopped()).willReturn(true);
        given(extAScan.getScan(1)).willReturn(activeScan);

        AutomationProgress progress = new AutomationProgress();

        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.getDefaultContextWrapper()).willReturn(contextWrapper);

        given(policyManager.getPolicy("policy1")).willReturn(mock(ScanPolicy.class));

        ActiveScanJob job = new ActiveScanJob();
        job.getParameters().setPolicy("policy1");

        // When
        job.runJob(env, progress);

        // Then
        assertThat(job.getType(), is(equalTo("activeScan")));
        assertThat(job.getOrder(), is(equalTo(Order.ATTACK)));
        assertThat(job.getParamMethodObject(), is(extAScan));
        assertThat(job.getParamMethodName(), is("getScannerParam"));

        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.getJobResultData("activeScanData"), is(notNullValue()));
    }

    @Test
    void shouldFailIfUnknownContext() throws MalformedURLException {
        // Given
        Constant.messages = new I18N(Locale.ENGLISH);
        AutomationProgress progress = new AutomationProgress();

        AutomationEnvironment env = mock(AutomationEnvironment.class);

        // When
        ActiveScanJob job = new ActiveScanJob();
        job.getParameters().setContext("Unknown");
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().get(0), is(equalTo("!automation.error.context.unknown!")));
    }

    @Test
    void shouldFailIfUnknownPolicy() throws Exception {
        // Given
        given(policyManager.getPolicy("missingPolicy")).willThrow(ConfigurationException.class);
        Constant.messages = new I18N(Locale.ENGLISH);
        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = mock(AutomationEnvironment.class);

        ContextWrapper contextWrapper = new ContextWrapper(mock(Context.class), env);
        given(env.getDefaultContextWrapper()).willReturn(contextWrapper);

        ActiveScanJob job = new ActiveScanJob();
        job.getParameters().setPolicy("missingPolicy");

        // When
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors(), contains("!automation.error.ascan.policy.name!"));
    }

    @Test
    void shouldUseSpecifiedContext() throws MalformedURLException {
        // Given
        Constant.messages = new I18N(Locale.ENGLISH);
        Session session = mock(Session.class);
        Context context1 = mock(Context.class);
        Context context2 = mock(Context.class);
        given(session.getNewContext("context1")).willReturn(context1);
        given(session.getNewContext("context2")).willReturn(context2);
        Target target1 = new Target(context1);
        Target target2 = new Target(context2);
        AutomationEnvironment env = mock(AutomationEnvironment.class);
        ContextWrapper contextWrapper1 = new ContextWrapper(context1, env);
        ContextWrapper contextWrapper2 = new ContextWrapper(context2, env);

        given(extAScan.startScan(any(), any(), any())).willReturn(1);

        ActiveScan activeScan = mock(ActiveScan.class);
        given(activeScan.isStopped()).willReturn(true);
        given(extAScan.getScan(1)).willReturn(activeScan);

        AutomationProgress progress = new AutomationProgress();

        given(env.getContext("context1")).willReturn(context1);
        given(env.getContext("context2")).willReturn(context2);
        given(env.getContextWrapper("context1")).willReturn(contextWrapper1);
        given(env.getContextWrapper("context2")).willReturn(contextWrapper2);
        given(env.getDefaultContext()).willReturn(context1);

        // When
        ActiveScanJob job = new ActiveScanJob();
        job.getParameters().setContext("context2");
        job.runJob(env, progress);

        // Then
        verify(extAScan, times(0))
                .startScan(argThat(new TargetContextMatcher(target1)), any(), any());
        verify(extAScan, times(1))
                .startScan(argThat(new TargetContextMatcher(target2)), any(), any());

        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.getJobResultData("activeScanData"), is(notNullValue()));
    }

    private static class TargetContextMatcher implements ArgumentMatcher<Target> {

        private Target left;

        public TargetContextMatcher(Target target) {
            left = target;
        }

        @Override
        public boolean matches(Target right) {
            return (Objects.equals(left.getContext(), right.getContext()));
        }
    }

    @Test
    void shouldExitIfActiveScanTakesTooLong() throws MalformedURLException {
        // Given
        Context context = mock(Context.class);
        ContextWrapper contextWrapper =
                new ContextWrapper(context, new AutomationEnvironment(new AutomationProgress()));

        given(extAScan.startScan(any(), any(), any())).willReturn(1);

        ActiveScan activeScan = mock(ActiveScan.class);
        given(activeScan.isStopped()).willReturn(false);
        given(extAScan.getScan(1)).willReturn(activeScan);

        AutomationProgress progress = new AutomationProgress();

        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.getDefaultContextWrapper()).willReturn(contextWrapper);

        ActiveScanJob job = new ActiveScanJob();

        // When
        job.getParameters().setMaxScanDurationInMins(1);
        job.runJob(env, progress);

        // Then
        assertThat(job.getType(), is(equalTo("activeScan")));
        assertThat(job.getOrder(), is(equalTo(Order.ATTACK)));
        assertThat(job.getParamMethodObject(), is(extAScan));
        assertThat(job.getParamMethodName(), is("getScannerParam"));

        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldReturnWarningForBadScanPolicyData() throws MalformedURLException {
        // Given
        ActiveScanJob job = new ActiveScanJob();
        AutomationProgress progress = new AutomationProgress();
        LinkedHashMap<String, String> data = new LinkedHashMap<>();
        data.put("policyDefinition", "Incorrect");

        // When
        job.setJobData(data);
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(
                progress.getWarnings().get(0), is(equalTo("!automation.error.options.badlist!")));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldReturnWarningOnUnexpectedElement() throws MalformedURLException {
        // Given
        ActiveScanJob job = new ActiveScanJob();
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
    void shouldReturnNullScanPolicyForEmptyData() {
        // Given
        ActiveScanJob job = new ActiveScanJob();
        AutomationProgress progress = new AutomationProgress();
        LinkedHashMap<String, LinkedHashMap<?, ?>> data = new LinkedHashMap<>();
        data.put("policyDefinition", new LinkedHashMap<>());

        // When
        job.setJobData(data);
        job.verifyParameters(progress);
        ScanPolicy policy = job.getData().getPolicyDefinition().getScanPolicy(null, progress);

        // Then
        assertThat(policy, is(equalTo(null)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @ParameterizedTest
    @EnumSource(
            value = AttackStrength.class,
            mode = EnumSource.Mode.EXCLUDE,
            names = {"DEFAULT"})
    void shouldReturnScanPolicyIfOnlyDefaultStrength(AttackStrength attackStrength) {
        // Given
        ActiveScanJob job = new ActiveScanJob();
        AutomationProgress progress = new AutomationProgress();
        LinkedHashMap<String, LinkedHashMap<?, ?>> data = new LinkedHashMap<>();
        LinkedHashMap<String, String> policyDefn = new LinkedHashMap<>();
        policyDefn.put("defaultStrength", attackStrength.name());
        data.put("policyDefinition", policyDefn);

        // When
        job.setJobData(data);
        job.verifyParameters(progress);
        ScanPolicy policy = job.getData().getPolicyDefinition().getScanPolicy(null, progress);

        // Then
        assertThat(policy, is(notNullValue()));
        assertThat(policy.getDefaultStrength(), is(attackStrength));
        assertThat(policy.getDefaultThreshold(), is(AlertThreshold.MEDIUM));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @ParameterizedTest
    @EnumSource(
            value = AlertThreshold.class,
            mode = EnumSource.Mode.EXCLUDE,
            names = {"DEFAULT"})
    void shouldReturnScanPolicyIfOnlyDefaultThreshold(AlertThreshold alertThreshold) {
        // Given
        ActiveScanJob job = new ActiveScanJob();
        AutomationProgress progress = new AutomationProgress();
        LinkedHashMap<String, LinkedHashMap<?, ?>> data = new LinkedHashMap<>();
        LinkedHashMap<String, String> policyDefn = new LinkedHashMap<>();
        policyDefn.put("defaultThreshold", alertThreshold.name());
        data.put("policyDefinition", policyDefn);

        // When
        job.setJobData(data);
        job.verifyParameters(progress);
        ScanPolicy policy = job.getData().getPolicyDefinition().getScanPolicy(null, progress);

        // Then
        assertThat(policy, is(notNullValue()));
        assertThat(policy.getDefaultStrength(), is(AttackStrength.MEDIUM));
        assertThat(policy.getDefaultThreshold(), is(alertThreshold));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldSetScanPolicyDefaults() throws MalformedURLException {
        // Given
        ActiveScanJob job = new ActiveScanJob();
        AutomationProgress progress = new AutomationProgress();
        LinkedHashMap<String, String> policyDefn = new LinkedHashMap<>();
        policyDefn.put("defaultStrength", "LOW");
        policyDefn.put("defaultThreshold", "high");
        LinkedHashMap<String, LinkedHashMap<?, ?>> data = new LinkedHashMap<>();
        data.put("policyDefinition", policyDefn);

        // When
        job.setJobData(data);
        job.verifyParameters(progress);
        ScanPolicy policy = job.getData().getPolicyDefinition().getScanPolicy(null, progress);

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
        ActiveScanJob job = new ActiveScanJob();
        AutomationProgress progress = new AutomationProgress();
        LinkedHashMap<String, String> policyDefn = new LinkedHashMap<>();
        policyDefn.put("defaultThreshold", "off");
        LinkedHashMap<String, LinkedHashMap<?, ?>> data = new LinkedHashMap<>();
        data.put("policyDefinition", policyDefn);

        // When
        job.setJobData(data);
        job.verifyParameters(progress);
        ScanPolicy policy = job.getData().getPolicyDefinition().getScanPolicy(null, progress);

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
        ActiveScanJob job = new ActiveScanJob();
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
        ScanPolicy policy = job.getData().getPolicyDefinition().getScanPolicy(null, progress);

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
        ActiveScanJob job = new ActiveScanJob();
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
        ScanPolicy policy = job.getData().getPolicyDefinition().getScanPolicy(null, progress);

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
        ActiveScanJob job = new ActiveScanJob();
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
        job.getData().getPolicyDefinition().getScanPolicy(null, progress);

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
        ActiveScanJob job = new ActiveScanJob();
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
        ActiveScanJob job = new ActiveScanJob();
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
        ActiveScanJob job = new ActiveScanJob();
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
        ActiveScanJob job = new ActiveScanJob();
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
    void shouldVerifyParameters() {
        // Given
        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.getAllUserNames()).willReturn(List.of("user0", "user1"));
        ActiveScanJob job = new ActiveScanJob();
        job.setEnv(env);
        AutomationProgress progress = new AutomationProgress();

        String yamlStr =
                """
                    parameters:
                      context: "context1"
                      user: "user1"
                      policy: "policy1"
                      maxRuleDurationInMins: 1
                      maxScanDurationInMins: 10
                      addQueryParam: true
                      defaultPolicy: "policy2"
                      delayInMs: 10
                      handleAntiCSRFTokens: true
                      injectPluginIdInHeader: true
                      scanHeadersAllRequests: true
                      threadPerHost: 2
                      maxAlertsPerRule: 5
                """;

        Object data = new Yaml().load(yamlStr);
        job.setJobData(((LinkedHashMap<?, ?>) data));

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(job.getParameters().getContext(), is(equalTo("context1")));
        assertThat(job.getParameters().getUser(), is(equalTo("user1")));
        assertThat(job.getParameters().getPolicy(), is(equalTo("policy1")));
        assertThat(job.getParameters().getMaxRuleDurationInMins(), is(equalTo(1)));
        assertThat(job.getParameters().getMaxScanDurationInMins(), is(equalTo(10)));
        assertThat(job.getParameters().getAddQueryParam(), is(equalTo(true)));
        assertThat(job.getParameters().getDefaultPolicy(), is(equalTo("policy2")));
        assertThat(job.getParameters().getDelayInMs(), is(equalTo(10)));
        assertThat(job.getParameters().getHandleAntiCSRFTokens(), is(equalTo(true)));
        assertThat(job.getParameters().getInjectPluginIdInHeader(), is(equalTo(true)));
        assertThat(job.getParameters().getScanHeadersAllRequests(), is(equalTo(true)));
        assertThat(job.getParameters().getThreadPerHost(), is(equalTo(2)));
        assertThat(job.getParameters().getMaxAlertsPerRule(), is(equalTo(5)));
    }
}
