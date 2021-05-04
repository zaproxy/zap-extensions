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
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatcher;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.parosproxy.paros.core.scanner.ScannerParam;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob.Order;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.extension.ascan.ActiveScan;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.extension.ascan.ScanPolicy;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.Target;
import org.zaproxy.zap.utils.I18N;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class ActiveScanJobUnitTest {

    private static MockedStatic<CommandLine> mockedCmdLine;
    private ExtensionActiveScan extAScan;

    @BeforeAll
    static void init() {
        mockedCmdLine = Mockito.mockStatic(CommandLine.class);
    }

    @AfterAll
    static void close() {
        mockedCmdLine.close();
    }

    @BeforeEach
    void setUp() throws Exception {
        Constant.messages = new I18N(Locale.ENGLISH);

        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
        ExtensionLoader extensionLoader = mock(ExtensionLoader.class, withSettings().lenient());
        extAScan = mock(ExtensionActiveScan.class, withSettings().lenient());
        given(extensionLoader.getExtension(ExtensionActiveScan.class)).willReturn(extAScan);

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
    void shouldApplyCustomConfigParams() {
        // Given
        ActiveScanJob job = new ActiveScanJob();

        // When
        job.applyCustomParameter("maxScanDurationInMins", "12");
        job.applyCustomParameter("policy", "testPolicy");

        // Then
        assertThat(job.getMaxDuration(), is(equalTo(12)));
        assertThat(job.getPolicy(), is(equalTo("testPolicy")));
    }

    @Test
    void shouldFailWithUnknownConfigParam() {
        // Given
        ActiveScanJob job = new ActiveScanJob();

        // When
        boolean result = job.applyCustomParameter("blah", "12");

        // Then
        assertThat(result, is(equalTo(false)));
    }

    @Test
    void shouldReturnConfigParams() throws MalformedURLException {
        // Given
        ActiveScanJob job = new ActiveScanJob();

        // When
        Map<String, String> params =
                job.getConfigParameters(new ScannerParamWrapper(), job.getParamMethodName());

        // Then
        assertThat(params.size(), is(equalTo(9)));

        assertThat(params.containsKey("addQueryParam"), is(equalTo(true)));
        assertThat(params.containsKey("defaultPolicy"), is(equalTo(true)));
        assertThat(params.containsKey("delayInMs"), is(equalTo(true)));
        assertThat(params.containsKey("handleAntiCSRFTokens"), is(equalTo(true)));
        assertThat(params.containsKey("injectPluginIdInHeader"), is(equalTo(true)));
        assertThat(params.containsKey("maxRuleDurationInMins"), is(equalTo(true)));
        assertThat(params.containsKey("maxScanDurationInMins"), is(equalTo(true)));
        assertThat(params.containsKey("scanHeadersAllRequests"), is(equalTo(true)));
        assertThat(params.containsKey("threadPerHost"), is(equalTo(true)));
    }

    private static class ScannerParamWrapper {
        @SuppressWarnings("unused")
        public ScannerParam getScannerParam() {
            return new ScannerParam();
        }
    }

    @Test
    void shouldRunValidJob() throws MalformedURLException {
        // Given
        Constant.messages = new I18N(Locale.ENGLISH);
        Session session = mock(Session.class);
        Context context = mock(Context.class);
        given(session.getNewContext(any())).willReturn(context);

        given(extAScan.startScan(any(), any(), any())).willReturn(1);

        ActiveScan activeScan = mock(ActiveScan.class);
        given(activeScan.isStopped()).willReturn(true);
        given(extAScan.getScan(1)).willReturn(activeScan);

        AutomationProgress progress = new AutomationProgress();

        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.getUrlStringForContext(any())).willReturn("https://www.example.com");

        // When
        ActiveScanJob job = new ActiveScanJob();
        job.runJob(env, null, progress);

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
        job.applyCustomParameter("context", "Unknown");
        job.runJob(env, null, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().get(0), is(equalTo("!automation.error.context.unknown!")));
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

        given(extAScan.startScan(any(), any(), any())).willReturn(1);

        ActiveScan activeScan = mock(ActiveScan.class);
        given(activeScan.isStopped()).willReturn(true);
        given(extAScan.getScan(1)).willReturn(activeScan);

        AutomationProgress progress = new AutomationProgress();

        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.getUrlStringForContext(any())).willReturn("https://www.example.com");
        given(env.getContext("context1")).willReturn(context1);
        given(env.getContext("context2")).willReturn(context2);
        given(env.getDefaultContext()).willReturn(context1);

        // When
        ActiveScanJob job = new ActiveScanJob();
        job.applyCustomParameter("context", "context2");
        job.runJob(env, null, progress);

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
        Session session = mock(Session.class);
        Context context = mock(Context.class);
        given(session.getNewContext(any())).willReturn(context);

        given(extAScan.startScan(any(), any(), any())).willReturn(1);

        ActiveScan activeScan = mock(ActiveScan.class);
        given(activeScan.isStopped()).willReturn(false);
        given(extAScan.getScan(1)).willReturn(activeScan);

        AutomationProgress progress = new AutomationProgress();

        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.getUrlStringForContext(any())).willReturn("https://www.example.com");

        ActiveScanJob job = new ActiveScanJob();

        // When
        job.applyCustomParameter("maxScanDurationInMins", "1");
        job.runJob(env, null, progress);

        // Then
        assertThat(job.getType(), is(equalTo("activeScan")));
        assertThat(job.getOrder(), is(equalTo(Order.ATTACK)));
        assertThat(job.getParamMethodObject(), is(extAScan));
        assertThat(job.getParamMethodName(), is("getScannerParam"));

        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldReturnNullScanPolicyForNullData() throws MalformedURLException {
        // Given
        ActiveScanJob job = new ActiveScanJob();

        // When
        ScanPolicy policy = job.getScanPolicy(null, null);

        // Then
        assertThat(policy, is(nullValue()));
    }

    @Test
    void shouldReturnNullScanPolicyForEmptyData() throws MalformedURLException {
        // Given
        ActiveScanJob job = new ActiveScanJob();

        // When
        ScanPolicy policy = job.getScanPolicy(new LinkedHashMap<>(), null);

        // Then
        assertThat(policy, is(nullValue()));
    }

    @Test
    void shouldReturnWarningForBadScanPolicyData() throws MalformedURLException {
        // Given
        ActiveScanJob job = new ActiveScanJob();
        AutomationProgress progress = new AutomationProgress();
        LinkedHashMap<String, String> data = new LinkedHashMap<>();
        data.put("policyDefinition", "Incorrect");

        // When
        ScanPolicy policy = job.getScanPolicy(data, progress);

        // Then
        assertThat(policy, is(nullValue()));
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(
                progress.getWarnings().get(0), is(equalTo("!automation.error.options.badlist!")));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldReturnScanPolicyForDefaultData() throws MalformedURLException {
        // Given
        ActiveScanJob job = new ActiveScanJob();
        AutomationProgress progress = new AutomationProgress();
        LinkedHashMap<String, LinkedHashMap<?, ?>> data = new LinkedHashMap<>();
        data.put("policyDefinition", new LinkedHashMap<>());

        // When
        ScanPolicy policy = job.getScanPolicy(data, progress);

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
        ActiveScanJob job = new ActiveScanJob();
        AutomationProgress progress = new AutomationProgress();
        LinkedHashMap<String, String> policyDefn = new LinkedHashMap<>();
        policyDefn.put("defaultStrength", "LOW");
        policyDefn.put("defaultThreshold", "high");
        LinkedHashMap<String, LinkedHashMap<?, ?>> data = new LinkedHashMap<>();
        data.put("policyDefinition", policyDefn);

        // When
        ScanPolicy policy = job.getScanPolicy(data, progress);

        // Then
        assertThat(policy, is(notNullValue()));
        assertThat(policy.getDefaultStrength(), is(AttackStrength.LOW));
        assertThat(policy.getDefaultThreshold(), is(AlertThreshold.HIGH));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldDisableAllRulesWithString() throws MalformedURLException {
        // There is one built in rule, and mocking more is tricky outside of the package :/

        // Given
        ActiveScanJob job = new ActiveScanJob();
        AutomationProgress progress = new AutomationProgress();
        LinkedHashMap<String, String> policyDefn = new LinkedHashMap<>();
        policyDefn.put("defaultThreshold", "off");
        LinkedHashMap<String, LinkedHashMap<?, ?>> data = new LinkedHashMap<>();
        data.put("policyDefinition", policyDefn);

        // When
        ScanPolicy policy = job.getScanPolicy(data, progress);

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
    void shouldDisableAllRulesWithBoolean() throws MalformedURLException {
        // There is one built in rule, and mocking more is tricky outside of the package :/

        // Given
        ActiveScanJob job = new ActiveScanJob();
        AutomationProgress progress = new AutomationProgress();
        LinkedHashMap<String, Boolean> policyDefn = new LinkedHashMap<>();
        policyDefn.put("defaultThreshold", Boolean.FALSE);
        LinkedHashMap<String, LinkedHashMap<?, ?>> data = new LinkedHashMap<>();
        data.put("policyDefinition", policyDefn);

        // When
        ScanPolicy policy = job.getScanPolicy(data, progress);

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
        // There is one built in rule, and mocking more is tricky outside of the package :/

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
        ScanPolicy policy = job.getScanPolicy(data, progress);

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
    void shouldWarnOnUnknownRule() throws MalformedURLException {
        // Given
        ActiveScanJob job = new ActiveScanJob();
        AutomationProgress progress = new AutomationProgress();

        LinkedHashMap<String, Object> ruleDefn = new LinkedHashMap<>();
        ruleDefn.put("id", 1377);

        LinkedHashMap<String, List<?>> policyDefn = new LinkedHashMap<>();

        ArrayList<LinkedHashMap<?, ?>> rulesDefn = new ArrayList<>();
        rulesDefn.add(ruleDefn);
        policyDefn.put("rules", rulesDefn);

        LinkedHashMap<String, LinkedHashMap<?, ?>> data = new LinkedHashMap<>();
        data.put("policyDefinition", policyDefn);

        // When
        job.getScanPolicy(data, progress);

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
        job.getScanPolicy(data, progress);

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
        job.getScanPolicy(data, progress);

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
        job.getScanPolicy(data, progress);

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
        job.getScanPolicy(data, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(
                progress.getWarnings().get(0), is(equalTo("!automation.error.ascan.threshold!")));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }
}
