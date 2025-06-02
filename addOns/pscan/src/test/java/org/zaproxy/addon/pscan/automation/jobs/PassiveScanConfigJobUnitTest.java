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
package org.zaproxy.addon.pscan.automation.jobs;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.OptionsParam;
import org.yaml.snakeyaml.Yaml;
import org.zaproxy.addon.automation.AutomationJob.Order;
import org.zaproxy.addon.automation.AutomationPlan;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.addon.pscan.ExtensionPassiveScan2;
import org.zaproxy.addon.pscan.PassiveScannersManager;
import org.zaproxy.addon.pscan.internal.PassiveScannerOptions;
import org.zaproxy.addon.pscan.internal.RegexAutoTagScanner;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.utils.I18N;

class PassiveScanConfigJobUnitTest {

    private PassiveScannersManager scannersManager;
    private ExtensionPassiveScan2 pscan;
    private PassiveScannerOptions options;

    @BeforeEach
    void setUp() throws Exception {
        Constant.messages = new I18N(Locale.ENGLISH);

        Model model = mock(Model.class);
        Model.setSingletonForTesting(model);
        OptionsParam optionsParam = mock(OptionsParam.class);
        given(model.getOptionsParam()).willReturn(optionsParam);
        options = mock(PassiveScannerOptions.class);
        given(optionsParam.getParamSet(PassiveScannerOptions.class)).willReturn(options);

        pscan = mock(ExtensionPassiveScan2.class);
        scannersManager = mock(PassiveScannersManager.class);
        given(pscan.getPassiveScannersManager()).willReturn(scannersManager);

        given(pscan.getModel()).willReturn(model);

        ExtensionLoader extensionLoader = mock(ExtensionLoader.class);
        given(extensionLoader.getExtension(ExtensionPassiveScan2.class)).willReturn(pscan);

        Control.initSingletonForTesting(model, extensionLoader);
    }

    @Test
    void shouldReturnDefaultFields() {
        // Given / When
        PassiveScanConfigJob job = new PassiveScanConfigJob();

        // Then
        assertThat(job.getType(), is(equalTo("passiveScan-config")));
        assertThat(job.getName(), is(equalTo("passiveScan-config")));
        assertThat(job.getOrder(), is(equalTo(Order.CONFIGS)));
        assertThat(job.getParamMethodObject(), is(job));
        assertThat(job.getParamMethodName(), is("getPassiveScannerOptions"));
        assertThat(job.getParameters().getEnableTags(), is(equalTo(false)));
    }

    @Test
    void shouldReturnNoCustomConfigParams() {
        // Given
        PassiveScanConfigJob job = new PassiveScanConfigJob();

        // When
        Map<String, String> params = job.getCustomConfigParameters();

        // Then
        assertThat(params.size(), is(equalTo(0)));
    }

    @Test
    void shouldGetOptions() {
        // Given
        AutomationProgress progress = new AutomationProgress();

        // When
        PassiveScanConfigJob job = new PassiveScanConfigJob();
        Object o = JobUtils.getJobOptions(job, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(o, is(instanceOf(PassiveScannerOptions.class)));
    }

    @Test
    void shouldApplyParameters() {
        // Given
        String yamlStr =
                "parameters:\n"
                        + "  maxAlertsPerRule: 2\n"
                        + "  scanOnlyInScope: true\n"
                        + "  maxBodySizeInBytesToScan: 1000\n"
                        + "  enableTags: true";
        AutomationProgress progress = new AutomationProgress();
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);

        PassiveScanConfigJob job = new PassiveScanConfigJob();

        // When
        job.setJobData(((LinkedHashMap<?, ?>) data));
        job.verifyParameters(progress);
        job.applyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        verify(options).setMaxAlertsPerRule(2);
        verify(options).setScanOnlyInScope(true);
        verify(options).setMaxBodySizeInBytesToScan(1000);
        assertThat(job.getParameters().getEnableTags(), is(equalTo(true)));
    }

    @Test
    void shouldResetParameters() {
        // Given
        String yamlStr =
                "parameters:\n"
                        + "  maxAlertsPerRule: 2\n"
                        + "  scanOnlyInScope: true\n"
                        + "  maxBodySizeInBytesToScan: 1000";
        AutomationProgress progress = new AutomationProgress();
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);

        PassiveScanConfigJob job = new PassiveScanConfigJob();
        job.setPlan(mock(AutomationPlan.class));
        given(options.getMaxBodySizeInBytesToScan()).willReturn(200);
        given(options.isScanOnlyInScope()).willReturn(false);
        given(options.getMaxAlertsPerRule()).willReturn(8);

        InOrder inOrder = inOrder(options);

        // When
        job.planStarted();
        job.setJobData(((LinkedHashMap<?, ?>) data));
        job.verifyParameters(progress);
        job.applyParameters(progress);
        job.planFinished();

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        inOrder.verify(options).setMaxAlertsPerRule(2);
        inOrder.verify(options).setMaxBodySizeInBytesToScan(1000);
        inOrder.verify(options).setScanOnlyInScope(true);
        inOrder.verify(options).setMaxAlertsPerRule(8);
        inOrder.verify(options).setMaxBodySizeInBytesToScan(200);
        inOrder.verify(options).setScanOnlyInScope(false);
    }

    @Test
    void shouldWarnOnBadParameter() {
        // Given
        String yamlStr =
                "parameters:\n"
                        + "  maxAlertsPerRule: 2\n"
                        + "  badParam: true\n"
                        + "  maxBodySizeInBytesToScan: 1000";
        AutomationProgress progress = new AutomationProgress();
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);

        PassiveScanConfigJob job = new PassiveScanConfigJob();

        // When
        job.setJobData(((LinkedHashMap<?, ?>) data));
        job.verifyParameters(progress);
        job.applyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.getWarnings().size(), is(equalTo(1)));
        assertThat(
                progress.getWarnings().get(0), is(equalTo("!automation.error.options.unknown!")));
        verify(options).setMaxAlertsPerRule(2);
        verify(options).setScanOnlyInScope(true);
        verify(options).setMaxBodySizeInBytesToScan(1000);
    }

    @Test
    void shouldSetRules() {
        // Given
        String yamlStr =
                "rules:\n" + "- id: 1\n" + "  threshold: Low\n" + "- id: 3\n" + "  threshold: High";

        TestPluginScanner rule1 = new TestPluginScanner(1);
        TestPluginScanner rule2 = new TestPluginScanner(2);
        TestPluginScanner rule3 = new TestPluginScanner(3);
        given(scannersManager.getScanRule(1)).willReturn(rule1);
        given(scannersManager.getScanRule(2)).willReturn(rule2);
        given(scannersManager.getScanRule(3)).willReturn(rule3);

        AutomationProgress progress = new AutomationProgress();
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data = (LinkedHashMap<?, ?>) yaml.load(yamlStr);

        PassiveScanConfigJob job = new PassiveScanConfigJob();

        // When
        job.setJobData(data);
        job.verifyParameters(progress);
        job.applyParameters(progress);
        job.runJob(null, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(rule1.getAlertThreshold(), is(equalTo(AlertThreshold.LOW)));
        assertThat(rule2.getAlertThreshold(), is(equalTo(AlertThreshold.MEDIUM)));
        assertThat(rule3.getAlertThreshold(), is(equalTo(AlertThreshold.HIGH)));
    }

    @Test
    void shouldWarnOnUnknownRule() {
        // Given
        String yamlStr =
                "rules:\n" + "- id: 4\n" + "  threshold: Low\n" + "- id: 3\n" + "  threshold: High";

        TestPluginScanner rule1 = new TestPluginScanner(1);
        TestPluginScanner rule2 = new TestPluginScanner(2);
        TestPluginScanner rule3 = new TestPluginScanner(3);
        given(scannersManager.getScanRule(1)).willReturn(rule1);
        given(scannersManager.getScanRule(2)).willReturn(rule2);
        given(scannersManager.getScanRule(3)).willReturn(rule3);

        AutomationProgress progress = new AutomationProgress();
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data = (LinkedHashMap<?, ?>) yaml.load(yamlStr);

        PassiveScanConfigJob job = new PassiveScanConfigJob();

        // When
        job.setJobData(data);
        job.verifyParameters(progress);
        job.applyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.getWarnings().size(), is(equalTo(1)));
        assertThat(
                progress.getWarnings().get(0),
                is(equalTo("!pscan.automation.error.pscan.rule.unknown!")));
    }

    @Test
    void shouldIgnoreRuleWithNoId() {
        // Given
        String yamlStr =
                "rules:\n" + "- id:\n" + "  threshold: Low\n" + "- id: 3\n" + "  threshold: High";

        TestPluginScanner rule3 = new TestPluginScanner(3);
        given(scannersManager.getScanRule(3)).willReturn(rule3);

        AutomationProgress progress = new AutomationProgress();
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data = (LinkedHashMap<?, ?>) yaml.load(yamlStr);

        PassiveScanConfigJob job = new PassiveScanConfigJob();

        // When
        job.setJobData(data);
        job.verifyParameters(progress);
        job.applyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.getInfos().size(), is(equalTo(1)));
        assertThat(
                progress.getInfos().get(0), is(equalTo("!pscan.automation.info.pscan.rule.noid!")));
    }

    @Test
    void shouldDisableAllRules() {
        // Given
        String yamlStr = "parameters:\n" + "  disableAllRules: true";

        TestPluginScanner rule1 = new TestPluginScanner(1);
        TestPluginScanner rule2 = new TestPluginScanner(2);
        TestPluginScanner rule3 = new TestPluginScanner(3);
        List<PluginPassiveScanner> allRules = Arrays.asList(rule1, rule2, rule3);
        given(scannersManager.getScanRule(1)).willReturn(rule1);
        given(scannersManager.getScanRule(2)).willReturn(rule2);
        given(scannersManager.getScanRule(3)).willReturn(rule3);
        given(scannersManager.getScanRules()).willReturn(allRules);

        AutomationProgress progress = new AutomationProgress();
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data = (LinkedHashMap<?, ?>) yaml.load(yamlStr);

        PassiveScanConfigJob job = new PassiveScanConfigJob();

        // When
        job.setJobData(data);
        job.verifyParameters(progress);
        job.applyParameters(progress);
        job.runJob(null, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(rule1.isEnabled(), is(equalTo(false)));
        assertThat(rule2.isEnabled(), is(equalTo(false)));
        assertThat(rule3.isEnabled(), is(equalTo(false)));
    }

    @Test
    void shouldDisableAllRulesExceptSpecifiedOnes() {
        // Given
        String yamlStr =
                "parameters:\n"
                        + "  disableAllRules: true\n"
                        + "rules:\n"
                        + "- id: 1\n"
                        + "  threshold: Low\n"
                        + "- id: 3\n"
                        + "  threshold: High";

        TestPluginScanner rule1 = new TestPluginScanner(1);
        TestPluginScanner rule2 = new TestPluginScanner(2);
        TestPluginScanner rule3 = new TestPluginScanner(3);
        List<PluginPassiveScanner> allRules = Arrays.asList(rule1, rule2, rule3);
        given(scannersManager.getScanRule(1)).willReturn(rule1);
        given(scannersManager.getScanRule(2)).willReturn(rule2);
        given(scannersManager.getScanRule(3)).willReturn(rule3);
        given(scannersManager.getScanRules()).willReturn(allRules);

        AutomationProgress progress = new AutomationProgress();
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data = (LinkedHashMap<?, ?>) yaml.load(yamlStr);

        PassiveScanConfigJob job = new PassiveScanConfigJob();

        // When
        job.setJobData(data);
        job.verifyParameters(progress);
        job.applyParameters(progress);
        job.runJob(null, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(rule1.isEnabled(), is(equalTo(true)));
        assertThat(rule2.isEnabled(), is(equalTo(false)));
        assertThat(rule3.isEnabled(), is(equalTo(true)));
        assertThat(rule1.getAlertThreshold(), is(equalTo(AlertThreshold.LOW)));
        assertThat(rule2.getAlertThreshold(), is(equalTo(AlertThreshold.MEDIUM)));
        assertThat(rule3.getAlertThreshold(), is(equalTo(AlertThreshold.HIGH)));
    }

    @Test
    void shouldRejectBadEnableTagsParam() {
        // Given
        String yamlStr = "parameters:\n" + "  enableTags: test";
        AutomationProgress progress = new AutomationProgress();
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);

        PassiveScanConfigJob job = new PassiveScanConfigJob();

        // When
        job.setJobData(((LinkedHashMap<?, ?>) data));
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(progress.getErrors().get(0), is(equalTo("!automation.error.options.badbool!")));
    }

    @Test
    void shouldEnableTags() {
        // Given
        String yamlStr = "parameters:\n" + "  enableTags: true";
        AutomationProgress progress = new AutomationProgress();
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);

        PassiveScanConfigJob job = new PassiveScanConfigJob();

        RegexAutoTagScanner tag1 = new TestRegexAutoTagScanner();
        tag1.setEnabled(false);
        RegexAutoTagScanner tag2 = new TestRegexAutoTagScanner();
        tag2.setEnabled(false);
        given(options.getAutoTagScanners()).willReturn(Arrays.asList(tag1, tag2));

        // When
        job.setJobData(((LinkedHashMap<?, ?>) data));
        job.verifyParameters(progress);
        job.applyParameters(progress);
        job.runJob(null, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(tag1.isEnabled(), is(equalTo(true)));
        assertThat(tag2.isEnabled(), is(equalTo(true)));
    }

    @Test
    void shouldDisableTags() {
        // Given
        String yamlStr = "parameters:\n" + "  enableTags: false";
        AutomationProgress progress = new AutomationProgress();
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);

        PassiveScanConfigJob job = new PassiveScanConfigJob();

        RegexAutoTagScanner tag1 = new TestRegexAutoTagScanner();
        tag1.setEnabled(true);
        RegexAutoTagScanner tag2 = new TestRegexAutoTagScanner();
        tag2.setEnabled(true);
        given(options.getAutoTagScanners()).willReturn(Arrays.asList(tag1, tag2));

        // When
        job.setJobData(((LinkedHashMap<?, ?>) data));
        job.verifyParameters(progress);
        job.applyParameters(progress);
        job.runJob(null, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(tag1.isEnabled(), is(equalTo(false)));
        assertThat(tag2.isEnabled(), is(equalTo(false)));
    }

    @Test
    void shouldDisableTagsByDefault() {
        // Given
        String yamlStr = "parameters:\n" + "  enableTags: ";
        AutomationProgress progress = new AutomationProgress();
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);

        PassiveScanConfigJob job = new PassiveScanConfigJob();

        RegexAutoTagScanner tag1 = new RegexAutoTagScanner() {};
        tag1.setEnabled(true);
        RegexAutoTagScanner tag2 = new RegexAutoTagScanner() {};
        tag2.setEnabled(true);
        given(options.getAutoTagScanners()).willReturn(Arrays.asList(tag1, tag2));

        // When
        job.setJobData(((LinkedHashMap<?, ?>) data));
        job.verifyParameters(progress);
        job.applyParameters(progress);
        job.runJob(null, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(tag1.isEnabled(), is(equalTo(false)));
        assertThat(tag2.isEnabled(), is(equalTo(false)));
    }

    private class TestPluginScanner extends PluginPassiveScanner {

        private int id;

        public TestPluginScanner(int id) {
            this.id = id;
        }

        @Override
        public int getPluginId() {
            return this.id;
        }

        @Override
        public String getName() {
            return null;
        }
    }

    private class TestRegexAutoTagScanner extends RegexAutoTagScanner {
        // Nothing to do.
    }
}
