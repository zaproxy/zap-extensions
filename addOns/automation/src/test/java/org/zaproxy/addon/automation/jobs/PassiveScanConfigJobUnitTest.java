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
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.parosproxy.paros.CommandLine;
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
import org.zaproxy.zap.extension.pscan.ExtensionPassiveScan;
import org.zaproxy.zap.extension.pscan.PassiveScanParam;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.extension.pscan.scanner.RegexAutoTagScanner;
import org.zaproxy.zap.utils.I18N;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class PassiveScanConfigJobUnitTest {

    private static MockedStatic<CommandLine> mockedCmdLine;

    private ExtensionLoader extensionLoader;
    private ExtensionPassiveScan extPscan;
    private PassiveScanParam pscanParam;

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
        OptionsParam optionsParam = mock(OptionsParam.class);
        given(model.getOptionsParam()).willReturn(optionsParam);
        pscanParam = mock(PassiveScanParam.class);
        given(optionsParam.getParamSet(PassiveScanParam.class)).willReturn(pscanParam);

        extensionLoader = mock(ExtensionLoader.class, withSettings().lenient());
        extPscan = new ExtensionPassiveScan();
        given(extensionLoader.getExtension(ExtensionPassiveScan.class)).willReturn(extPscan);

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
        Model.getSingleton().getOptionsParam().load(new ZapXmlConfiguration());
    }

    @Test
    void shouldReturnDefaultFields() {
        // Given / When
        PassiveScanConfigJob job = new PassiveScanConfigJob();

        // Then
        assertThat(job.getType(), is(equalTo("passiveScan-config")));
        assertThat(job.getName(), is(equalTo("passiveScan-config")));
        assertThat(job.getOrder(), is(equalTo(Order.CONFIGS)));
        assertThat(job.getParamMethodObject(), is(extPscan));
        assertThat(job.getParamMethodName(), is("getPassiveScanParam"));
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
        assertThat(o, is(notNullValue()));
        assertThat(o.getClass(), is(equalTo(PassiveScanParam.class)));
        assertThat(((PassiveScanParam) o).getMaxAlertsPerRule(), is(equalTo(0)));
        assertThat(((PassiveScanParam) o).isScanOnlyInScope(), is(equalTo(false)));
        assertThat(((PassiveScanParam) o).getMaxBodySizeInBytesToScan(), is(equalTo(0)));
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
        PassiveScanParam psp = (PassiveScanParam) JobUtils.getJobOptions(job, progress);
        psp.load(new ZapXmlConfiguration());

        // When
        job.setJobData(((LinkedHashMap<?, ?>) data));
        job.verifyParameters(progress);
        job.applyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(psp.getMaxAlertsPerRule(), is(equalTo(2)));
        assertThat(psp.isScanOnlyInScope(), is(equalTo(true)));
        assertThat(psp.getMaxBodySizeInBytesToScan(), is(equalTo(1000)));
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
        PassiveScanParam psp = (PassiveScanParam) JobUtils.getJobOptions(job, progress);
        psp.load(new ZapXmlConfiguration());
        psp.setMaxBodySizeInBytesToScan(200);
        psp.setScanOnlyInScope(false);
        psp.setMaxAlertsPerRule(8);

        // When
        job.planStarted();
        job.setJobData(((LinkedHashMap<?, ?>) data));
        job.verifyParameters(progress);
        job.applyParameters(progress);
        job.planFinished();

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(psp.getMaxAlertsPerRule(), is(equalTo(8)));
        assertThat(psp.isScanOnlyInScope(), is(equalTo(false)));
        assertThat(psp.getMaxBodySizeInBytesToScan(), is(equalTo(200)));
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
        PassiveScanParam psp = (PassiveScanParam) JobUtils.getJobOptions(job, progress);
        psp.load(new ZapXmlConfiguration());

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
        assertThat(psp.getMaxAlertsPerRule(), is(equalTo(2)));
        assertThat(psp.isScanOnlyInScope(), is(equalTo(true)));
        assertThat(psp.getMaxBodySizeInBytesToScan(), is(equalTo(1000)));
    }

    @Test
    void shouldSetRules() {
        // Given
        String yamlStr =
                "rules:\n" + "- id: 1\n" + "  threshold: Low\n" + "- id: 3\n" + "  threshold: High";

        // Need to mock the extension for this test
        extPscan = mock(ExtensionPassiveScan.class);
        given(extensionLoader.getExtension(ExtensionPassiveScan.class)).willReturn(extPscan);
        TestPluginScanner rule1 = new TestPluginScanner(1);
        TestPluginScanner rule2 = new TestPluginScanner(2);
        TestPluginScanner rule3 = new TestPluginScanner(3);
        given(extPscan.getPluginPassiveScanner(1)).willReturn(rule1);
        given(extPscan.getPluginPassiveScanner(2)).willReturn(rule2);
        given(extPscan.getPluginPassiveScanner(3)).willReturn(rule3);

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

        // Need to mock the extension for this test
        extPscan = mock(ExtensionPassiveScan.class);
        given(extensionLoader.getExtension(ExtensionPassiveScan.class)).willReturn(extPscan);
        TestPluginScanner rule1 = new TestPluginScanner(1);
        TestPluginScanner rule2 = new TestPluginScanner(2);
        TestPluginScanner rule3 = new TestPluginScanner(3);
        given(extPscan.getPluginPassiveScanner(1)).willReturn(rule1);
        given(extPscan.getPluginPassiveScanner(2)).willReturn(rule2);
        given(extPscan.getPluginPassiveScanner(3)).willReturn(rule3);

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
                is(equalTo("!automation.error.pscan.rule.unknown!")));
    }

    @Test
    void shouldIgnoreRuleWithNoId() {
        // Given
        String yamlStr =
                "rules:\n" + "- id:\n" + "  threshold: Low\n" + "- id: 3\n" + "  threshold: High";

        // Need to mock the extension for this test
        extPscan = mock(ExtensionPassiveScan.class);
        given(extensionLoader.getExtension(ExtensionPassiveScan.class)).willReturn(extPscan);
        TestPluginScanner rule3 = new TestPluginScanner(3);
        given(extPscan.getPluginPassiveScanner(3)).willReturn(rule3);

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
        assertThat(progress.getInfos().get(0), is(equalTo("!automation.info.pscan.rule.noid!")));
    }

    @Test
    void shouldRejectBadEnableTagsParam() {
        // Given
        String yamlStr = "parameters:\n" + "  enableTags: test";
        AutomationProgress progress = new AutomationProgress();
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);

        PassiveScanConfigJob job = new PassiveScanConfigJob();
        PassiveScanParam psp = (PassiveScanParam) JobUtils.getJobOptions(job, progress);
        psp.load(new ZapXmlConfiguration());

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
        PassiveScanParam psp = (PassiveScanParam) JobUtils.getJobOptions(job, progress);
        psp.load(new ZapXmlConfiguration());

        RegexAutoTagScanner tag1 = new RegexAutoTagScanner();
        tag1.setEnabled(false);
        RegexAutoTagScanner tag2 = new RegexAutoTagScanner();
        tag2.setEnabled(false);
        given(pscanParam.getAutoTagScanners()).willReturn(Arrays.asList(tag1, tag2));

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
        PassiveScanParam psp = (PassiveScanParam) JobUtils.getJobOptions(job, progress);
        psp.load(new ZapXmlConfiguration());

        RegexAutoTagScanner tag1 = new RegexAutoTagScanner();
        tag1.setEnabled(true);
        RegexAutoTagScanner tag2 = new RegexAutoTagScanner();
        tag2.setEnabled(true);
        given(pscanParam.getAutoTagScanners()).willReturn(Arrays.asList(tag1, tag2));

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
        PassiveScanParam psp = (PassiveScanParam) JobUtils.getJobOptions(job, progress);
        psp.load(new ZapXmlConfiguration());

        RegexAutoTagScanner tag1 = new RegexAutoTagScanner();
        tag1.setEnabled(true);
        RegexAutoTagScanner tag2 = new RegexAutoTagScanner();
        tag2.setEnabled(true);
        given(pscanParam.getAutoTagScanners()).willReturn(Arrays.asList(tag1, tag2));

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
}
