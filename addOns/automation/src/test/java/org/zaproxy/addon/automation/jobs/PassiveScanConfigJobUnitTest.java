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
import org.yaml.snakeyaml.Yaml;
import org.zaproxy.addon.automation.AutomationJob.Order;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.extension.pscan.ExtensionPassiveScan;
import org.zaproxy.zap.extension.pscan.PassiveScanParam;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.utils.I18N;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class PassiveScanConfigJobUnitTest {

    private static MockedStatic<CommandLine> mockedCmdLine;

    private ExtensionLoader extensionLoader;
    private ExtensionPassiveScan extPscan;

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
                        + "  maxBodySizeInBytesToScan: 1000";
        AutomationProgress progress = new AutomationProgress();
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);

        PassiveScanConfigJob job = new PassiveScanConfigJob();
        PassiveScanParam psp = (PassiveScanParam) JobUtils.getJobOptions(job, progress);
        psp.load(new ZapXmlConfiguration());

        // When
        LinkedHashMap<?, ?> params =
                (LinkedHashMap<?, ?>) ((LinkedHashMap<?, ?>) data).get("parameters");
        job.applyParameters(params, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(psp.getMaxAlertsPerRule(), is(equalTo(2)));
        assertThat(psp.isScanOnlyInScope(), is(equalTo(true)));
        assertThat(psp.getMaxBodySizeInBytesToScan(), is(equalTo(1000)));
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
        LinkedHashMap<?, ?> params =
                (LinkedHashMap<?, ?>) ((LinkedHashMap<?, ?>) data).get("parameters");
        job.applyParameters(params, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.getWarnings().size(), is(equalTo(1)));
        assertThat(
                progress.getWarnings().get(0), is(equalTo("!automation.error.options.unknown!")));
        assertThat(psp.getMaxAlertsPerRule(), is(equalTo(2)));
        assertThat(psp.isScanOnlyInScope(), is(equalTo(false)));
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
        job.runJob(null, data, progress);

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
        job.runJob(null, data, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.getWarnings().size(), is(equalTo(1)));
        assertThat(
                progress.getWarnings().get(0),
                is(equalTo("!automation.error.pscan.rule.unknown!")));
        assertThat(rule2.getAlertThreshold(), is(equalTo(AlertThreshold.MEDIUM)));
        assertThat(rule3.getAlertThreshold(), is(equalTo(AlertThreshold.HIGH)));
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
        public void setParent(PassiveScanThread parent) {}

        @Override
        public String getName() {
            return null;
        }
    }
}
