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
package org.zaproxy.zap.extension.alertFilters.automation;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Locale;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.yaml.snakeyaml.Yaml;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob.Order;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.extension.alertFilters.ContextAlertFilterManager;
import org.zaproxy.zap.extension.alertFilters.ExtensionAlertFilters;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.utils.I18N;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class AlertFilterJobUnitTest {

    @BeforeEach
    void setUp() throws Exception {
        Constant.messages = new I18N(Locale.ENGLISH);
    }

    @Test
    void shouldReturnDefaultFields() {
        // Given / When
        AlertFilterJob job = new AlertFilterJob();

        // Then
        assertThat(job.getType(), is(equalTo("alertFilter")));
        assertThat(job.getName(), is(equalTo("alertFilter")));
        assertThat(job.getOrder(), is(equalTo(Order.CONFIGS)));
        assertThat(job.getParamMethodObject(), is(nullValue()));
        assertThat(job.getParamMethodName(), is(nullValue()));
        assertThat(job.getAlertFilterCount(), is(equalTo(0)));
        assertThat(job.getData().getAlertFilters(), is(nullValue()));
        assertThat(job.getParameters().getDeleteGlobalAlerts(), is(nullValue()));
    }

    @Test
    void shouldWarnOnNoFilters() {
        // Given
        AutomationProgress progress = new AutomationProgress();
        AlertFilterJob job = new AlertFilterJob();
        String contextStr = "parameters: \n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> jobData =
                yaml.load(new ByteArrayInputStream(contextStr.getBytes(StandardCharsets.UTF_8)));

        // When
        job.setJobData(jobData);
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.getWarnings().size(), is(equalTo(1)));
        assertThat(
                progress.getWarnings().get(0),
                is(equalTo("!alertFilters.automation.error.nofilters!")));
    }

    @Test
    void shouldErrorOnBadFilters() {
        // Given
        AutomationProgress progress = new AutomationProgress();
        AlertFilterJob job = new AlertFilterJob();
        String contextStr = "parameters: \nalertFilters: 'A string'\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> jobData =
                yaml.load(new ByteArrayInputStream(contextStr.getBytes(StandardCharsets.UTF_8)));

        // When
        job.setJobData(jobData);
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(
                progress.getErrors().get(0),
                is(equalTo("!alertFilters.automation.error.badfilters!")));
    }

    @Test
    void shouldErrorOnMissingRuleId() {
        // Given
        AutomationProgress progress = new AutomationProgress();
        AlertFilterJob job = new AlertFilterJob();
        String contextStr = "parameters: \nalertFilters:\n- newRisk: 'Info'";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> jobData =
                yaml.load(new ByteArrayInputStream(contextStr.getBytes(StandardCharsets.UTF_8)));

        // When
        job.setJobData(jobData);
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(
                progress.getErrors().get(0),
                is(equalTo("!alertFilters.automation.error.noruleid!")));
    }

    @Test
    void shouldErrorOnMissingNewRisk() {
        // Given
        AutomationProgress progress = new AutomationProgress();
        AlertFilterJob job = new AlertFilterJob();
        String contextStr = "parameters: \nalertFilters:\n- ruleId: 1\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> jobData =
                yaml.load(new ByteArrayInputStream(contextStr.getBytes(StandardCharsets.UTF_8)));

        // When
        job.setJobData(jobData);
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(
                progress.getErrors().get(0),
                is(equalTo("!alertFilters.automation.error.badrisk!")));
    }

    @Test
    void shouldErrorOnBadNewRisk() {
        // Given
        AutomationProgress progress = new AutomationProgress();
        AlertFilterJob job = new AlertFilterJob();
        String contextStr = "parameters: \nalertFilters:\n- ruleId: 1\n  newRisk: 'blah'\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> jobData =
                yaml.load(new ByteArrayInputStream(contextStr.getBytes(StandardCharsets.UTF_8)));

        // When
        job.setJobData(jobData);
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(
                progress.getErrors().get(0),
                is(equalTo("!alertFilters.automation.error.badrisk!")));
    }

    @Test
    void shouldErrorOnBadUrlRegex() {
        // Given
        AutomationProgress progress = new AutomationProgress();
        AlertFilterJob job = new AlertFilterJob();
        String contextStr =
                "parameters: \nalertFilters:\n- ruleId: 1\n  newRisk: 'Info'\n  urlRegex: true\n  url: '*'\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> jobData =
                yaml.load(new ByteArrayInputStream(contextStr.getBytes(StandardCharsets.UTF_8)));

        // When
        job.setJobData(jobData);
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(
                progress.getErrors().get(0),
                is(equalTo("!alertFilters.automation.error.badurlregex!")));
    }

    @Test
    void shouldErrorOnBadParamRegex() {
        // Given
        AutomationProgress progress = new AutomationProgress();
        AlertFilterJob job = new AlertFilterJob();
        String contextStr =
                "parameters: \nalertFilters:\n- ruleId: 1\n  newRisk: 'Info'\n  parameterRegex: true\n  parameter: '*'\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> jobData =
                yaml.load(new ByteArrayInputStream(contextStr.getBytes(StandardCharsets.UTF_8)));

        // When
        job.setJobData(jobData);
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(
                progress.getErrors().get(0),
                is(equalTo("!alertFilters.automation.error.badparamregex!")));
    }

    @Test
    void shouldErrorOnBadAttackRegex() {
        // Given
        AutomationProgress progress = new AutomationProgress();
        AlertFilterJob job = new AlertFilterJob();
        String contextStr =
                "parameters: \nalertFilters:\n- ruleId: 1\n  newRisk: 'Info'\n  attackRegex: true\n  attack: '*'\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> jobData =
                yaml.load(new ByteArrayInputStream(contextStr.getBytes(StandardCharsets.UTF_8)));

        // When
        job.setJobData(jobData);
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(
                progress.getErrors().get(0),
                is(equalTo("!alertFilters.automation.error.badattackregex!")));
    }

    @Test
    void shouldErrorOnBadEvidenceRegex() {
        // Given
        AutomationProgress progress = new AutomationProgress();
        AlertFilterJob job = new AlertFilterJob();
        String contextStr =
                "parameters: \nalertFilters:\n- ruleId: 1\n  newRisk: 'Info'\n  evidenceRegex: true\n  evidence: '*'\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> jobData =
                yaml.load(new ByteArrayInputStream(contextStr.getBytes(StandardCharsets.UTF_8)));

        // When
        job.setJobData(jobData);
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(
                progress.getErrors().get(0),
                is(equalTo("!alertFilters.automation.error.badevidenceregex!")));
    }

    @Test
    void shouldParseValidData() {
        // Given
        AutomationProgress progress = new AutomationProgress();
        AlertFilterJob job = new AlertFilterJob();
        String contextStr =
                "parameters: \nalertFilters:\n- ruleId: 1\n  newRisk: 'Info'\n  context: 'example'\n  urlRegex: true\n  url: '.*'\n  parameterRegex: true\n  parameter: '.*'\n"
                        + "  url: '.*'\n  attackRegex: true\n  attack: '.*'\n  url: '.*'\n  evidenceRegex: true\n  evidence: '.*'\n  url: '.*'\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> jobData =
                yaml.load(new ByteArrayInputStream(contextStr.getBytes(StandardCharsets.UTF_8)));

        // When
        job.setJobData(jobData);
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldCreateGlobalFilter() {
        // Given
        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
        ExtensionLoader extensionLoader = mock(ExtensionLoader.class, withSettings().lenient());
        ExtensionAlertFilters extAF = mock(ExtensionAlertFilters.class, withSettings().lenient());
        given(extensionLoader.getExtension(ExtensionAlertFilters.class)).willReturn(extAF);

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
        Model.getSingleton().getOptionsParam().load(new ZapXmlConfiguration());

        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = new AutomationEnvironment(progress);
        AlertFilterJob job = new AlertFilterJob();
        String contextStr =
                "parameters: \nalertFilters:\n- ruleId: 1\n  newRisk: 'Low'\n  urlRegex: true\n  url: '.*'\n  parameterRegex: true\n  parameter: '.*'\n"
                        + "  url: '.*'\n  attackRegex: true\n  attack: '.*'\n  url: '.*'\n  evidenceRegex: true\n  evidence: '.*'\n  url: '.*'\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> jobData =
                yaml.load(new ByteArrayInputStream(contextStr.getBytes(StandardCharsets.UTF_8)));

        // When
        job.setJobData(jobData);
        job.verifyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
        verify(extAF, times(1)).addGlobalAlertFilter(any());
    }

    @Test
    void shouldCreateContextFilter() {
        // Given
        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
        ExtensionLoader extensionLoader = mock(ExtensionLoader.class, withSettings().lenient());
        ExtensionAlertFilters extAF = mock(ExtensionAlertFilters.class, withSettings().lenient());
        given(extensionLoader.getExtension(ExtensionAlertFilters.class)).willReturn(extAF);

        ContextAlertFilterManager cafm = new ContextAlertFilterManager(0);
        given(extAF.getContextAlertFilterManager(0)).willReturn(cafm);

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
        Model.getSingleton().getOptionsParam().load(new ZapXmlConfiguration());

        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = mock(AutomationEnvironment.class);
        Context context = mock(Context.class);
        given(env.getContext("example")).willReturn(context);

        AlertFilterJob job = new AlertFilterJob();
        String contextStr =
                "parameters: \nalertFilters:\n- ruleId: 1\n  newRisk: 'Medium'\n  context: 'example'\n  urlRegex: true\n  url: '.*'\n  parameterRegex: true\n  parameter: '.*'\n"
                        + "  url: '.*'\n  attackRegex: true\n  attack: '.*'\n  url: '.*'\n  evidenceRegex: true\n  evidence: '.*'\n  url: '.*'\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> jobData =
                yaml.load(new ByteArrayInputStream(contextStr.getBytes(StandardCharsets.UTF_8)));

        // When
        job.setJobData(jobData);
        job.verifyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(cafm.getAlertFilters().size(), is(equalTo(1)));
    }
}
