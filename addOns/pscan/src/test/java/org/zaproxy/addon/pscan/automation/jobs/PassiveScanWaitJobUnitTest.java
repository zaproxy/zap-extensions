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
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob.Order;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.pscan.ExtensionPassiveScan2;
import org.zaproxy.addon.pscan.PassiveScannersManager;
import org.zaproxy.zap.utils.I18N;

class PassiveScanWaitJobUnitTest {

    private ExtensionPassiveScan2 pscan;

    @BeforeEach
    void setUp() throws Exception {
        Constant.messages = new I18N(Locale.ENGLISH);

        pscan = mock(ExtensionPassiveScan2.class);
        PassiveScannersManager scannersManager = mock(PassiveScannersManager.class);
        given(pscan.getPassiveScannersManager()).willReturn(scannersManager);

        ExtensionLoader extensionLoader = mock(ExtensionLoader.class);
        given(extensionLoader.getExtension(ExtensionPassiveScan2.class)).willReturn(pscan);

        Control.initSingletonForTesting(mock(Model.class), extensionLoader);
    }

    @Test
    void shouldReturnDefaultFields() {
        // Given / When
        PassiveScanWaitJob job = new PassiveScanWaitJob();

        // Then
        assertThat(job.getType(), is(equalTo("passiveScan-wait")));
        assertThat(job.getName(), is(equalTo("passiveScan-wait")));
        assertThat(job.getOrder(), is(equalTo(Order.AFTER_EXPLORE)));
        assertThat(job.getParamMethodObject(), is(nullValue()));
        assertThat(job.getParamMethodName(), is(nullValue()));
        assertThat(job.getKeyAlertTestsResultData(), is("passiveScanData2"));
    }

    @Test
    void shouldReturnCustomConfigParams() {
        // Given
        PassiveScanWaitJob job = new PassiveScanWaitJob();

        // When
        Map<String, String> params = job.getCustomConfigParameters();

        // Then
        assertThat(params.size(), is(equalTo(1)));
        assertThat(params.containsKey("maxDuration"), is(equalTo(true)));
        assertThat(params.containsValue("0"), is(equalTo(true)));
    }

    @Test
    void shouldApplyParams() {
        // Given
        PassiveScanWaitJob job = new PassiveScanWaitJob();
        AutomationProgress progress = new AutomationProgress();
        int duration = 10;
        LinkedHashMap<String, Object> jobData = new LinkedHashMap<>();
        jobData.put("parameters", Map.of("maxDuration", duration));

        // When
        job.setJobData(jobData);
        job.verifyParameters(progress);
        job.applyParameters(progress);

        // Then
        assertThat(job.getParameters().getMaxDuration(), is(equalTo(duration)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldWarnOnUnknownParams() {
        // Given
        PassiveScanWaitJob job = new PassiveScanWaitJob();
        AutomationProgress progress = new AutomationProgress();
        LinkedHashMap<String, Object> jobData = new LinkedHashMap<>();
        jobData.put("parameters", Map.of("test", "test"));

        // When
        job.setJobData(jobData);
        job.verifyParameters(progress);
        job.applyParameters(progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.getWarnings().size(), is(equalTo(1)));
        assertThat(
                progress.getWarnings().get(0), is(equalTo("!automation.error.options.unknown!")));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldWaitForPassiveScan() {
        // Given
        when(pscan.getRecordsToScan())
                .thenAnswer(
                        new Answer<Integer>() {
                            private int records = 5;

                            @Override
                            public Integer answer(InvocationOnMock invocation) {
                                records = records - 1;
                                return records;
                            }
                        });

        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = mock(AutomationEnvironment.class);

        PassiveScanWaitJob job = new PassiveScanWaitJob();

        // When
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.getJobResultData("passiveScanData2"), is(notNullValue()));
    }

    @Test
    void shouldExitIfPassiveScanTakesLongerThanConfig() {
        // Given
        given(pscan.getRecordsToScan()).willReturn(1);

        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = mock(AutomationEnvironment.class);

        PassiveScanWaitJob job = new PassiveScanWaitJob();

        int duration = 1;
        LinkedHashMap<String, Object> jobData = new LinkedHashMap<>();
        jobData.put("parameters", Map.of("maxDuration", duration));

        // When
        job.setJobData(jobData);
        job.verifyParameters(progress);
        job.applyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.getJobResultData("passiveScanData2"), is(notNullValue()));
    }
}
