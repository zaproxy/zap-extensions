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
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob.Order;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.extension.pscan.ExtensionPassiveScan;
import org.zaproxy.zap.utils.I18N;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class PassiveScanWaitJobUnitTest {

    private static MockedStatic<CommandLine> mockedCmdLine;

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
    }

    @Test
    void shouldReturnDefaultFields() {
        // Given
        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
        ExtensionLoader extensionLoader = mock(ExtensionLoader.class, withSettings().lenient());
        ExtensionPassiveScan extPscan = mock(ExtensionPassiveScan.class, withSettings().lenient());
        given(extensionLoader.getExtension(ExtensionPassiveScan.class)).willReturn(extPscan);

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
        Model.getSingleton().getOptionsParam().load(new ZapXmlConfiguration());

        // When
        PassiveScanWaitJob job = new PassiveScanWaitJob();

        // Then
        assertThat(job.getType(), is(equalTo("passiveScan-wait")));
        assertThat(job.getName(), is(equalTo("passiveScan-wait")));
        assertThat(job.getOrder(), is(equalTo(Order.AFTER_EXPLORE)));
        assertThat(job.getParamMethodObject(), is(nullValue()));
        assertThat(job.getParamMethodName(), is(nullValue()));
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

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Test
    void shouldApplyParams() {
        // Given
        PassiveScanWaitJob job = new PassiveScanWaitJob();
        AutomationProgress progress = new AutomationProgress();
        int duration = 10;
        Map map = new HashMap();
        map.put("maxDuration", Integer.toString(duration));
        LinkedHashMap<?, ?> params = new LinkedHashMap(map);
        LinkedHashMap<String, Object> jobData = new LinkedHashMap<>();
        jobData.put("parameters", params);

        // When
        job.setJobData(jobData);
        job.verifyParameters(progress);
        job.applyParameters(progress);

        // Then
        assertThat(job.getParameters().getMaxDuration(), is(equalTo(duration)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Test
    void shouldWarnOnUnknownParams() {
        // Given
        PassiveScanWaitJob job = new PassiveScanWaitJob();
        AutomationProgress progress = new AutomationProgress();
        Map map = new HashMap();
        map.put("test", "test");
        LinkedHashMap<?, ?> params = new LinkedHashMap(map);
        LinkedHashMap<String, Object> jobData = new LinkedHashMap<>();
        jobData.put("parameters", params);

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
        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
        ExtensionLoader extensionLoader = mock(ExtensionLoader.class, withSettings().lenient());
        ExtensionPassiveScan extAuto = mock(ExtensionPassiveScan.class, withSettings().lenient());
        given(extensionLoader.getExtension(ExtensionPassiveScan.class)).willReturn(extAuto);

        when(extAuto.getRecordsToScan())
                .thenAnswer(
                        new Answer<Integer>() {
                            private int records = 5;

                            @Override
                            public Integer answer(InvocationOnMock invocation) {
                                records = records - 1;
                                return records;
                            }
                        });

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
        Model.getSingleton().getOptionsParam().load(new ZapXmlConfiguration());

        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = mock(AutomationEnvironment.class);

        PassiveScanWaitJob job = new PassiveScanWaitJob();

        // When
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.getJobResultData("passiveScanData"), is(notNullValue()));
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Test
    void shouldExitIfPassiveScanTakesLongerThanConfig() {
        // Given
        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
        ExtensionLoader extensionLoader = mock(ExtensionLoader.class, withSettings().lenient());
        ExtensionPassiveScan extAuto = mock(ExtensionPassiveScan.class, withSettings().lenient());
        given(extensionLoader.getExtension(ExtensionPassiveScan.class)).willReturn(extAuto);
        given(extAuto.getRecordsToScan()).willReturn(1);

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
        Model.getSingleton().getOptionsParam().load(new ZapXmlConfiguration());

        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = mock(AutomationEnvironment.class);

        PassiveScanWaitJob job = new PassiveScanWaitJob();

        int duration = 1;
        Map map = new HashMap();
        map.put("maxDuration", Integer.toString(duration));
        LinkedHashMap<?, ?> params = new LinkedHashMap(map);
        LinkedHashMap<String, Object> jobData = new LinkedHashMap<>();
        jobData.put("parameters", params);

        // When
        job.setJobData(jobData);
        job.verifyParameters(progress);
        job.applyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.getJobResultData("passiveScanData"), is(notNullValue()));
    }
}
