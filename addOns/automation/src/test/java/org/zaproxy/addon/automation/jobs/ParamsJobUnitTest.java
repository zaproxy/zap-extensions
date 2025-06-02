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
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.util.List;
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
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.automation.AutomationJob.Order;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.JobResultData;
import org.zaproxy.zap.utils.I18N;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class ParamsJobUnitTest {

    private static MockedStatic<CommandLine> mockedCmdLine;

    private ExtensionLoader extensionLoader;

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

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
        Model.getSingleton().getOptionsParam().load(new ZapXmlConfiguration());
    }

    @Test
    void shouldReturnDefaultFields() {
        // Given / When
        ParamsJob job = new ParamsJob();

        // Then
        assertThat(job.getType(), is(equalTo("params")));
        assertThat(job.getName(), is(equalTo("params")));
        assertThat(job.getOrder(), is(equalTo(Order.REPORT)));
        assertThat(job.isDataJob(), is(true));
        assertThat(job.getTemplateDataMin(), is(equalTo("")));
        assertThat(job.getTemplateDataMax(), is(equalTo("")));
        assertThat(job.getParamMethodObject(), is(nullValue()));
        assertThat(job.getParamMethodName(), is(nullValue()));
    }

    @Test
    void shouldReturnNoCustomConfigParams() {
        // Given
        ParamsJob job = new ParamsJob();

        // When
        Map<String, String> params = job.getCustomConfigParameters();

        // Then
        assertThat(params.size(), is(equalTo(0)));
    }

    @Test
    void shouldReturnJobResultData() {
        // Given
        ParamsJob job = new ParamsJob();

        // When
        List<JobResultData> data = job.getJobResultData();

        // Then
        assertThat(data.size(), is(equalTo(1)));
        assertThat(data.get(0).getClass(), is(equalTo(ParamsJobResultData.class)));
    }

    @Test
    void shouldNotFailJob() {
        // Given
        ParamsJob job = new ParamsJob();
        AutomationProgress progress = new AutomationProgress();

        // When
        job.runJob(null, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }
}
