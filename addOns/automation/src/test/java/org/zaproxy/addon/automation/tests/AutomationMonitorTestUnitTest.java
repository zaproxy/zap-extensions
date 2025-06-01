/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.automation.tests;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.jobs.ActiveScanJob;
import org.zaproxy.zap.extension.stats.ExtensionStats;
import org.zaproxy.zap.extension.stats.InMemoryStats;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.I18N;

class AutomationMonitorTestUnitTest extends TestUtils {

    private ExtensionStats extStats;

    @BeforeEach
    void setUp() {
        Constant.messages = new I18N(Locale.ENGLISH);
        ExtensionLoader extensionLoader = mock(ExtensionLoader.class);
        Control.initSingletonForTesting(mock(Model.class), extensionLoader);
        extStats = mock(ExtensionStats.class);
        when(extensionLoader.getExtension(ExtensionStats.class)).thenReturn(extStats);
        InMemoryStats inMemoryStats = mock(InMemoryStats.class);
        when(extStats.getInMemoryStats()).thenReturn(inMemoryStats);
    }

    @Test
    void shouldPassTestIfThresholdNotReached() {
        // Given
        AutomationProgress progress = new AutomationProgress();
        String name = "example name";
        String key = "stats.job.something";
        String onFail = "warn";
        AutomationMonitorTest test =
                new AutomationMonitorTest(key, name, 100, onFail, new ActiveScanJob(), progress);
        test.getJob().setEnv(new AutomationEnvironment(progress));

        // When
        boolean hasRunFirst = test.hasRun();
        when(extStats.getInMemoryStats().getStat(key)).thenReturn(80l);
        test.logToProgress(progress);

        // Then
        assertThat(hasRunFirst, is(false));
        assertThat(test.getName(), is(name));
        assertThat(test.getTestType(), is(AutomationMonitorTest.TEST_TYPE));
        assertThat(test.getJobType(), is("activeScan"));
        assertThat(progress.hasWarnings(), is(false));
        assertThat(progress.hasErrors(), is(false));
        assertThat(progress.getInfos().size(), is(6));
        assertThat(progress.getInfos().get(5), is("!automation.tests.pass!"));
        assertThat(test.hasRun(), is(true));
        assertThat(test.hasPassed(), is(true));
    }

    @Test
    void shouldPassTestIfNoStatistic() {
        // Given
        AutomationProgress progress = new AutomationProgress();
        String name = "example name";
        String key = "stats.job.something";
        String onFail = "warn";
        AutomationMonitorTest test =
                new AutomationMonitorTest(key, name, 100, onFail, new ActiveScanJob(), progress);
        test.getJob().setEnv(new AutomationEnvironment(progress));

        // When
        boolean hasRunFirst = test.hasRun();
        test.logToProgress(progress);

        // Then
        assertThat(hasRunFirst, is(false));
        assertThat(test.getName(), is(name));
        assertThat(test.getTestType(), is(AutomationMonitorTest.TEST_TYPE));
        assertThat(test.getJobType(), is("activeScan"));
        assertThat(progress.hasWarnings(), is(false));
        assertThat(progress.hasErrors(), is(false));
        assertThat(progress.getInfos().size(), is(6));
        assertThat(progress.getInfos().get(5), is("!automation.tests.pass!"));
        assertThat(test.hasRun(), is(true));
        assertThat(test.hasPassed(), is(true));
    }

    @Test
    void shouldFailTestIfThresholdExceeded() {
        // Given
        AutomationProgress progress = new AutomationProgress();
        String name = "example name";
        String key = "stats.job.something";
        String onFail = "warn";
        AutomationMonitorTest test =
                new AutomationMonitorTest(key, name, 50, onFail, new ActiveScanJob(), progress);
        test.getJob().setEnv(new AutomationEnvironment(progress));

        // When
        when(extStats.getInMemoryStats().getStat(key)).thenReturn(80l);
        test.logToProgress(progress);

        // Then
        assertThat(progress.hasErrors(), is(false));
        assertThat(progress.hasWarnings(), is(true));
        assertThat(progress.getWarnings().size(), is(1));
        assertThat(progress.getWarnings().get(0), is("!automation.tests.fail!"));
        assertThat(test.hasRun(), is(true));
        assertThat(test.hasPassed(), is(false));
    }

    @Test
    void shouldResetTestStatus() {
        // Given
        AutomationProgress progress = new AutomationProgress();
        String key = "stats.job.something";
        long value = 5;
        AutomationMonitorTest test =
                new AutomationMonitorTest(
                        key, "example name", value, "warn", new ActiveScanJob(), progress);
        test.getJob().setEnv(new AutomationEnvironment(progress));

        // When
        when(extStats.getInMemoryStats().getStat(key)).thenReturn(value - 1);
        test.logToProgress(progress);
        boolean ran = test.hasRun();
        boolean passed = test.hasPassed();
        test.reset();

        // Then
        assertThat(ran, is(true));
        assertThat(passed, is(true));
        assertThat(test.hasRun(), is(false));
        assertThat(test.hasPassed(), is(false));
    }

    @Test
    void shouldLogWarningsIfSpecifiedWarnOnFail() {
        // Given
        AutomationProgress progress = new AutomationProgress();
        String name = "example name";
        String key = "stats.job.something";
        String onFail = "warn";
        long value = 10;
        AutomationMonitorTest test =
                new AutomationMonitorTest(key, name, value, onFail, new ActiveScanJob(), progress);
        test.getJob().setEnv(new AutomationEnvironment(progress));

        // When
        when(extStats.getInMemoryStats().getStat(key)).thenReturn(value + 1);
        test.logToProgress(progress);

        // Then
        assertThat(progress.hasErrors(), is(false));
        assertThat(progress.hasWarnings(), is(true));
        assertThat(progress.getWarnings().size(), is(1));
        assertThat(progress.getWarnings().get(0), is("!automation.tests.fail!"));
    }

    @Test
    void shouldLogErrorsIfSpecifiedErrorOnFail() {
        // Given
        AutomationProgress progress = new AutomationProgress();
        String name = "example name";
        String key = "stats.job.something";
        String onFail = "error";
        long value = 10;
        AutomationMonitorTest test =
                new AutomationMonitorTest(key, name, value, onFail, new ActiveScanJob(), progress);
        test.getJob().setEnv(new AutomationEnvironment(progress));

        // When
        when(extStats.getInMemoryStats().getStat(key)).thenReturn(value + 1);
        test.logToProgress(progress);

        // Then
        assertThat(progress.hasWarnings(), is(false));
        assertThat(progress.hasErrors(), is(true));
        assertThat(progress.getErrors().size(), is(1));
        assertThat(progress.getErrors().get(0), is("!automation.tests.fail!"));
    }

    @Test
    void shouldLogInfoIfSpecifiedInfoOnFail() {
        // Given
        AutomationProgress progress = new AutomationProgress();
        String name = "example name";
        String key = "stats.job.something";
        String onFail = "info";
        long value = 10;
        AutomationMonitorTest test =
                new AutomationMonitorTest(key, name, value, onFail, new ActiveScanJob(), progress);
        test.getJob().setEnv(new AutomationEnvironment(progress));

        // When
        when(extStats.getInMemoryStats().getStat(key)).thenReturn(value + 1);
        test.logToProgress(progress);

        // Then
        assertThat(progress.hasWarnings(), is(false));
        assertThat(progress.hasErrors(), is(false));
        assertThat(progress.getInfos().size(), is(6));
        assertThat(progress.getInfos().get(5), is("!automation.tests.fail!"));
    }

    @Test
    void shouldReplaceSiteEnvVar() {
        // Given
        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = new AutomationEnvironment(progress);
        Map<String, String> map = new HashMap<>();
        map.put("site", "www.example");
        String name = "example name";
        String site = "https://${site}.com";
        String key = "stats.job.something";
        String onFail = "warn";
        long value = 7;
        AutomationMonitorTest test =
                new AutomationMonitorTest(
                        key, name, site, value, onFail, new ActiveScanJob(), progress);
        test.getJob().setEnv(env);

        // When
        when(extStats.getInMemoryStats().getStat("https://www.example.com", key))
                .thenReturn(value + 1);
        env.getData().setVars(map);
        test.logToProgress(progress);

        // Then
        assertThat(progress.hasErrors(), is(false));
        assertThat(progress.getWarnings().size(), is(1));
        assertThat(progress.getWarnings().get(0), is("!automation.tests.fail!"));
        assertThat(progress.hasWarnings(), is(true));
        assertThat(test.hasPassed(), is(false));
    }
}
