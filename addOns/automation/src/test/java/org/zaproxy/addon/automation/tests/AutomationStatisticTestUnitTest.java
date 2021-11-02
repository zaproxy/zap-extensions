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
package org.zaproxy.addon.automation.tests;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
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

class AutomationStatisticTestUnitTest extends TestUtils {

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

    static Stream<Arguments> shouldPassTestParamsSource() {
        return Stream.of(
                Arguments.of("<", 1, 2),
                Arguments.of(">", 4, 3),
                Arguments.of("<=", 5, 5),
                Arguments.of("<=", 5, 6),
                Arguments.of(">=", 7, 7),
                Arguments.of(">=", 8, 7),
                Arguments.of("==", 9, 9),
                Arguments.of("!=", 10, 11));
    }

    @ParameterizedTest
    @MethodSource("shouldPassTestParamsSource")
    void shouldPassTestIfSpecifiedConditionIsSatisfied(
            String operator, long statValue, long value) {
        // Given
        AutomationProgress progress = new AutomationProgress();
        String name = "example name";
        String key = "stats.job.something";
        String onFail = "warn";
        AutomationStatisticTest test =
                new AutomationStatisticTest(
                        key, name, operator, value, onFail, new ActiveScanJob(), progress);
        test.getJob().setEnv(new AutomationEnvironment(progress));

        // When
        boolean hasRunFirst = test.hasRun();
        when(extStats.getInMemoryStats().getStat(key)).thenReturn(statValue);
        test.logToProgress(progress);

        // Then
        assertThat(hasRunFirst, is(false));
        assertThat(test.getName(), is(name));
        assertThat(test.getTestType(), is(AutomationStatisticTest.TEST_TYPE));
        assertThat(test.getJobType(), is("activeScan"));
        assertThat(progress.hasWarnings(), is(false));
        assertThat(progress.hasErrors(), is(false));
        assertThat(progress.getInfos().size(), is(7));
        assertThat(progress.getInfos().get(6), is("!automation.tests.pass!"));
        assertThat(test.hasRun(), is(true));
        assertThat(test.hasPassed(), is(true));
    }

    static Stream<Arguments> shouldFailTestParamsSource() {
        return Stream.of(
                Arguments.of("<", 2, 1),
                Arguments.of(">", 3, 4),
                Arguments.of("<=", 6, 5),
                Arguments.of(">=", 7, 8),
                Arguments.of("==", 10, 9),
                Arguments.of("!=", 11, 11));
    }

    @ParameterizedTest
    @MethodSource("shouldFailTestParamsSource")
    void shouldFailTestIfSpecifiedConditionIsNotSatisfied(
            String operator, long statValue, long value) {
        // Given
        AutomationProgress progress = new AutomationProgress();
        String name = "example name";
        String key = "stats.job.something";
        String onFail = "warn";
        AutomationStatisticTest test =
                new AutomationStatisticTest(
                        key, name, operator, value, onFail, new ActiveScanJob(), progress);
        test.getJob().setEnv(new AutomationEnvironment(progress));

        // When
        when(extStats.getInMemoryStats().getStat(key)).thenReturn(statValue);
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
        AutomationStatisticTest test =
                new AutomationStatisticTest(
                        key, "example name", "==", value, "warn", new ActiveScanJob(), progress);
        test.getJob().setEnv(new AutomationEnvironment(progress));

        // When
        when(extStats.getInMemoryStats().getStat(key)).thenReturn(value);
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
        String operator = "==";
        String onFail = "warn";
        long value = 10;
        AutomationStatisticTest test =
                new AutomationStatisticTest(
                        key, name, operator, value, onFail, new ActiveScanJob(), progress);
        test.getJob().setEnv(new AutomationEnvironment(progress));

        // When
        when(extStats.getInMemoryStats().getStat(key)).thenReturn(value - 1);
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
        String operator = "==";
        String onFail = "error";
        long value = 10;
        AutomationStatisticTest test =
                new AutomationStatisticTest(
                        key, name, operator, value, onFail, new ActiveScanJob(), progress);
        test.getJob().setEnv(new AutomationEnvironment(progress));

        // When
        when(extStats.getInMemoryStats().getStat(key)).thenReturn(value - 1);
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
        String operator = "==";
        String onFail = "info";
        long value = 10;
        AutomationStatisticTest test =
                new AutomationStatisticTest(
                        key, name, operator, value, onFail, new ActiveScanJob(), progress);
        test.getJob().setEnv(new AutomationEnvironment(progress));

        // When
        when(extStats.getInMemoryStats().getStat(key)).thenReturn(value - 1);
        test.logToProgress(progress);

        // Then
        assertThat(progress.hasWarnings(), is(false));
        assertThat(progress.hasErrors(), is(false));
        assertThat(progress.getInfos().size(), is(7));
        assertThat(progress.getInfos().get(6), is("!automation.tests.fail!"));
    }

    @Test
    void shouldReturnZeroForUnknownStat() {
        // Given
        AutomationProgress progress = new AutomationProgress();
        String name = "example name";
        String key = "stats.unknown";
        String operator = "==";
        String onFail = "warn";
        long value = 0;
        AutomationStatisticTest test =
                new AutomationStatisticTest(
                        key, name, operator, value, onFail, new ActiveScanJob(), progress);
        test.getJob().setEnv(new AutomationEnvironment(progress));

        // When
        test.logToProgress(progress);

        // Then
        assertThat(progress.hasErrors(), is(false));
        assertThat(progress.hasWarnings(), is(false));
        assertThat(test.hasPassed(), is(true));
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
        String operator = "==";
        String onFail = "warn";
        long value = 7;
        AutomationStatisticTest test =
                new AutomationStatisticTest(
                        key, name, site, operator, value, onFail, new ActiveScanJob(), progress);
        test.getJob().setEnv(env);

        // When
        when(extStats.getInMemoryStats().getStat("https://www.example.com", key)).thenReturn(value);
        env.getData().setVars(map);
        test.logToProgress(progress);

        // Then
        assertThat(progress.hasErrors(), is(false));
        assertThat(progress.hasWarnings(), is(false));
        assertThat(test.hasPassed(), is(true));
    }
}
