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
package org.zaproxy.addon.automation;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
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
import org.zaproxy.addon.automation.jobs.ActiveScanJob;
import org.zaproxy.addon.automation.tests.AbstractAutomationTest;
import org.zaproxy.addon.automation.tests.AbstractAutomationTest.OnFail;
import org.zaproxy.addon.automation.tests.AutomationAlertTest;
import org.zaproxy.addon.automation.tests.AutomationStatisticTest;
import org.zaproxy.addon.automation.tests.UrlPresenceTest;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.extension.stats.ExtensionStats;
import org.zaproxy.zap.extension.stats.InMemoryStats;
import org.zaproxy.zap.utils.I18N;

class AutomationJobUnitTest {

    private static MockedStatic<CommandLine> mockedCmdLine;
    private String stringParamValue = "a string";
    private int intParamValue = 6;
    private Integer integerParamValue = Integer.valueOf(7);
    private boolean boolParamValue = true;
    private Boolean booleanParamValue = Boolean.FALSE;
    private TestParam.Option enumParamValue = TestParam.Option.FIRST_OPTION;

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
    void shouldChangeName() {
        // Given
        AutomationJob job = new AutomationJobImpl();
        String newName = "new-name";

        // When
        String type = job.getType();
        String initialName = job.getName();
        job.setName(newName);
        String afterSetName = job.getName();
        job.setName(null);
        String afterNullName = job.getName();

        // Then
        assertThat(initialName, is(equalTo(type)));
        assertThat(afterSetName, is(equalTo(newName)));
        assertThat(afterNullName, is(equalTo(type)));
    }

    @Test
    void shouldExtractExpectedParams() {
        // Given
        TestParamContainer tpc = new TestParamContainer();
        AutomationJob job = new AutomationJobImpl(tpc);

        // When
        Map<String, String> params = job.getConfigParameters(tpc, "getTestParam");

        // Then
        assertThat(params.size(), is(equalTo(6)));
        assertThat(params.containsKey("stringParam"), is(equalTo(true)));
        assertThat(params.containsKey("integerParam"), is(equalTo(true)));
        assertThat(params.containsKey("intParam"), is(equalTo(true)));
        assertThat(params.containsKey("booleanParam"), is(equalTo(true)));
        assertThat(params.containsKey("boolParam"), is(equalTo(true)));
        assertThat(params.containsKey("enumParam"), is(equalTo(true)));
    }

    @Test
    void shouldExcludeNamedParams() {
        // Given
        TestParamContainer tpc = new TestParamContainer();
        AutomationJob job =
                new AutomationJobImpl(tpc) {
                    @Override
                    public boolean isExcludeParam(String param) {
                        switch (param) {
                            case "integerParam":
                            case "boolParam":
                                return true;
                            default:
                                return false;
                        }
                    }
                };

        // When
        Map<String, String> params = job.getConfigParameters(tpc, "getTestParam");

        // Then
        assertThat(params.size(), is(equalTo(4)));
        assertThat(params.containsKey("stringParam"), is(equalTo(true)));
        assertThat(params.containsKey("intParam"), is(equalTo(true)));
        assertThat(params.containsKey("booleanParam"), is(equalTo(true)));
        assertThat(params.containsKey("enumParam"), is(equalTo(true)));
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Test
    void shouldSetParams() {
        // Given
        TestParamContainer tpc = new TestParamContainer();
        AutomationJob job = new AutomationJobImpl(tpc);
        AutomationProgress progress = new AutomationProgress();

        Map map = new HashMap();
        map.put("stringParam", stringParamValue);
        map.put("intParam", Integer.toString(intParamValue));
        map.put("integerParam", integerParamValue.toString());
        map.put("boolParam", Boolean.toString(boolParamValue));
        map.put("booleanParam", booleanParamValue.toString());
        map.put("enumParam", enumParamValue.toString());
        LinkedHashMap<?, ?> params = new LinkedHashMap(map);
        LinkedHashMap<String, Object> jobData = new LinkedHashMap();
        jobData.put("parameters", params);

        // When
        job.setJobData(jobData);
        job.applyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(tpc.getTestParam().getStringParam(), is(equalTo(stringParamValue)));
        assertThat(tpc.getTestParam().getIntParam(), is(equalTo(intParamValue)));
        assertThat(tpc.getTestParam().getIntegerParam(), is(equalTo(integerParamValue)));
        assertThat(tpc.getTestParam().isBoolParam(), is(equalTo(boolParamValue)));
        assertThat(tpc.getTestParam().getBooleanParam(), is(equalTo(booleanParamValue)));
        assertThat(tpc.getTestParam().getEnumParam(), is(equalTo(enumParamValue)));
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Test
    void shouldSetResolvedParams() {
        // Given
        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.replaceVars(eq("${myStringParam}"))).willReturn(stringParamValue);
        given(env.replaceVars(eq("${myIntParam}"))).willReturn(Integer.toString(intParamValue));
        given(env.replaceVars(eq("${myIntegerParam}"))).willReturn(integerParamValue.toString());
        given(env.replaceVars(eq("${myBoolParam}"))).willReturn(Boolean.toString(boolParamValue));
        given(env.replaceVars(eq("${myBooleanParam}"))).willReturn(booleanParamValue.toString());
        given(env.replaceVars(eq("${myEnumParam}"))).willReturn(enumParamValue.toString());
        TestParamContainer tpc = new TestParamContainer();
        AutomationJob job = new AutomationJobImpl(tpc);
        job.setEnv(env);
        AutomationProgress progress = new AutomationProgress();

        Map map = new HashMap();
        map.put("stringParam", "${myStringParam}");
        map.put("intParam", "${myIntParam}");
        map.put("integerParam", "${myIntegerParam}");
        map.put("boolParam", "${myBoolParam}");
        map.put("booleanParam", "${myBooleanParam}");
        map.put("enumParam", "${myEnumParam}");
        LinkedHashMap<?, ?> params = new LinkedHashMap(map);
        LinkedHashMap<String, Object> jobData = new LinkedHashMap();
        jobData.put("parameters", params);

        // When
        job.setJobData(jobData);
        job.applyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(tpc.getTestParam().getStringParam(), is(equalTo(stringParamValue)));
        assertThat(tpc.getTestParam().getIntParam(), is(equalTo(intParamValue)));
        assertThat(tpc.getTestParam().getIntegerParam(), is(equalTo(integerParamValue)));
        assertThat(tpc.getTestParam().isBoolParam(), is(equalTo(boolParamValue)));
        assertThat(tpc.getTestParam().getBooleanParam(), is(equalTo(booleanParamValue)));
        assertThat(tpc.getTestParam().getEnumParam(), is(equalTo(enumParamValue)));
    }

    @Test
    void shouldAddStatisticsTests() {
        // Given
        ExtensionLoader extensionLoader = mock(ExtensionLoader.class);
        Control.initSingletonForTesting(mock(Model.class), extensionLoader);
        ExtensionStats extStats = mock(ExtensionStats.class);
        when(extensionLoader.getExtension(ExtensionStats.class)).thenReturn(extStats);
        InMemoryStats inMemoryStats = mock(InMemoryStats.class);
        when(extStats.getInMemoryStats()).thenReturn(inMemoryStats);
        TestParamContainer tpc = new TestParamContainer();
        AutomationJob job = new AutomationJobImpl(tpc);
        AutomationProgress progress = new AutomationProgress();
        String name = "example name";
        String type = "stats";
        String statistic = "stats.job.something";
        String operator = "==";
        String onFail = "warn";
        int value = 3;

        LinkedHashMap<String, Object> test = new LinkedHashMap<>();
        test.put("name", name);
        test.put("type", type);
        test.put("statistic", statistic);
        test.put("operator", operator);
        test.put("onFail", onFail);
        test.put("value", value);
        ArrayList<LinkedHashMap<String, Object>> tests = new ArrayList<>();
        tests.add(test);

        // When
        job.addTests(tests, progress);

        // Then
        AutomationStatisticTest addedTest = (AutomationStatisticTest) job.getTests().get(0);
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(addedTest.getData().getName(), is(equalTo(name)));
        assertThat(addedTest.getData().getStatistic(), is(equalTo(statistic)));
        assertThat(addedTest.getData().getOperator(), is(equalTo(operator)));
        assertThat(addedTest.getData().getOnFail(), is(equalTo(OnFail.WARN)));
    }

    @Test
    void shouldAddUrlPresenceTests() {
        // Given
        ExtensionLoader extensionLoader = mock(ExtensionLoader.class);
        Control.initSingletonForTesting(mock(Model.class), extensionLoader);
        ExtensionStats extStats = mock(ExtensionStats.class);
        when(extensionLoader.getExtension(ExtensionStats.class)).thenReturn(extStats);
        TestParamContainer tpc = new TestParamContainer();
        AutomationJob job = new AutomationJobImpl(tpc);
        AutomationProgress progress = new AutomationProgress();
        String name = "example name";
        String type = "url";
        String url = "http://example.com";
        String onFail = "warn";
        String operator = "or";

        LinkedHashMap<String, Object> test = new LinkedHashMap<>();
        test.put("name", name);
        test.put("type", type);
        test.put("url", url);
        test.put("onFail", onFail);
        test.put("operator", operator);
        ArrayList<LinkedHashMap<String, Object>> tests = new ArrayList<>();
        tests.add(test);

        // When
        job.addTests(tests, progress);

        // Then
        UrlPresenceTest addedTest = (UrlPresenceTest) job.getTests().get(0);
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(addedTest.getData().getName(), is(equalTo(name)));
        assertThat(addedTest.getData().getUrl(), is(equalTo(url)));
        assertThat(addedTest.getData().getOnFail(), is(equalTo(OnFail.WARN)));
    }

    @Test
    void shouldAddMultipleTestsForSameStatistic() {
        // Given
        ExtensionLoader extensionLoader = mock(ExtensionLoader.class);
        Control.initSingletonForTesting(mock(Model.class), extensionLoader);
        ExtensionStats extStats = mock(ExtensionStats.class);
        when(extensionLoader.getExtension(ExtensionStats.class)).thenReturn(extStats);
        InMemoryStats inMemoryStats = mock(InMemoryStats.class);
        when(extStats.getInMemoryStats()).thenReturn(inMemoryStats);

        TestParamContainer tpc = new TestParamContainer();
        AutomationJob job = new AutomationJobImpl(tpc);
        AutomationProgress progress = new AutomationProgress();
        job.setEnv(new AutomationEnvironment(progress));
        String key = "stats.job.something";
        long value = 10;
        String nameOne = "test one";
        String operatorOne = "==";
        String onFailOne = "warn";
        String nameTwo = "test two";
        String operatorTwo = ">";
        String onFailTwo = "error";

        job.addTest(
                new AutomationStatisticTest(
                        key, nameOne, operatorOne, value, onFailOne, job, progress));
        job.addTest(
                new AutomationStatisticTest(
                        key, nameTwo, operatorTwo, value, onFailTwo, job, progress));
        when(inMemoryStats.getStat(key)).thenReturn(value + 1);

        // When
        job.logTestsToProgress(progress);

        // Then
        assertThat(
                job.getTests().stream().filter(AutomationStatisticTest.class::isInstance).count(),
                is(2L));
        assertThat(progress.hasWarnings(), is(true));
        assertThat(progress.getWarnings().size(), is(1));
        assertThat(progress.getWarnings().get(0), is("!automation.tests.fail!"));
        assertThat(progress.hasErrors(), is(false));
    }

    @Test
    void shouldWarnIfUnknownTestType() {
        // Given
        ExtensionLoader extLoader = mock(ExtensionLoader.class);
        Control.initSingletonForTesting(mock(Model.class), extLoader);
        when(extLoader.getExtension(ExtensionStats.class)).thenReturn(mock(ExtensionStats.class));

        // Given
        TestParamContainer tpc = new TestParamContainer();
        AutomationJob job = new AutomationJobImpl(tpc);
        AutomationProgress progress = new AutomationProgress();
        String type = "unknown test type";

        LinkedHashMap<String, Object> test = new LinkedHashMap<>();
        test.put("type", type);
        ArrayList<LinkedHashMap<String, Object>> tests = new ArrayList<>();
        tests.add(test);

        // When
        job.addTests(tests, progress);

        // Then
        assertThat(progress.hasErrors(), is(false));
        assertThat(progress.hasWarnings(), is(true));
        assertThat(progress.getWarnings().get(0), is("!automation.tests.invalidType!"));
    }

    @Test
    void shouldWarnIfNullInMemoryStats() {
        // Given
        ExtensionLoader extLoader = mock(ExtensionLoader.class);
        Control.initSingletonForTesting(mock(Model.class), extLoader);
        when(extLoader.getExtension(ExtensionStats.class)).thenReturn(mock(ExtensionStats.class));

        // Given
        TestParamContainer tpc = new TestParamContainer();
        AutomationJob job = new AutomationJobImpl(tpc);
        AutomationProgress progress = new AutomationProgress();
        String type = "stats";

        LinkedHashMap<String, Object> test = new LinkedHashMap<>();
        test.put("type", type);
        ArrayList<LinkedHashMap<String, Object>> tests = new ArrayList<>();
        tests.add(test);

        // When
        job.addTests(tests, progress);

        // Then
        assertThat(progress.hasErrors(), is(false));
        assertThat(progress.hasWarnings(), is(true));
        assertThat(progress.getWarnings().get(0), is("!automation.tests.stats.nullInMemoryStats!"));
    }

    @Test
    void shouldAllowToOverrideStatisticTests() {
        // Given
        ExtensionLoader extLoader = mock(ExtensionLoader.class);
        Control.initSingletonForTesting(mock(Model.class), extLoader);
        ExtensionStats extStats = mock(ExtensionStats.class);
        when(extLoader.getExtension(ExtensionStats.class)).thenReturn(extStats);
        when(extStats.getInMemoryStats()).thenReturn(mock(InMemoryStats.class));

        TestParamContainer tpc = new TestParamContainer();
        AutomationProgress progress = new AutomationProgress();
        String name = "regular test";
        String type = "stats";
        String statistic = "stats.job.regular";
        String operator = "==";
        String onFail = "warn";
        int value = 3;

        String filteredName = "filtered test";
        String filteredType = "stats";
        String filteredStatistic = "stats.job.filtered";
        String filteredOperator = "!=";
        String filteredOnFail = "error";
        int filteredValue = 4;

        LinkedHashMap<String, Object> test = new LinkedHashMap<>();
        test.put("name", name);
        test.put("type", type);
        test.put("statistic", statistic);
        test.put("operator", operator);
        test.put("onFail", onFail);
        test.put("value", value);

        LinkedHashMap<String, Object> filteredTest = new LinkedHashMap<>();
        filteredTest.put("name", filteredName);
        filteredTest.put("type", filteredType);
        filteredTest.put("statistic", filteredStatistic);
        filteredTest.put("operator", filteredOperator);
        filteredTest.put("onFail", filteredOnFail);
        filteredTest.put("value", filteredValue);

        ArrayList<LinkedHashMap<String, Object>> tests = new ArrayList<>();
        tests.add(test);
        tests.add(filteredTest);

        AutomationJob job =
                new AutomationJobImpl(tpc) {
                    @Override
                    public void addTest(AbstractAutomationTest test) {
                        AutomationStatisticTest statisticTest = (AutomationStatisticTest) test;
                        if (filteredStatistic.equals(statisticTest.getData().getStatistic())) {
                            return;
                        }
                        super.addTest(statisticTest);
                    }
                };

        // When
        job.addTests(tests, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(job.getTests().size(), is(equalTo(1)));
        AutomationStatisticTest addedTest = (AutomationStatisticTest) job.getTests().get(0);
        assertThat(addedTest.getData().getName(), is(equalTo(name)));
        assertThat(addedTest.getData().getStatistic(), is(equalTo(statistic)));
        assertThat(addedTest.getData().getOperator(), is(equalTo(operator)));
        assertThat(addedTest.getData().getOnFail(), is(equalTo(OnFail.WARN)));
    }

    @Test
    void shouldAddAlertTests() {
        // Given
        ExtensionLoader extensionLoader = mock(ExtensionLoader.class);
        Control.initSingletonForTesting(mock(Model.class), extensionLoader);
        ExtensionAlert extAlert = mock(ExtensionAlert.class);
        when(extensionLoader.getExtension(ExtensionAlert.class)).thenReturn(extAlert);

        TestParamContainer tpc = new TestParamContainer();
        AutomationJob job =
                new AutomationJobImpl(tpc) {
                    @Override
                    public String getType() {
                        return ActiveScanJob.JOB_NAME;
                    }
                };

        AutomationProgress progress = new AutomationProgress();
        String name = "example name";
        String type = "alert";
        Integer scanRuleId = 100;
        String onFail = "warn";

        LinkedHashMap<String, Object> test = new LinkedHashMap<>();
        test.put("name", name);
        test.put("type", type);
        test.put("scanRuleId", scanRuleId);
        test.put("onFail", onFail);
        ArrayList<LinkedHashMap<String, Object>> tests = new ArrayList<>();
        tests.add(test);

        // When
        job.addTests(tests, progress);

        // Then
        AutomationAlertTest addedTest = (AutomationAlertTest) job.getTests().get(0);
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(addedTest.getData().getName(), is(equalTo(name)));
        assertThat(addedTest.getData().getScanRuleId(), is(equalTo(100)));
        assertThat(
                addedTest.getData().getOnFail(), is(equalTo(AbstractAutomationTest.OnFail.WARN)));
    }

    @Test
    void shouldWarnIfInvalidJobTypeForAlertTest() {
        // Given
        ExtensionLoader extensionLoader = mock(ExtensionLoader.class);
        Control.initSingletonForTesting(mock(Model.class), extensionLoader);
        ExtensionAlert extAlert = mock(ExtensionAlert.class);
        when(extensionLoader.getExtension(ExtensionAlert.class)).thenReturn(extAlert);

        TestParamContainer tpc = new TestParamContainer();
        AutomationJob job = new AutomationJobImpl(tpc);

        AutomationProgress progress = new AutomationProgress();
        String name = "example name";
        String type = "alert";
        Integer scanRuleId = 100;
        String onFail = "warn";

        LinkedHashMap<String, Object> test = new LinkedHashMap<>();
        test.put("name", name);
        test.put("type", type);
        test.put("scanRuleId", scanRuleId);
        test.put("onFail", onFail);
        ArrayList<LinkedHashMap<String, Object>> tests = new ArrayList<>();
        tests.add(test);

        // When
        job.addTests(tests, progress);

        // Then
        assertThat(job.getTests().size(), is(equalTo(1)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(
                progress.getErrors().get(0),
                is(equalTo("!automation.tests.alert.invalidJobType!")));
    }

    @Test
    void shouldAddMultipleTestsForSameScanRuleId() {
        // Given
        ExtensionLoader extensionLoader = mock(ExtensionLoader.class);
        Control.initSingletonForTesting(mock(Model.class), extensionLoader);
        ExtensionAlert extAlert = mock(ExtensionAlert.class);
        when(extensionLoader.getExtension(ExtensionAlert.class)).thenReturn(extAlert);

        TestParamContainer tpc = new TestParamContainer();
        AutomationJob job =
                new AutomationJobImpl(tpc) {
                    @Override
                    public String getType() {
                        return ActiveScanJob.JOB_NAME;
                    }
                };

        AutomationProgress progress = new AutomationProgress();
        String type = "alert";
        Integer scanRuleId = 100;

        String nameOne = "example nameOne";
        String onFailOne = "warn";

        LinkedHashMap<String, Object> testOne = new LinkedHashMap<>();
        testOne.put("name", nameOne);
        testOne.put("type", type);
        testOne.put("scanRuleId", scanRuleId);
        testOne.put("onFail", onFailOne);

        String nameTwo = "example nameTwo";
        String onFailTwo = "error";

        LinkedHashMap<String, Object> testTwo = new LinkedHashMap<>();
        testTwo.put("name", nameTwo);
        testTwo.put("type", type);
        testTwo.put("scanRuleId", scanRuleId);
        testTwo.put("onFail", onFailTwo);

        ArrayList<LinkedHashMap<String, Object>> tests = new ArrayList<>();
        tests.add(testOne);
        tests.add(testTwo);

        // When
        job.addTests(tests, progress);

        // Then
        AutomationAlertTest addedTestOne = (AutomationAlertTest) job.getTests().get(0);
        AutomationAlertTest addedTestTwo = (AutomationAlertTest) job.getTests().get(1);
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(addedTestOne.getData().getName(), is(equalTo(nameOne)));
        assertThat(addedTestOne.getData().getScanRuleId(), is(equalTo(100)));
        assertThat(
                addedTestOne.getData().getOnFail(),
                is(equalTo(AbstractAutomationTest.OnFail.WARN)));
        assertThat(addedTestTwo.getData().getName(), is(equalTo(nameTwo)));
        assertThat(addedTestTwo.getData().getScanRuleId(), is(equalTo(100)));
        assertThat(
                addedTestTwo.getData().getOnFail(),
                is(equalTo(AbstractAutomationTest.OnFail.ERROR)));
    }

    @Test
    void shouldErrorIfNullExtensionAlert() {
        ExtensionLoader extensionLoader = mock(ExtensionLoader.class);
        Control.initSingletonForTesting(mock(Model.class), extensionLoader);

        TestParamContainer tpc = new TestParamContainer();
        AutomationJob job =
                new AutomationJobImpl(tpc) {
                    @Override
                    public String getType() {
                        return ActiveScanJob.JOB_NAME;
                    }
                };

        AutomationProgress progress = new AutomationProgress();
        String name = "example name";
        String type = "alert";
        Integer scanRuleId = 100;
        String onFail = "warn";

        LinkedHashMap<String, Object> test = new LinkedHashMap<>();
        test.put("name", name);
        test.put("type", type);
        test.put("scanRuleId", scanRuleId);
        test.put("onFail", onFail);
        ArrayList<LinkedHashMap<String, Object>> tests = new ArrayList<>();
        tests.add(test);

        // When
        job.addTests(tests, progress);

        // Then
        assertThat(job.getTests().size(), is(equalTo(1)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(
                progress.getErrors().get(0), is(equalTo("!automation.tests.alert.nullExtension!")));
    }

    @Test
    void shouldAllowToOverrideAlertTests() {
        // Given
        ExtensionLoader extensionLoader = mock(ExtensionLoader.class);
        Control.initSingletonForTesting(mock(Model.class), extensionLoader);
        ExtensionAlert extAlert = mock(ExtensionAlert.class);
        when(extensionLoader.getExtension(ExtensionAlert.class)).thenReturn(extAlert);

        TestParamContainer tpc = new TestParamContainer();
        AutomationProgress progress = new AutomationProgress();
        String type = "alert";

        String name = "example name";
        Integer scanRuleId = 100;
        String onFail = "warn";

        LinkedHashMap<String, Object> test = new LinkedHashMap<>();
        test.put("name", name);
        test.put("type", type);
        test.put("scanRuleId", scanRuleId);
        test.put("onFail", onFail);

        String filteredName = "filtered name";
        Integer filteredScanRuleId = 200;
        String filteredOnFail = "error";

        LinkedHashMap<String, Object> filteredTest = new LinkedHashMap<>();
        filteredTest.put("name", filteredName);
        filteredTest.put("type", type);
        filteredTest.put("scanRuleId", filteredScanRuleId);
        filteredTest.put("onFail", filteredOnFail);

        ArrayList<LinkedHashMap<String, Object>> tests = new ArrayList<>();
        tests.add(test);
        tests.add(filteredTest);

        AutomationJob job =
                new AutomationJobImpl(tpc) {
                    @Override
                    public String getType() {
                        return ActiveScanJob.JOB_NAME;
                    }

                    @Override
                    public void addTest(AbstractAutomationTest test) {
                        AutomationAlertTest alertTest = (AutomationAlertTest) test;
                        if (filteredScanRuleId.equals(alertTest.getData().getScanRuleId())) {
                            return;
                        }
                        super.addTest(alertTest);
                    }
                };

        // When
        job.addTests(tests, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(job.getTests().size(), is(equalTo(1)));
        AutomationAlertTest addedTest = (AutomationAlertTest) job.getTests().get(0);
        assertThat(addedTest.getData().getName(), is(equalTo(name)));
        assertThat(addedTest.getData().getScanRuleId(), is(equalTo(scanRuleId)));
        assertThat(
                addedTest.getData().getOnFail(), is(equalTo(AbstractAutomationTest.OnFail.WARN)));
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    @Test
    void shouldSetCaseInsensitiveEnum() {
        // Given
        TestParamContainer tpc = new TestParamContainer();
        AutomationJob job = new AutomationJobImpl(tpc);
        AutomationProgress progress = new AutomationProgress();
        TestParam.Option enumParamValue = TestParam.Option.SECOND_OPTION;
        Map map = new HashMap();
        map.put("enumParam", enumParamValue.toString().toLowerCase(Locale.ROOT));
        LinkedHashMap<?, ?> params = new LinkedHashMap(map);
        LinkedHashMap<String, Object> jobData = new LinkedHashMap();
        jobData.put("parameters", params);

        // When
        job.setJobData(jobData);
        job.applyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(tpc.getTestParam().getEnumParam(), is(equalTo(enumParamValue)));
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Test
    void shouldWarnOnUnknownParam() {
        // Given
        TestParamContainer tpc = new TestParamContainer();
        AutomationJob job = new AutomationJobImpl(tpc);
        AutomationProgress progress = new AutomationProgress();

        Map map = new HashMap();
        map.put("unknownParam", "test");
        LinkedHashMap<?, ?> params = new LinkedHashMap(map);
        LinkedHashMap<String, Object> jobData = new LinkedHashMap();
        jobData.put("parameters", params);

        // When
        job.setJobData(jobData);
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.getWarnings().size(), is(equalTo(1)));
        assertThat(
                progress.getWarnings().get(0), is(equalTo("!automation.error.options.unknown!")));
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Test
    void shouldIgnoreNullParamValue() {
        // Given
        TestParamContainer tpc = new TestParamContainer();
        AutomationJob job = new AutomationJobImpl(tpc);
        AutomationProgress progress = new AutomationProgress();

        Map map = new HashMap();
        map.put("stringParam", null);
        LinkedHashMap<?, ?> params = new LinkedHashMap(map);
        LinkedHashMap<String, Object> jobData = new LinkedHashMap<>();
        jobData.put("parameters", params);

        // When
        job.setJobData(jobData);
        job.applyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
    }

    @Test
    void shouldWarnOnUnknownCustomParam() {
        // Given
        TestParamContainer tpc = new TestParamContainer();
        AutomationJob job = new AutomationJobImpl(tpc);
        AutomationProgress progress = new AutomationProgress();
        Map<String, String> map = new HashMap<>();
        map.put("unknownParam", "test");
        LinkedHashMap<?, ?> params = new LinkedHashMap<>(map);
        LinkedHashMap<String, Object> jobData = new LinkedHashMap<>();
        jobData.put("parameters", params);

        // When
        job.setJobData(jobData);
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.getWarnings().size(), is(1));
        assertThat(progress.getWarnings().get(0), is("!automation.error.options.unknown!"));
    }

    @Test
    void shouldNotWarnOnKnownCustomParam() {
        // Given
        TestParamContainer tpc = new TestParamContainer();
        AutomationJob job =
                new AutomationJobImpl(tpc) {
                    @Override
                    public boolean verifyCustomParameter(
                            String name, String value, AutomationProgress progress) {
                        return "customStringParam".equals(name);
                    }
                };
        AutomationProgress progress = new AutomationProgress();
        Map<String, String> map = new HashMap<>();
        map.put("customStringParam", stringParamValue);
        LinkedHashMap<?, ?> params = new LinkedHashMap<>(map);
        LinkedHashMap<String, Object> jobData = new LinkedHashMap<>();
        jobData.put("parameters", params);

        // When
        job.setJobData(jobData);
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
    }

    @Test
    void shouldNotWarnForJobsWithDefaultVerifyCustomParameterImplementation() {
        // Given
        TestParamContainer tpc = new TestParamContainer();
        AutomationJob job =
                new AutomationJobImpl(tpc) {
                    @Override
                    public Map<String, String> getCustomConfigParameters() {
                        Map<String, String> map = new HashMap<>();
                        map.put("customStringParam", stringParamValue);
                        return map;
                    }
                };
        AutomationProgress progress = new AutomationProgress();
        Map<String, String> map = new HashMap<>();
        map.put("customStringParam", stringParamValue);
        LinkedHashMap<?, ?> params = new LinkedHashMap<>(map);
        LinkedHashMap<String, Object> jobData = new LinkedHashMap<>();
        jobData.put("parameters", params);

        // When
        job.setJobData(jobData);
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Test
    void shouldFailOnBadInt() {
        // Given
        TestParamContainer tpc = new TestParamContainer();
        AutomationJob job = new AutomationJobImpl(tpc);
        AutomationProgress progress = new AutomationProgress();

        Map map = new HashMap();
        map.put("intParam", "Not an int");
        LinkedHashMap<?, ?> params = new LinkedHashMap(map);
        LinkedHashMap<String, Object> jobData = new LinkedHashMap<>();
        jobData.put("parameters", params);

        // When
        job.setJobData(jobData);
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(progress.getErrors().get(0), is(equalTo("!automation.error.options.badint!")));
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Test
    void shouldFailOnBadInteger() {
        // Given
        TestParamContainer tpc = new TestParamContainer();
        AutomationJob job = new AutomationJobImpl(tpc);
        AutomationProgress progress = new AutomationProgress();

        Map map = new HashMap();
        map.put("integerParam", "Not an int");
        LinkedHashMap<?, ?> params = new LinkedHashMap(map);
        LinkedHashMap<String, Object> jobData = new LinkedHashMap<>();
        jobData.put("parameters", params);

        // When
        job.setJobData(jobData);
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(progress.getErrors().get(0), is(equalTo("!automation.error.options.badint!")));
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Test
    void shouldFailOnBadBool() {
        // Given
        TestParamContainer tpc = new TestParamContainer();
        AutomationJob job = new AutomationJobImpl(tpc);
        AutomationProgress progress = new AutomationProgress();
        Map map = new HashMap();
        map.put("boolParam", "Not a bool");
        LinkedHashMap<?, ?> params = new LinkedHashMap(map);
        LinkedHashMap<String, Object> jobData = new LinkedHashMap<>();
        jobData.put("parameters", params);

        // When
        job.setJobData(jobData);
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(progress.getErrors().get(0), is(equalTo("!automation.error.options.badbool!")));
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Test
    void shouldFailOnBadEnum() {
        // Given
        TestParamContainer tpc = new TestParamContainer();
        AutomationJob job = new AutomationJobImpl(tpc);
        AutomationProgress progress = new AutomationProgress();
        Map map = new HashMap();
        map.put("enumParam", "Invalid enum value");
        LinkedHashMap<?, ?> params = new LinkedHashMap(map);
        LinkedHashMap<String, Object> jobData = new LinkedHashMap<>();
        jobData.put("parameters", params);

        // When
        job.setJobData(jobData);
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(progress.getErrors().get(0), is(equalTo("!automation.error.options.badenum!")));
    }

    @Test
    void shouldIgnoreUnsetParams() {
        // Given
        TestParamContainer tpc = new TestParamContainer();
        AutomationJob job = new AutomationJobImpl(tpc);
        AutomationProgress progress = new AutomationProgress();

        // When
        job.applyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Test
    void shouldFailOnBadOptionsGetterName() {
        // Given
        TestParamContainer tpc = new TestParamContainer();
        AutomationJob job = new AutomationJobImpl(tpc, "getBadTestParam");
        AutomationProgress progress = new AutomationProgress();

        Map map = new HashMap();
        LinkedHashMap<?, ?> params = new LinkedHashMap(map);
        LinkedHashMap<String, Object> jobData = new LinkedHashMap();
        jobData.put("parameters", params);

        // When
        job.setJobData(jobData);
        job.verifyOrApplyParameters(tpc, "getBadTestParam", progress, false);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(progress.getErrors().get(0), is(equalTo("!automation.error.options.method!")));
    }

    @Test
    void shouldReturnDefaultConfigFileData() {
        // Given
        String expectedParams =
                "  - type: type\n"
                        + "    name: type\n"
                        + "    parameters:\n"
                        + "      boolParam: false\n"
                        + "      booleanParam: \n"
                        + "      enumParam: \n"
                        + "      intParam: 0\n"
                        + "      integerParam: \n"
                        + "      stringParam: \n";

        TestParamContainer tpc = new TestParamContainer();
        AutomationJobImpl job = new AutomationJobImpl(tpc);

        // When
        String data = job.getConfigFileData();

        // Then
        assertThat(data, is(equalTo(expectedParams)));
    }

    @Test
    void shouldReturnSetConfigFileData() {
        // Given
        String expectedParams =
                "  - type: type\n"
                        + "    name: type\n"
                        + "    parameters:\n"
                        + "      boolParam: true\n"
                        + "      booleanParam: false\n"
                        + "      enumParam: SECOND_OPTION\n"
                        + "      intParam: 8\n"
                        + "      integerParam: 9\n"
                        + "      stringParam: testStr\n";

        TestParamContainer tpc = new TestParamContainer();
        AutomationJobImpl job = new AutomationJobImpl(tpc);
        tpc.getTestParam().setBoolParam(true);
        tpc.getTestParam().setBooleanParam(Boolean.FALSE);
        tpc.getTestParam().setIntParam(8);
        tpc.getTestParam().setIntegerParam(9);
        tpc.getTestParam().setStringParam("testStr");
        tpc.getTestParam().setEnumParam(TestParam.Option.SECOND_OPTION);

        // When
        String data = job.getConfigFileData();

        // Then
        assertThat(data, is(equalTo(expectedParams)));
    }

    @Test
    void shouldCorrectlyOrderJobs() {
        // Given
        AutomationJob lastJob =
                new AutomationJobImpl() {
                    @Override
                    public String getType() {
                        return "Last job";
                    }

                    @Override
                    public Order getOrder() {
                        return Order.RUN_LAST;
                    }
                };
        AutomationJob firstJob =
                new AutomationJobImpl() {
                    @Override
                    public String getType() {
                        return "First job";
                    }

                    @Override
                    public Order getOrder() {
                        return Order.RUN_FIRST;
                    }
                };
        AutomationJob explore1Job =
                new AutomationJobImpl() {
                    @Override
                    public String getType() {
                        return "Explore 1";
                    }

                    @Override
                    public Order getOrder() {
                        return Order.EXPLORE;
                    }
                };
        AutomationJob explore2Job =
                new AutomationJobImpl() {
                    @Override
                    public String getType() {
                        return "Explore 2";
                    }

                    @Override
                    public Order getOrder() {
                        return Order.EXPLORE;
                    }
                };

        ArrayList<AutomationJob> list = new ArrayList<>();
        list.add(explore2Job);
        list.add(lastJob);
        list.add(firstJob);
        list.add(explore1Job);

        // When
        Collections.sort(list);

        // Then
        assertThat(list.size(), is(equalTo(4)));
        assertThat(list.get(0), is(equalTo(firstJob)));
        assertThat(list.get(1), is(equalTo(explore1Job)));
        assertThat(list.get(2), is(equalTo(explore2Job)));
        assertThat(list.get(3), is(equalTo(lastJob)));
    }

    // Methods are accessed via reflection
    private static class TestParamContainer {
        private TestParam testParam = new TestParam();

        public TestParam getTestParam() {
            return testParam;
        }
    }

    // Methods are accessed via reflection
    @SuppressWarnings("unused")
    private static class TestParam {

        private enum Option {
            FIRST_OPTION,
            SECOND_OPTION,
            THIRD_OPTION
        }

        private String stringParam;
        private Integer integerParam;
        private int intParam;
        private Boolean booleanParam;
        private boolean boolParam;
        private List<String> listStringPram;
        private Option enumParam;

        public String getStringParam() {
            return stringParam;
        }

        public void setStringParam(String stringParam) {
            this.stringParam = stringParam;
        }

        public Integer getIntegerParam() {
            return integerParam;
        }

        public void setIntegerParam(Integer integerParam) {
            this.integerParam = integerParam;
        }

        public int getIntParam() {
            return intParam;
        }

        public void setIntParam(int intParam) {
            this.intParam = intParam;
        }

        public Boolean getBooleanParam() {
            return booleanParam;
        }

        public void setBooleanParam(Boolean booleanParam) {
            this.booleanParam = booleanParam;
        }

        public boolean isBoolParam() {
            return boolParam;
        }

        public void setBoolParam(boolean boolParam) {
            this.boolParam = boolParam;
        }

        public List<String> getListStringPram() {
            return listStringPram;
        }

        public void setListStringPram(List<String> listStringPram) {
            this.listStringPram = listStringPram;
        }

        public Option getEnumParam() {
            return enumParam;
        }

        public void setEnumParam(Option enumParam) {
            this.enumParam = enumParam;
        }

        public boolean getWithOneParam(String test) {
            return test.length() > 0;
        }

        public void setWithOneParam(String test) {}

        public boolean getWithNoSetter() {
            return false;
        }
    }

    private static class AutomationJobImpl extends AutomationJob {

        private Object paramMethodObject;
        private String paramNameMethod = "getTestParam";

        public AutomationJobImpl() {}

        public AutomationJobImpl(Object paramMethodObject) {
            this.paramMethodObject = paramMethodObject;
        }

        public AutomationJobImpl(TestParamContainer paramMethodObject, String paramNameMethod) {
            this.paramMethodObject = paramMethodObject;
            this.paramNameMethod = paramNameMethod;
        }

        @Override
        public void runJob(AutomationEnvironment env, AutomationProgress progress) {}

        @Override
        public String getType() {
            return "type";
        }

        @Override
        public Order getOrder() {
            return null;
        }

        @Override
        public String getSummary() {
            return "";
        }

        @Override
        public Object getParamMethodObject() {
            return paramMethodObject;
        }

        @Override
        public String getParamMethodName() {
            return paramNameMethod;
        }
    }
}
