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
package org.zaproxy.addon.reports.automation;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.yaml.snakeyaml.Yaml;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.reports.ExtensionReports;
import org.zaproxy.addon.reports.automation.OutputSummaryJob.Format;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.utils.I18N;

@SuppressWarnings("removal")
class OutputSummaryJobUnitTest {

    private OutputSummaryJob job;
    private ExtensionReportAutomation ext;
    private ExtensionReports extReport;
    private ByteArrayOutputStream os;
    private AutomationEnvironment env;
    private AutomationProgress progress;
    private org.zaproxy.addon.automation.jobs.PassiveScanJobResultData psJobResData;

    @BeforeEach
    void setUp() throws Exception {
        Constant.messages = new I18N(Locale.ENGLISH);

        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
        ExtensionLoader extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);

        ext = mock(ExtensionReportAutomation.class);
        extReport = mock(ExtensionReports.class);
        env = mock(AutomationEnvironment.class);
        progress = mock(AutomationProgress.class);
        psJobResData = mock(org.zaproxy.addon.automation.jobs.PassiveScanJobResultData.class);
        job = new OutputSummaryJob();
        os = new ByteArrayOutputStream();
        job.setOutput(new PrintStream(os));

        given(extensionLoader.getExtension(ExtensionReports.class)).willReturn(extReport);
        given(extensionLoader.getExtension(ExtensionReportAutomation.class)).willReturn(ext);
        given(progress.getJobResultData(any())).willReturn(psJobResData);
    }

    @Test
    void shouldReportBadFormat() throws Exception {
        // Given
        String yamlStr = "parameters:\n  format: bad_format";
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);
        AutomationProgress realProgress = new AutomationProgress();

        // When
        job.setJobData((LinkedHashMap<?, ?>) data);
        job.verifyParameters(realProgress);

        // Then
        assertThat(realProgress.hasErrors(), is(equalTo(true)));
        assertThat(
                realProgress.getErrors(),
                contains(
                        "!automation.error.options.badenum!",
                        "!reports.automation.error.noparent!"));
    }

    @ParameterizedTest
    @EmptySource
    @ValueSource(strings = {"/", "/bad/path"})
    void shouldReportBadSummaryFile(String path) throws Exception {
        // Given
        String yamlStr = "parameters:\n  summaryFile: " + path;
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);
        AutomationProgress realProgress = new AutomationProgress();

        // When
        job.setJobData((LinkedHashMap<?, ?>) data);
        job.verifyParameters(realProgress);

        // Then
        assertThat(realProgress.hasErrors(), is(equalTo(true)));
        assertThat(realProgress.getErrors(), contains("!reports.automation.error.noparent!"));
    }

    @Test
    void shouldWarnOnRuleWithAlerts() throws Exception {
        // Given
        given(ext.countNumberOfUrls()).willReturn(3);

        Map<Integer, Integer> alertCounts = new HashMap<>();
        alertCounts.put(1, 3);
        given(extReport.getAlertCountsByRule()).willReturn(alertCounts);

        var list = List.of(createRuleData(new TestPluginPassiveScanner(1, "rule1")));

        given(psJobResData.getAllRuleData()).willReturn(list);

        job.getData().getParameters().setFormat(Format.LONG);

        // When
        job.runJob(env, progress);

        // Then
        assertOutput(
                "Total of 3 URLs\n"
                        + "WARN-NEW: rule1 [1] x 3 \n"
                        + "FAIL-NEW: 0\tFAIL-INPROG: 0\tWARN-NEW: 1\tWARN-INPROG: 0\tINFO: 0\tIGNORE: 0\tPASS: 0\n");
    }

    @Test
    void shouldFailIfConfigOnRuleWithAlerts() throws Exception {
        // Given
        given(ext.countNumberOfUrls()).willReturn(3);

        Map<Integer, Integer> alertCounts = new HashMap<>();
        alertCounts.put(1, 3);
        given(extReport.getAlertCountsByRule()).willReturn(alertCounts);

        var list = List.of(createRuleData(new TestPluginPassiveScanner(1, "rule1")));

        given(psJobResData.getAllRuleData()).willReturn(list);

        job.getData().getParameters().setFormat(Format.LONG);

        LinkedHashMap<String, Object> ruleDefn = new LinkedHashMap<>();
        ruleDefn.put("id", 1);
        ruleDefn.put("action", "FAIL");

        LinkedHashMap<String, List<?>> data = new LinkedHashMap<>();
        ArrayList<LinkedHashMap<?, ?>> rulesDefn = new ArrayList<>();
        rulesDefn.add(ruleDefn);
        data.put("rules", rulesDefn);

        // When
        job.setJobData(data);
        job.verifyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertOutput(
                "Total of 3 URLs\n"
                        + "FAIL-NEW: rule1 [1] x 3 \n"
                        + "FAIL-NEW: 1\tFAIL-INPROG: 0\tWARN-NEW: 0\tWARN-INPROG: 0\tINFO: 0\tIGNORE: 0\tPASS: 0\n");
    }

    @Test
    void shouldInfoIfConfigOnRuleWithAlerts() throws Exception {
        // Given
        given(ext.countNumberOfUrls()).willReturn(3);

        Map<Integer, Integer> alertCounts = new HashMap<>();
        alertCounts.put(1, 3);
        given(extReport.getAlertCountsByRule()).willReturn(alertCounts);

        var list = List.of(createRuleData(new TestPluginPassiveScanner(1, "rule1")));

        given(psJobResData.getAllRuleData()).willReturn(list);

        job.getData().getParameters().setFormat(Format.LONG);

        LinkedHashMap<String, Object> ruleDefn = new LinkedHashMap<>();
        ruleDefn.put("id", 1);
        ruleDefn.put("action", "INFO");

        LinkedHashMap<String, List<?>> data = new LinkedHashMap<>();
        ArrayList<LinkedHashMap<?, ?>> rulesDefn = new ArrayList<>();
        rulesDefn.add(ruleDefn);
        data.put("rules", rulesDefn);

        // When
        job.setJobData(data);
        job.verifyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertOutput(
                "Total of 3 URLs\n"
                        + "INFO: rule1 [1] x 3 \n"
                        + "FAIL-NEW: 0\tFAIL-INPROG: 0\tWARN-NEW: 0\tWARN-INPROG: 0\tINFO: 1\tIGNORE: 0\tPASS: 0\n");
    }

    @Test
    void shouldIgnoreIfConfigOnRuleWithAlerts() throws Exception {
        // Given
        given(ext.countNumberOfUrls()).willReturn(3);

        Map<Integer, Integer> alertCounts = new HashMap<>();
        alertCounts.put(1, 3);
        given(extReport.getAlertCountsByRule()).willReturn(alertCounts);

        var list = List.of(createRuleData(new TestPluginPassiveScanner(1, "rule1")));

        given(psJobResData.getAllRuleData()).willReturn(list);

        job.getData().getParameters().setFormat(Format.LONG);

        LinkedHashMap<String, Object> ruleDefn = new LinkedHashMap<>();
        ruleDefn.put("id", 1);
        ruleDefn.put("action", "IGNORE");

        LinkedHashMap<String, List<?>> data = new LinkedHashMap<>();
        ArrayList<LinkedHashMap<?, ?>> rulesDefn = new ArrayList<>();
        rulesDefn.add(ruleDefn);
        data.put("rules", rulesDefn);

        // When
        job.setJobData(data);
        job.verifyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertOutput(
                "Total of 3 URLs\n"
                        + "IGNORE: rule1 [1] x 3 \n"
                        + "FAIL-NEW: 0\tFAIL-INPROG: 0\tWARN-NEW: 0\tWARN-INPROG: 0\tINFO: 0\tIGNORE: 1\tPASS: 0\n");
    }

    @Test
    void shouldReportInOrderRulesWithAlerts() throws Exception {
        // Given
        given(ext.countNumberOfUrls()).willReturn(3);

        Map<Integer, Integer> alertCounts = new HashMap<>();
        alertCounts.put(1, 3);
        alertCounts.put(2, 3);
        alertCounts.put(3, 3);
        alertCounts.put(4, 3);
        given(extReport.getAlertCountsByRule()).willReturn(alertCounts);

        var list =
                List.of(
                        createRuleData(new TestPluginPassiveScanner(1, "rule1")),
                        createRuleData(new TestPluginPassiveScanner(2, "rule2")),
                        createRuleData(new TestPluginPassiveScanner(3, "rule3")),
                        createRuleData(new TestPluginPassiveScanner(4, "rule4")));

        given(psJobResData.getAllRuleData()).willReturn(list);

        ArrayList<LinkedHashMap<?, ?>> rulesDefn = new ArrayList<>();

        LinkedHashMap<String, Object> rule1Defn = new LinkedHashMap<>();
        rule1Defn.put("id", 1);
        rule1Defn.put("action", "FAIL");
        rulesDefn.add(rule1Defn);

        LinkedHashMap<String, Object> rule2Defn = new LinkedHashMap<>();
        rule2Defn.put("id", 2);
        rule2Defn.put("action", "IGNORE");
        rulesDefn.add(rule2Defn);

        LinkedHashMap<String, Object> rule4Defn = new LinkedHashMap<>();
        rule4Defn.put("id", 4);
        rule4Defn.put("action", "INFO");
        rulesDefn.add(rule4Defn);

        LinkedHashMap<String, List<?>> data = new LinkedHashMap<>();
        data.put("rules", rulesDefn);

        // When
        job.setJobData(data);
        job.verifyParameters(progress);
        job.getData().getParameters().setFormat(Format.LONG);
        job.runJob(env, progress);

        // Then
        assertOutput(
                "Total of 3 URLs\n"
                        + "IGNORE: rule2 [2] x 3 \n"
                        + "INFO: rule4 [4] x 3 \n"
                        + "WARN-NEW: rule3 [3] x 3 \n"
                        + "FAIL-NEW: rule1 [1] x 3 \n"
                        + "FAIL-NEW: 1\tFAIL-INPROG: 0\tWARN-NEW: 1\tWARN-INPROG: 0\tINFO: 1\tIGNORE: 1\tPASS: 0\n");
    }

    @Test
    void shouldWarnOnNoURLs() throws Exception {
        // Given
        given(ext.countNumberOfUrls()).willReturn(0);
        job.getData().getParameters().setFormat(Format.LONG);

        // When
        job.runJob(env, progress);

        // Then
        assertOutput(
                "No URLs found - is the target URL accessible? Local services may not be accessible from a Docker container\n");
    }

    @Test
    void shouldShowUrlsOnRuleWithAlerts() throws Exception {
        // Given
        given(ext.countNumberOfUrls()).willReturn(8);

        Map<Integer, Integer> alertCounts = new HashMap<>();
        alertCounts.put(1, 3);
        given(extReport.getAlertCountsByRule()).willReturn(alertCounts);

        List<HttpMessage> msgList =
                Arrays.asList(
                        new HttpMessage(new URI("https://www.example.com", true)),
                        new HttpMessage(new URI("https://www.example.com/a", true)),
                        new HttpMessage(new URI("https://www.example.com/b", true)));
        given(extReport.getHttpMessagesForRule(1, 5)).willReturn(msgList);

        var list = List.of(createRuleData(new TestPluginPassiveScanner(1, "rule1")));

        given(psJobResData.getAllRuleData()).willReturn(list);

        job.getData().getParameters().setFormat(Format.LONG);

        // When
        job.runJob(env, progress);

        // Then
        assertOutput(
                "Total of 8 URLs\n"
                        + "WARN-NEW: rule1 [1] x 3 \n"
                        + "\thttps://www.example.com (0 )\n"
                        + "\thttps://www.example.com/a (0 )\n"
                        + "\thttps://www.example.com/b (0 )\n"
                        + "FAIL-NEW: 0\tFAIL-INPROG: 0\tWARN-NEW: 1\tWARN-INPROG: 0\tINFO: 0\tIGNORE: 0\tPASS: 0\n");
    }

    @Test
    void shouldPassIfNoAlerts() throws Exception {
        // Given
        given(ext.countNumberOfUrls()).willReturn(10);

        given(extReport.getAlertCountsByRule()).willReturn(new HashMap<>());

        var list =
                List.of(
                        createRuleData(new TestPluginPassiveScanner(3, "rule3")),
                        createRuleData(new TestPluginPassiveScanner(2, "rule2")),
                        createRuleData(new TestPluginPassiveScanner(1, "rule1")));

        given(psJobResData.getAllRuleData()).willReturn(list);

        job.getData().getParameters().setFormat(Format.LONG);

        // When
        job.runJob(env, progress);

        // Then
        assertOutput(
                "Total of 10 URLs\n"
                        + "PASS: rule1 [1]\n"
                        + "PASS: rule2 [2]\n"
                        + "PASS: rule3 [3]\n"
                        + "FAIL-NEW: 0\tFAIL-INPROG: 0\tWARN-NEW: 0\tWARN-INPROG: 0\tINFO: 0\tIGNORE: 0\tPASS: 3\n");
    }

    @Test
    void shouldOutputJobsInAlphabeticIdOrder() throws Exception {
        // Given
        given(ext.countNumberOfUrls()).willReturn(10);

        given(extReport.getAlertCountsByRule()).willReturn(new HashMap<>());

        var list =
                List.of(
                        createRuleData(new TestPluginPassiveScanner(20, "rule20")),
                        createRuleData(new TestPluginPassiveScanner(1001, "rule1001")),
                        createRuleData(new TestPluginPassiveScanner(9, "rule9")));

        given(psJobResData.getAllRuleData()).willReturn(list);

        job.getData().getParameters().setFormat(Format.LONG);

        // When
        job.runJob(env, progress);

        // Then
        assertOutput(
                "Total of 10 URLs\n"
                        + "PASS: rule1001 [1001]\n"
                        + "PASS: rule20 [20]\n"
                        + "PASS: rule9 [9]\n"
                        + "FAIL-NEW: 0\tFAIL-INPROG: 0\tWARN-NEW: 0\tWARN-INPROG: 0\tINFO: 0\tIGNORE: 0\tPASS: 3\n");
    }

    @Test
    void shouldOutputCorrectLongReport() throws Exception {
        // Given
        given(ext.countNumberOfUrls()).willReturn(20);

        Map<Integer, Integer> alertCounts = new HashMap<>();
        alertCounts.put(1, 3);
        given(extReport.getAlertCountsByRule()).willReturn(alertCounts);

        List<HttpMessage> msgList =
                Arrays.asList(
                        new HttpMessage(new URI("https://www.example.com", true)),
                        new HttpMessage(new URI("https://www.example.com/a", true)),
                        new HttpMessage(new URI("https://www.example.com/b", true)));
        given(extReport.getHttpMessagesForRule(1, 5)).willReturn(msgList);

        var list =
                List.of(
                        createRuleData(new TestPluginPassiveScanner(1, "rule1")),
                        createRuleData(new TestPluginPassiveScanner(2, "rule2")),
                        createRuleData(new TestPluginPassiveScanner(3, "rule3")));

        given(psJobResData.getAllRuleData()).willReturn(list);

        job.getData().getParameters().setFormat(Format.LONG);

        // When
        job.runJob(env, progress);

        // Then
        assertOutput(
                "Total of 20 URLs\n"
                        + "PASS: rule2 [2]\n"
                        + "PASS: rule3 [3]\n"
                        + "WARN-NEW: rule1 [1] x 3 \n"
                        + "\thttps://www.example.com (0 )\n"
                        + "\thttps://www.example.com/a (0 )\n"
                        + "\thttps://www.example.com/b (0 )\n"
                        + "FAIL-NEW: 0\tFAIL-INPROG: 0\tWARN-NEW: 1\tWARN-INPROG: 0\tINFO: 0\tIGNORE: 0\tPASS: 2\n");
    }

    @Test
    void shouldOutputCorrectShortReport() throws Exception {
        // Given
        given(ext.countNumberOfUrls()).willReturn(20);

        Map<Integer, Integer> alertCounts = new HashMap<>();
        alertCounts.put(1, 3);
        given(extReport.getAlertCountsByRule()).willReturn(alertCounts);

        List<HttpMessage> msgList =
                Arrays.asList(
                        new HttpMessage(new URI("https://www.example.com", true)),
                        new HttpMessage(new URI("https://www.example.com/a", true)),
                        new HttpMessage(new URI("https://www.example.com/b", true)));
        given(extReport.getHttpMessagesForRule(1, 5)).willReturn(msgList);

        var list =
                List.of(
                        createRuleData(new TestPluginPassiveScanner(1, "rule1")),
                        createRuleData(new TestPluginPassiveScanner(2, "rule2")),
                        createRuleData(new TestPluginPassiveScanner(3, "rule3")));

        given(psJobResData.getAllRuleData()).willReturn(list);

        job.getData().getParameters().setFormat(Format.SHORT);

        // When
        job.runJob(env, progress);

        // Then
        assertOutput(
                "WARN-NEW: rule1 [1] x 3 \n"
                        + "FAIL-NEW: 0\tFAIL-INPROG: 0\tWARN-NEW: 1\tWARN-INPROG: 0\tINFO: 0\tIGNORE: 0\tPASS: 2\n");
    }

    @Test
    void shouldOutputNothingForNoneReport() throws Exception {
        // Given
        given(ext.countNumberOfUrls()).willReturn(20);

        Map<Integer, Integer> alertCounts = new HashMap<>();
        alertCounts.put(1, 3);
        given(extReport.getAlertCountsByRule()).willReturn(alertCounts);

        List<HttpMessage> msgList =
                Arrays.asList(
                        new HttpMessage(new URI("https://www.example.com", true)),
                        new HttpMessage(new URI("https://www.example.com/a", true)),
                        new HttpMessage(new URI("https://www.example.com/b", true)));
        given(extReport.getHttpMessagesForRule(1, 5)).willReturn(msgList);

        var list =
                List.of(
                        createRuleData(new TestPluginPassiveScanner(1, "rule1")),
                        createRuleData(new TestPluginPassiveScanner(2, "rule2")),
                        createRuleData(new TestPluginPassiveScanner(3, "rule3")));

        given(psJobResData.getAllRuleData()).willReturn(list);

        job.getData().getParameters().setFormat(Format.NONE);

        // When
        job.runJob(env, progress);

        // Then
        assertThat(os.toString(), is(""));
    }

    @Test
    void shouldOutputNothingByDefault() throws Exception {
        // Given
        given(ext.countNumberOfUrls()).willReturn(20);

        Map<Integer, Integer> alertCounts = new HashMap<>();
        alertCounts.put(1, 3);
        given(extReport.getAlertCountsByRule()).willReturn(alertCounts);

        List<HttpMessage> msgList =
                Arrays.asList(
                        new HttpMessage(new URI("https://www.example.com", true)),
                        new HttpMessage(new URI("https://www.example.com/a", true)),
                        new HttpMessage(new URI("https://www.example.com/b", true)));
        given(extReport.getHttpMessagesForRule(1, 5)).willReturn(msgList);

        var list =
                List.of(
                        createRuleData(new TestPluginPassiveScanner(1, "rule1")),
                        createRuleData(new TestPluginPassiveScanner(2, "rule2")),
                        createRuleData(new TestPluginPassiveScanner(3, "rule3")));

        given(psJobResData.getAllRuleData()).willReturn(list);

        // When
        job.runJob(env, progress);

        // Then
        assertThat(os.toString(), is(""));
    }

    @Test
    void shouldGenerateSummaryFile() throws Exception {
        // Given
        given(ext.countNumberOfUrls()).willReturn(20);

        Map<Integer, Integer> alertCounts = new HashMap<>();
        alertCounts.put(1, 3);
        given(extReport.getAlertCountsByRule()).willReturn(alertCounts);

        var list =
                List.of(
                        createRuleData(new TestPluginPassiveScanner(1, "rule1")),
                        createRuleData(new TestPluginPassiveScanner(2, "rule2")),
                        createRuleData(new TestPluginPassiveScanner(3, "rule3")));

        given(psJobResData.getAllRuleData()).willReturn(list);

        File f = File.createTempFile("zap.reports.outputsummary", "json");
        job.getData().getParameters().setSummaryFile(f.getAbsolutePath());
        job.getData().getParameters().setFormat(Format.LONG);

        // When
        job.runJob(env, progress);

        String summary = new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);

        // Then
        assertThat(summary, is("{\"pass\":2,\"warn\":1,\"fail\":0}"));
    }

    @Test
    void shouldIncludeCustomMessage() throws Exception {
        // Given
        given(ext.countNumberOfUrls()).willReturn(3);

        Map<Integer, Integer> alertCounts = new HashMap<>();
        alertCounts.put(1, 3);
        given(extReport.getAlertCountsByRule()).willReturn(alertCounts);

        var list = List.of(createRuleData(new TestPluginPassiveScanner(1, "rule1")));

        given(psJobResData.getAllRuleData()).willReturn(list);

        LinkedHashMap<String, Object> ruleDefn = new LinkedHashMap<>();
        ruleDefn.put("id", 1);
        ruleDefn.put("action", "WARN");
        ruleDefn.put("customMessage", "A custom message");

        LinkedHashMap<String, List<?>> data = new LinkedHashMap<>();
        ArrayList<LinkedHashMap<?, ?>> rulesDefn = new ArrayList<>();
        rulesDefn.add(ruleDefn);
        data.put("rules", rulesDefn);

        AutomationProgress realProgress = new AutomationProgress();

        // When
        job.setJobData(data);
        job.verifyParameters(realProgress);
        job.getData().getParameters().setFormat(Format.LONG);
        job.runJob(env, progress);

        // Then
        assertOutput(
                "Total of 3 URLs\n"
                        + "WARN-NEW: rule1 [1] x 3 A custom message\n"
                        + "FAIL-NEW: 0\tFAIL-INPROG: 0\tWARN-NEW: 1\tWARN-INPROG: 0\tINFO: 0\tIGNORE: 0\tPASS: 0\n");
    }

    private void assertOutput(String output) {
        assertThat(os.toString(), is(output.replace("\n", System.lineSeparator())));
    }

    private static org.zaproxy.addon.automation.jobs.PassiveScanJobResultData.RuleData
            createRuleData(TestPluginPassiveScanner rule) {
        return new org.zaproxy.addon.automation.jobs.PassiveScanJobResultData.RuleData(rule);
    }

    class TestPluginPassiveScanner extends PluginPassiveScanner {

        private int id;
        private String name;

        public TestPluginPassiveScanner(int id, String name) {
            this.id = id;
            this.name = name;
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public int getPluginId() {
            return id;
        }
    }
}
