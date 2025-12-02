/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.addon.reports;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import com.lowagie.text.DocumentException;
import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.logging.log4j.core.config.Configurator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.automation.JobResultData;
import org.zaproxy.zap.extension.alert.AlertNode;
import org.zaproxy.zap.extension.sequence.StdActiveScanRunner.SequenceStepData;
import org.zaproxy.zap.extension.sequence.automation.SequenceAScanJobResultData;
import org.zaproxy.zap.extension.stats.ExtensionStats;
import org.zaproxy.zap.extension.stats.InMemoryStats;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class ExtensionReportsJsonUnitTest extends TestUtils {

    private ExtensionLoader extensionLoader;

    @BeforeEach
    void setUp() throws Exception {
        mockMessages(new ExtensionReports());

        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
        extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
        Model.getSingleton().getOptionsParam().load(new ZapXmlConfiguration());

        Constant.PROGRAM_VERSION = "Dev Build";
        HttpRequestHeader.setDefaultUserAgent(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0");
    }

    @AfterEach
    void cleanup() throws URISyntaxException {
        Configurator.reconfigure(getClass().getResource("/log4j2-test.properties").toURI());
    }

    private static void checkAlert(JSONObject alert) {
        assertThat(alert.getString("@name"), is(equalTo("http://example.com")));
        assertThat(alert.getString("@host"), is(equalTo("example.com")));
        assertThat(alert.getString("@port"), is(equalTo("80")));
        assertThat(alert.getString("@ssl"), is(equalTo("false")));

        JSONArray alerts = alert.getJSONArray("alerts");
        assertThat(alerts.size(), is(equalTo(1)));
        assertThat(alerts.getJSONObject(0).getString("pluginid"), is(equalTo("1")));
        assertThat(alerts.getJSONObject(0).getString("alertRef"), is(equalTo("1")));
        assertThat(alerts.getJSONObject(0).getString("alert"), is(equalTo("XSS")));
        assertThat(alerts.getJSONObject(0).getString("name"), is(equalTo("XSS")));
        assertThat(alerts.getJSONObject(0).getString("riskcode"), is(equalTo("3")));
        assertThat(alerts.getJSONObject(0).getString("confidence"), is(equalTo("2")));
        assertThat(alerts.getJSONObject(0).getString("riskdesc"), is(equalTo("High (Medium)")));
        assertThat(
                alerts.getJSONObject(0).getString("desc"), is(equalTo("<p>XSS Description</p>")));
        assertThat(alerts.getJSONObject(0).getString("count"), is(equalTo("2")));
        assertThat(alerts.getJSONObject(0).getBoolean("systemic"), is(equalTo(false)));

        assertThat(
                alerts.getJSONObject(0).getString("solution"), is(equalTo("<p>Test Solution</p>")));
        assertThat(
                alerts.getJSONObject(0).getString("otherinfo"),
                is(equalTo("<p>Test 'Other\\</p>")));
        assertThat(
                alerts.getJSONObject(0).getString("reference"),
                is(equalTo("<p>Test Reference</p>")));
        assertThat(alerts.getJSONObject(0).getString("cweid"), is(equalTo("123")));
        assertThat(alerts.getJSONObject(0).getString("wascid"), is(equalTo("456")));
        assertThat(alerts.getJSONObject(0).getString("sourceid"), is(equalTo("0")));

        JSONArray instances = alerts.getJSONObject(0).getJSONArray("instances");
        assertThat(instances.size(), is(equalTo(2)));

        checkJsonAlertInstance(instances, 0);
        checkJsonAlertInstance(instances, 1);
    }

    private static void checkJsonAlertInstance(JSONArray instances, int i) {
        assertThat(
                instances.getJSONObject(i).getString("uri"),
                is(equalTo("http://example.com/example_3")));
        assertThat(instances.getJSONObject(i).getString("method"), is(equalTo("GET")));
        assertThat(instances.getJSONObject(i).getString("param"), is(equalTo("Test Param")));
        assertThat(
                instances.getJSONObject(i).getString("attack"), is(equalTo("Test \"Attack\\\"")));
        assertThat(
                instances.getJSONObject(i).getString("evidence"), is(equalTo("Test <p>Evidence")));
        String otherInfo = i == 0 ? "Test 'Other\\" : "Test Another 'Other\\";
        assertThat(instances.getJSONObject(i).getString("otherinfo"), is(equalTo(otherInfo)));
    }

    private static void checkJsonAlertInstanceAndMessages(JSONArray instances, int i) {
        assertThat(
                instances.getJSONObject(i).getString("request-header"),
                is(
                        equalTo(
                                "GET http://example.com/example_3 HTTP/1.1\r\nhost: example.com\r\nuser-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0\r\npragma: no-cache\r\ncache-control: no-cache\r\n\r\n")));
        assertThat(
                instances.getJSONObject(i).getString("request-body"),
                is(equalTo("Test Request Body")));
        assertThat(
                instances.getJSONObject(i).getString("response-header"),
                is(equalTo("HTTP/1.0 0\r\n\r\n")));
        assertThat(
                instances.getJSONObject(i).getString("response-body"),
                is(equalTo("Test Response Body")));
    }

    @Test
    void shouldGenerateValidJsonReport() throws Exception {
        // Given
        Template template = ReportTestUtils.getTemplateFromYamlFile("traditional-json");
        String fileName = "basic-traditional-json";
        File f = File.createTempFile(fileName, template.getExtension());

        // When
        File r = ReportTestUtils.generateReportWithAlerts(template, f);
        String report = new String(Files.readAllBytes(r.toPath()));

        JSONObject json = JSONObject.fromObject(report);
        JSONArray site = json.getJSONArray("site");

        // Then
        assertThat(json.getString("@version"), is(equalTo("Dev Build")));
        assertThat(json.getString("@generated").length(), is(greaterThan(20)));
        assertThat(site.size(), is(equalTo(1)));
        checkAlert(site.getJSONObject(0));
    }

    @Test
    void shouldGenerateValidJsonReportWithStats() throws Exception {
        // Given
        Template template = ReportTestUtils.getTemplateFromYamlFile("traditional-json-plus");
        String fileName = "traditional-json-plus-stats";
        File f = File.createTempFile(fileName, template.getExtension());
        InMemoryStats stats = new InMemoryStats();
        ExtensionStats extStats =
                mock(ExtensionStats.class, withSettings().strictness(Strictness.LENIENT));
        given(extensionLoader.getExtension(ExtensionStats.class)).willReturn(extStats);
        given(extStats.getInMemoryStats()).willReturn(stats);

        stats.counterInc("http://example.com", "site.a", 1);
        stats.counterInc("http://example.com", "site.b", 2);
        stats.counterInc("global.x", 3);
        stats.counterInc("global.y", 4);

        // When
        File r = ReportTestUtils.generateReportWithAlerts(template, f);
        String report = new String(Files.readAllBytes(r.toPath()));

        JSONObject json = JSONObject.fromObject(report);
        JSONArray site = json.getJSONArray("site");

        // Then
        assertThat(json.getString("@version"), is(equalTo("Dev Build")));
        assertThat(json.getString("@generated").length(), is(greaterThan(20)));
        assertThat(site.size(), is(equalTo(1)));
        checkAlert(site.getJSONObject(0));
        assertThat(site.getJSONObject(0).containsKey("statistics"), is(equalTo(true)));
        assertThat(site.getJSONObject(0).getJSONObject("statistics").size(), is(equalTo(2)));
        assertThat(site.getJSONObject(0).getJSONObject("statistics").get("site.a"), is(equalTo(1)));
        assertThat(site.getJSONObject(0).getJSONObject("statistics").get("site.b"), is(equalTo(2)));

        assertThat(json.containsKey("statistics"), is(equalTo(true)));
        assertThat(json.getJSONObject("statistics").size(), is(equalTo(2)));
        assertThat(json.getJSONObject("statistics").get("global.x"), is(equalTo(3)));
        assertThat(json.getJSONObject("statistics").get("global.y"), is(equalTo(4)));
    }

    private static File generateReportWithSequence(Template template, File f)
            throws IOException, DocumentException {
        ExtensionReports extRep = new ExtensionReports();
        ReportData reportData = new ReportData("test");
        reportData.setTitle("Test Title");
        reportData.setDescription("Test Description");
        reportData.setIncludeAllConfidences(true);
        reportData.setIncludeAllRisks(true);
        reportData.addSection("sequencedetails");

        AlertNode root = new AlertNode(0, "Test");
        reportData.setAlertTreeRootNode(root);

        List<JobResultData> list = new ArrayList<>();
        SequenceAScanJobResultData seqData = new SequenceAScanJobResultData("Test Job");
        List<SequenceStepData> steps = new ArrayList<>();
        steps.add(
                new SequenceStepData(
                        1,
                        true,
                        "Pass",
                        new ArrayList<Integer>(),
                        ReportTestUtils.newMsg("https://www.example.com/step1"),
                        ReportTestUtils.newMsg("https://www.example.com/step1")));
        steps.add(
                new SequenceStepData(
                        2,
                        false,
                        "Fail",
                        Arrays.asList(2, 4),
                        ReportTestUtils.newMsg("https://www.example.com/step2"),
                        ReportTestUtils.newMsg("https://www.example.com/step2")));
        seqData.addSequenceData("Seq name", steps);
        list.add(seqData);
        reportData.addReportObjects(seqData.getKey(), seqData);

        return extRep.generateReport(reportData, template, f.getAbsolutePath(), false);
    }

    @Test
    void shouldGenerateValidSequenceJsonReport() throws Exception {
        // Given
        Template template = ReportTestUtils.getTemplateFromYamlFile("traditional-json");
        String fileName = "basic-traditional-json";
        File f = File.createTempFile(fileName, template.getExtension());

        // When
        File r = generateReportWithSequence(template, f);
        String report = new String(Files.readAllBytes(r.toPath()));
        JSONObject json = JSONObject.fromObject(report);
        JSONArray site = json.getJSONArray("site");
        JSONArray sequences = json.getJSONArray("sequences");

        // Then
        assertThat(json.getString("@version"), is(equalTo("Dev Build")));
        assertThat(json.getString("@generated").length(), is(greaterThan(20)));
        assertThat(site.size(), is(equalTo(0)));
        assertThat(sequences.size(), is(equalTo(1)));
        assertThat(sequences.getJSONObject(0).getString("name"), is(equalTo("Seq name")));
        assertThat(sequences.getJSONObject(0).getJSONArray("steps").size(), is(equalTo(2)));

        assertThat(
                sequences.getJSONObject(0).getJSONArray("steps").getJSONObject(0).getString("step"),
                is(equalTo("1")));
        assertThat(
                sequences.getJSONObject(0).getJSONArray("steps").getJSONObject(0).getString("pass"),
                is(equalTo("true")));
        assertThat(
                sequences
                        .getJSONObject(0)
                        .getJSONArray("steps")
                        .getJSONObject(0)
                        .getString("resultDetails"),
                is(equalTo("Pass")));
        assertThat(
                sequences
                        .getJSONObject(0)
                        .getJSONArray("steps")
                        .getJSONObject(0)
                        .getJSONArray("alertIds")
                        .size(),
                is(equalTo(0)));
        assertThat(
                sequences
                        .getJSONObject(0)
                        .getJSONArray("steps")
                        .getJSONObject(0)
                        .getJSONObject("original")
                        .getString("uri"),
                is(equalTo("https://www.example.com/step1")));
        assertThat(
                sequences
                        .getJSONObject(0)
                        .getJSONArray("steps")
                        .getJSONObject(0)
                        .getJSONObject("original")
                        .getString("method"),
                is(equalTo("GET")));
        assertThat(
                sequences
                        .getJSONObject(0)
                        .getJSONArray("steps")
                        .getJSONObject(0)
                        .getJSONObject("replay")
                        .getString("uri"),
                is(equalTo("https://www.example.com/step1")));
        assertThat(
                sequences
                        .getJSONObject(0)
                        .getJSONArray("steps")
                        .getJSONObject(0)
                        .getJSONObject("replay")
                        .getString("method"),
                is(equalTo("GET")));
        assertThat(
                sequences
                        .getJSONObject(0)
                        .getJSONArray("steps")
                        .getJSONObject(0)
                        .getJSONObject("replay")
                        .containsKey("request-header"),
                is(false));
        assertThat(
                sequences
                        .getJSONObject(0)
                        .getJSONArray("steps")
                        .getJSONObject(0)
                        .getJSONObject("replay")
                        .containsKey("request-body"),
                is(false));
        assertThat(
                sequences
                        .getJSONObject(0)
                        .getJSONArray("steps")
                        .getJSONObject(0)
                        .getJSONObject("replay")
                        .containsKey("response-header"),
                is(false));
        assertThat(
                sequences
                        .getJSONObject(0)
                        .getJSONArray("steps")
                        .getJSONObject(0)
                        .getJSONObject("replay")
                        .containsKey("response-body"),
                is(false));

        assertThat(
                sequences.getJSONObject(0).getJSONArray("steps").getJSONObject(1).getString("step"),
                is(equalTo("2")));
        assertThat(
                sequences.getJSONObject(0).getJSONArray("steps").getJSONObject(1).getString("pass"),
                is(equalTo("false")));
        assertThat(
                sequences
                        .getJSONObject(0)
                        .getJSONArray("steps")
                        .getJSONObject(1)
                        .getString("resultDetails"),
                is(equalTo("Fail")));
        assertThat(
                sequences
                        .getJSONObject(0)
                        .getJSONArray("steps")
                        .getJSONObject(1)
                        .getJSONArray("alertIds")
                        .size(),
                is(equalTo(2)));
        assertThat(
                sequences
                        .getJSONObject(0)
                        .getJSONArray("steps")
                        .getJSONObject(1)
                        .getJSONArray("alertIds")
                        .getInt(0),
                is(equalTo(2)));
        assertThat(
                sequences
                        .getJSONObject(0)
                        .getJSONArray("steps")
                        .getJSONObject(1)
                        .getJSONArray("alertIds")
                        .getInt(1),
                is(equalTo(4)));
        assertThat(
                sequences
                        .getJSONObject(0)
                        .getJSONArray("steps")
                        .getJSONObject(1)
                        .getJSONObject("original")
                        .getString("uri"),
                is(equalTo("https://www.example.com/step2")));
        assertThat(
                sequences
                        .getJSONObject(0)
                        .getJSONArray("steps")
                        .getJSONObject(1)
                        .getJSONObject("original")
                        .getString("method"),
                is(equalTo("GET")));
        assertThat(
                sequences
                        .getJSONObject(0)
                        .getJSONArray("steps")
                        .getJSONObject(1)
                        .getJSONObject("replay")
                        .getString("uri"),
                is(equalTo("https://www.example.com/step2")));
        assertThat(
                sequences
                        .getJSONObject(0)
                        .getJSONArray("steps")
                        .getJSONObject(1)
                        .getJSONObject("replay")
                        .getString("method"),
                is(equalTo("GET")));
        assertThat(
                sequences
                        .getJSONObject(0)
                        .getJSONArray("steps")
                        .getJSONObject(1)
                        .getJSONObject("replay")
                        .containsKey("request-header"),
                is(false));
        assertThat(
                sequences
                        .getJSONObject(0)
                        .getJSONArray("steps")
                        .getJSONObject(1)
                        .getJSONObject("replay")
                        .containsKey("request-body"),
                is(false));
        assertThat(
                sequences
                        .getJSONObject(0)
                        .getJSONArray("steps")
                        .getJSONObject(1)
                        .getJSONObject("replay")
                        .containsKey("response-header"),
                is(false));
        assertThat(
                sequences
                        .getJSONObject(0)
                        .getJSONArray("steps")
                        .getJSONObject(1)
                        .getJSONObject("replay")
                        .containsKey("response-body"),
                is(false));
    }

    @Test
    void shouldGenerateValidSequenceJsonPlusReport() throws Exception {
        // Given
        Template template = ReportTestUtils.getTemplateFromYamlFile("traditional-json-plus");
        String fileName = "basic-traditional-json-plus";
        File f = File.createTempFile(fileName, template.getExtension());

        // When
        File r = generateReportWithSequence(template, f);

        String report = new String(Files.readAllBytes(r.toPath()));

        JSONObject json = JSONObject.fromObject(report);
        JSONArray site = json.getJSONArray("site");
        JSONArray sequences = json.getJSONArray("sequences");

        // Then
        assertThat(json.getString("@version"), is(equalTo("Dev Build")));
        assertThat(json.getString("@generated").length(), is(greaterThan(20)));
        assertThat(site.size(), is(equalTo(0)));
        assertThat(sequences.size(), is(equalTo(1)));
        assertThat(sequences.getJSONObject(0).getString("name"), is(equalTo("Seq name")));
        assertThat(sequences.getJSONObject(0).getJSONArray("steps").size(), is(equalTo(2)));

        assertThat(
                sequences.getJSONObject(0).getJSONArray("steps").getJSONObject(0).getString("step"),
                is(equalTo("1")));
        assertThat(
                sequences.getJSONObject(0).getJSONArray("steps").getJSONObject(0).getString("pass"),
                is(equalTo("true")));
        assertThat(
                sequences
                        .getJSONObject(0)
                        .getJSONArray("steps")
                        .getJSONObject(0)
                        .getString("resultDetails"),
                is(equalTo("Pass")));
        assertThat(
                sequences
                        .getJSONObject(0)
                        .getJSONArray("steps")
                        .getJSONObject(0)
                        .getJSONArray("alertIds")
                        .size(),
                is(equalTo(0)));
        assertThat(
                sequences
                        .getJSONObject(0)
                        .getJSONArray("steps")
                        .getJSONObject(0)
                        .getJSONObject("original")
                        .getString("uri"),
                is(equalTo("https://www.example.com/step1")));
        assertThat(
                sequences
                        .getJSONObject(0)
                        .getJSONArray("steps")
                        .getJSONObject(0)
                        .getJSONObject("original")
                        .getString("method"),
                is(equalTo("GET")));
        assertThat(
                sequences
                        .getJSONObject(0)
                        .getJSONArray("steps")
                        .getJSONObject(0)
                        .getJSONObject("replay")
                        .getString("uri"),
                is(equalTo("https://www.example.com/step1")));
        assertThat(
                sequences
                        .getJSONObject(0)
                        .getJSONArray("steps")
                        .getJSONObject(0)
                        .getJSONObject("replay")
                        .getString("method"),
                is(equalTo("GET")));
        assertThat(
                sequences
                        .getJSONObject(0)
                        .getJSONArray("steps")
                        .getJSONObject(0)
                        .getJSONObject("replay")
                        .getString("request-header"),
                is(not(nullValue())));
        assertThat(
                sequences
                        .getJSONObject(0)
                        .getJSONArray("steps")
                        .getJSONObject(0)
                        .getJSONObject("replay")
                        .getString("request-body"),
                is(not(nullValue())));
        assertThat(
                sequences
                        .getJSONObject(0)
                        .getJSONArray("steps")
                        .getJSONObject(0)
                        .getJSONObject("replay")
                        .getString("response-header"),
                is(not(nullValue())));
        assertThat(
                sequences
                        .getJSONObject(0)
                        .getJSONArray("steps")
                        .getJSONObject(0)
                        .getJSONObject("replay")
                        .getString("response-body"),
                is(not(nullValue())));

        assertThat(
                sequences.getJSONObject(0).getJSONArray("steps").getJSONObject(1).getString("step"),
                is(equalTo("2")));
        assertThat(
                sequences.getJSONObject(0).getJSONArray("steps").getJSONObject(1).getString("pass"),
                is(equalTo("false")));
        assertThat(
                sequences
                        .getJSONObject(0)
                        .getJSONArray("steps")
                        .getJSONObject(1)
                        .getString("resultDetails"),
                is(equalTo("Fail")));
        assertThat(
                sequences
                        .getJSONObject(0)
                        .getJSONArray("steps")
                        .getJSONObject(1)
                        .getJSONArray("alertIds")
                        .size(),
                is(equalTo(2)));
        assertThat(
                sequences
                        .getJSONObject(0)
                        .getJSONArray("steps")
                        .getJSONObject(1)
                        .getJSONArray("alertIds")
                        .getInt(0),
                is(equalTo(2)));
        assertThat(
                sequences
                        .getJSONObject(0)
                        .getJSONArray("steps")
                        .getJSONObject(1)
                        .getJSONArray("alertIds")
                        .getInt(1),
                is(equalTo(4)));
        assertThat(
                sequences
                        .getJSONObject(0)
                        .getJSONArray("steps")
                        .getJSONObject(1)
                        .getJSONObject("original")
                        .getString("uri"),
                is(equalTo("https://www.example.com/step2")));
        assertThat(
                sequences
                        .getJSONObject(0)
                        .getJSONArray("steps")
                        .getJSONObject(1)
                        .getJSONObject("original")
                        .getString("method"),
                is(equalTo("GET")));
        assertThat(
                sequences
                        .getJSONObject(0)
                        .getJSONArray("steps")
                        .getJSONObject(1)
                        .getJSONObject("replay")
                        .getString("uri"),
                is(equalTo("https://www.example.com/step2")));
        assertThat(
                sequences
                        .getJSONObject(0)
                        .getJSONArray("steps")
                        .getJSONObject(1)
                        .getJSONObject("replay")
                        .getString("method"),
                is(equalTo("GET")));
        assertThat(
                sequences
                        .getJSONObject(0)
                        .getJSONArray("steps")
                        .getJSONObject(1)
                        .getJSONObject("replay")
                        .getString("request-header"),
                is(not(nullValue())));
        assertThat(
                sequences
                        .getJSONObject(0)
                        .getJSONArray("steps")
                        .getJSONObject(1)
                        .getJSONObject("replay")
                        .getString("request-body"),
                is(not(nullValue())));
        assertThat(
                sequences
                        .getJSONObject(0)
                        .getJSONArray("steps")
                        .getJSONObject(1)
                        .getJSONObject("replay")
                        .getString("response-header"),
                is(not(nullValue())));
        assertThat(
                sequences
                        .getJSONObject(0)
                        .getJSONArray("steps")
                        .getJSONObject(1)
                        .getJSONObject("replay")
                        .getString("response-body"),
                is(not(nullValue())));
    }

    @Test
    void shouldGenerateValidInsightsJsonReport() throws Exception {
        // Given
        Template template = ReportTestUtils.getTemplateFromYamlFile("traditional-json");
        String fileName = "insights-traditional-json";
        File f = File.createTempFile(fileName, template.getExtension());

        // When
        File r = ReportTestUtils.generateReportWithInsights(template, f);
        String report = new String(Files.readAllBytes(r.toPath()));
        JSONObject json = JSONObject.fromObject(report);
        JSONArray site = json.getJSONArray("site");
        JSONArray insights = json.getJSONArray("insights");

        // Then
        assertThat(json.getString("@version"), is(equalTo("Dev Build")));
        assertThat(json.getString("@generated").length(), is(greaterThan(20)));
        assertThat(site.size(), is(equalTo(0)));
        assertThat(insights.size(), is(equalTo(3)));
        // Note that level and reason will not have been set up at the i18n'd in the insights add-on
        assertThat(
                insights.getJSONObject(0).getString("site"),
                is(equalTo("https://www.example.com")));
        assertThat(insights.getJSONObject(0).getString("key"), is(equalTo("insight.1")));
        assertThat(
                insights.getJSONObject(0).getString("description"), is(equalTo("Insight1 desc")));
        assertThat(insights.getJSONObject(0).getString("statistic"), is(equalTo("1")));

        assertThat(
                insights.getJSONObject(1).getString("site"),
                is(equalTo("https://www.example.com")));
        assertThat(insights.getJSONObject(1).getString("key"), is(equalTo("insight.2")));
        assertThat(
                insights.getJSONObject(1).getString("description"), is(equalTo("Insight2 desc")));
        assertThat(insights.getJSONObject(1).getString("statistic"), is(equalTo("2")));

        assertThat(insights.getJSONObject(2).getString("site"), is(equalTo("")));
        assertThat(insights.getJSONObject(2).getString("key"), is(equalTo("insight.3")));
        assertThat(
                insights.getJSONObject(2).getString("description"), is(equalTo("Insight3 desc")));
        assertThat(insights.getJSONObject(2).getString("statistic"), is(equalTo("30")));
    }

    @Test
    void shouldGenerateValidJsonPlusReport() throws Exception {
        // Given
        Template template = ReportTestUtils.getTemplateFromYamlFile("traditional-json-plus");
        String fileName = "basic-traditional-json-plus";
        File f = File.createTempFile(fileName, template.getExtension());

        // When
        File r = ReportTestUtils.generateReportWithAlerts(template, f);
        String report = new String(Files.readAllBytes(r.toPath()));

        JSONObject json = JSONObject.fromObject(report);
        JSONArray site = json.getJSONArray("site");

        // Then
        assertThat(json.getString("@version"), is(equalTo("Dev Build")));
        assertThat(json.getString("@generated").length(), is(greaterThan(20)));
        assertThat(site.size(), is(equalTo(1)));
        assertThat(site.getJSONObject(0).getString("@name"), is(equalTo("http://example.com")));
        assertThat(site.getJSONObject(0).getString("@host"), is(equalTo("example.com")));
        assertThat(site.getJSONObject(0).getString("@port"), is(equalTo("80")));
        assertThat(site.getJSONObject(0).getString("@ssl"), is(equalTo("false")));
        checkAlert(site.getJSONObject(0));

        JSONArray alerts = site.getJSONObject(0).getJSONArray("alerts");
        assertThat(alerts.size(), is(equalTo(1)));
        checkAlert(site.getJSONObject(0));
        JSONArray instances = alerts.getJSONObject(0).getJSONArray("instances");
        checkJsonAlertInstanceAndMessages(instances, 0);
        checkJsonAlertInstanceAndMessages(instances, 0);

        // tags are not included in non plus report
        JSONArray tags = alerts.getJSONObject(0).getJSONArray("tags");
        assertThat(tags.size(), is(equalTo(1)));
        assertThat(tags.getJSONObject(0).getString("tag"), is(equalTo("tagkey")));
        assertThat(tags.getJSONObject(0).getString("link"), is(equalTo("tagvalue")));
    }
}
