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
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertFalse;

import com.lowagie.text.DocumentException;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.insights.internal.Insight;
import org.zaproxy.addon.insights.report.ExtensionInsightsReport;
import org.zaproxy.zap.extension.alert.AlertNode;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.extension.scripts.internal.db.ScriptRunRecorder;
import org.zaproxy.zap.extension.scripts.report.ExtensionScriptsReport;
import org.zaproxy.zap.extension.scripts.report.ScriptRunReportData;
import org.zaproxy.zap.testutils.TestUtils;

public class ReportTestUtils {

    protected static final String ILLEGAL_XML_CHRS = "\u0000\u0013";
    // FIXME change everything that uses this to use ILLEGAL_XML_CHRS - these places currently fail
    protected static final String NOT_ILLEGAL_XML_CHRS = "";

    private static Alert createAlertNode(
            String name, String desc, int risk, int confidence, String prefix)
            throws URIException, HttpMalformedHeaderException, NullPointerException {
        Alert alert = new Alert(1, risk, confidence, name);
        String uriStr = "http://example.com/example_" + risk;
        HttpMessage msg = new HttpMessage(new URI(uriStr, true));
        msg.setRequestBody("Test Request Body");
        msg.setResponseBody("Test Response Body");

        alert.setDetail(
                desc,
                uriStr,
                "Test Param",
                "Test \"Attack\\\"",
                "Test " + prefix + "'Other\\" + (prefix.isEmpty() ? "\nSecond line" : ""),
                "Test Solution",
                "Test Reference",
                "Test <p>Evidence",
                123,
                456,
                msg);

        Map<String, String> tags = new HashMap<>();
        tags.put("tagkey", "tagvalue");
        alert.setTags(tags);
        return alert;
    }

    private static AlertNode getAlertNode(String name, String desc, int risk, int confidence)
            throws URIException, HttpMalformedHeaderException {
        AlertNode node = new AlertNode(risk, name);
        Alert alert1 = createAlertNode(name, desc, risk, confidence, "");
        Alert alert2 = createAlertNode(name, desc, risk, confidence, "Another ");
        node.setUserObject(alert1);

        AlertNode instance1 = new AlertNode(0, name);
        instance1.setUserObject(alert1);

        AlertNode instance2 = new AlertNode(0, name);
        instance2.setUserObject(alert2);

        node.add(instance1);
        node.add(instance2);

        return node;
    }

    static AlertNode getSystemicTaggedAlertNode(String name, String desc, int risk, int confidence)
            throws URIException, HttpMalformedHeaderException {
        AlertNode node = new AlertNode(risk, name);
        Alert alert1 = createAlertNode(name, desc, risk, confidence, "");
        Alert alert2 = createAlertNode(name, desc, risk, confidence, "Another ");

        Map<String, String> systemicTags = new HashMap<>();
        systemicTags.put(CommonAlertTag.SYSTEMIC.getTag(), CommonAlertTag.SYSTEMIC.getValue());
        alert1.setTags(systemicTags);
        alert2.setTags(systemicTags);

        node.setUserObject(alert1);

        AlertNode instance1 = new AlertNode(0, name);
        instance1.setUserObject(alert1);

        AlertNode instance2 = new AlertNode(0, name);
        instance2.setUserObject(alert2);

        node.add(instance1);
        node.add(instance2);

        return node;
    }

    @SuppressWarnings("removal")
    private static ReportData getTestReportDataWithAlerts()
            throws URIException, HttpMalformedHeaderException {
        ReportData reportData = new ReportData("test");
        reportData.setTitle("Test Title");
        reportData.setDescription("Test Description");
        reportData.setIncludeAllConfidences(true);
        reportData.setIncludeAllRisks(true);
        List<PluginPassiveScanner> list = new ArrayList<>();
        var pscanData =
                new org.zaproxy.addon.automation.jobs.PassiveScanJobResultData(
                        "passiveScan-wait", list);
        reportData.addReportObjects(pscanData.getKey(), pscanData);

        AlertNode root = new AlertNode(0, "Test");
        reportData.setAlertTreeRootNode(root);
        root.add(getAlertNode("XSS", "XSS Description", Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM));

        Alert emptyAlert = new Alert(1, 1, 1, "");
        emptyAlert.setMessage(new HttpMessage(new URI("http://example.com", true)));
        AlertNode instanceEmptyAlert = new AlertNode(0, "");
        instanceEmptyAlert.setUserObject(emptyAlert);
        root.add(instanceEmptyAlert);

        addSites(reportData);
        return reportData;
    }

    private static void addSites(ReportData reportData) {
        List<String> sites = new ArrayList<>();
        sites.add("http://example.com");
        reportData.setSites(sites);
    }

    protected static HttpMessage newMsg(String uri) {
        try {
            HttpMessage msg = new HttpMessage(new URI(uri + ILLEGAL_XML_CHRS, true));
            msg.getRequestHeader().setHeader("Test", "Foo-Header" + ILLEGAL_XML_CHRS);
            msg.getRequestBody().setBody(ILLEGAL_XML_CHRS);
            msg.getResponseHeader().setHeader("Test", "Foo-Header" + ILLEGAL_XML_CHRS);
            msg.getResponseBody().setBody(ILLEGAL_XML_CHRS);
            return msg;
        } catch (URIException | HttpMalformedHeaderException | NullPointerException e) {
            throw new RuntimeException(e);
        }
    }

    protected static AlertNode newAlertNode(
            int pluginId, int level, String name, String uri, int childCount) {
        Alert alert = new Alert(pluginId);
        setAlertData(uri, alert);
        AlertNode alertNode = new AlertNode(level, name + ILLEGAL_XML_CHRS);
        alertNode.setUserObject(alert);
        for (int i = 0; i < childCount; i++) {
            AlertNode childNode = new AlertNode(level, name + ILLEGAL_XML_CHRS);
            Alert childAlert = new Alert(pluginId);
            setAlertData(uri, childAlert);
            childNode.setUserObject(childAlert);
            alertNode.add(childNode);
        }
        return alertNode;
    }

    private static void setAlertData(String uri, Alert alert) {
        alert.setUri(uri + ILLEGAL_XML_CHRS);
        alert.setName("Foo-name" + ILLEGAL_XML_CHRS);
        alert.setDescription("Foo-Desc" + ILLEGAL_XML_CHRS);
        alert.setSolution("Foo-Sol" + ILLEGAL_XML_CHRS);
        alert.setOtherInfo("Foo-Other" + ILLEGAL_XML_CHRS);

        alert.setEvidence("Foo-evid" + ILLEGAL_XML_CHRS);
        alert.setReference("Foo-ref" + ILLEGAL_XML_CHRS);
        alert.setAttack("Foo-attack" + ILLEGAL_XML_CHRS);

        alert.setParam("Foo-param" + ILLEGAL_XML_CHRS);
        alert.setMessage(newMsg(uri));
    }

    static ReportData getTestReportData() {
        ReportData reportData = new ReportData("test");
        AlertNode root = new AlertNode(0, "Test");
        reportData.setAlertTreeRootNode(root);
        addSites(reportData);
        return reportData;
    }

    static File generateReportWithAlerts(Template template, File f)
            throws IOException, DocumentException {
        ExtensionReports extRep = new ExtensionReports();
        ReportData reportData = getTestReportDataWithAlerts();
        reportData.setSections(template.getSections());
        return extRep.generateReport(reportData, template, f.getAbsolutePath(), false);
    }

    static File generateReportWithSystemicTaggedAlert(Template template, File f)
            throws IOException, DocumentException, URIException, HttpMalformedHeaderException {
        ExtensionReports extRep = new ExtensionReports();
        ReportData reportData = new ReportData("test");
        reportData.setTitle("Test Title");
        reportData.setDescription("Test Description");
        reportData.setIncludeAllConfidences(true);
        reportData.setIncludeAllRisks(true);
        reportData.setSections(template.getSections());

        AlertNode root = new AlertNode(0, "Test");
        root.add(
                getSystemicTaggedAlertNode(
                        "XSS", "XSS Description", Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM));
        reportData.setAlertTreeRootNode(root);
        addSites(reportData);

        return extRep.generateReport(reportData, template, f.getAbsolutePath(), false);
    }

    static File generateReportWithInsights(Template template, File f)
            throws IOException, DocumentException {
        ExtensionReports extRep = new ExtensionReports();
        ReportData reportData = new ReportData("test");
        reportData.setTitle("Test Title");
        reportData.setDescription("Test Description");
        reportData.setIncludeAllConfidences(true);
        reportData.setIncludeAllRisks(true);
        reportData.addSection("insights");

        AlertNode root = new AlertNode(0, "Test");
        reportData.setAlertTreeRootNode(root);

        List<Insight> insightList =
                List.of(
                        new Insight(
                                Insight.Level.HIGH,
                                Insight.Reason.EXCEEDED_HIGH,
                                "https://www.example.com",
                                "insight.1",
                                "Insight1 desc",
                                1,
                                false),
                        new Insight(
                                Insight.Level.LOW,
                                Insight.Reason.EXCEEDED_LOW,
                                "https://www.example.com",
                                "insight.2",
                                "Insight2 desc",
                                2,
                                false),
                        new Insight(
                                Insight.Level.INFO,
                                Insight.Reason.INFO,
                                "",
                                "insight.3",
                                "Insight3 desc",
                                30,
                                true));
        reportData.addReportObjects(ExtensionInsightsReport.INSIGHTS_LIST, insightList);

        return extRep.generateReport(reportData, template, f.getAbsolutePath(), false);
    }

    static File generateReportWithScriptDiagnostics(Template template, File f)
            throws IOException, DocumentException {
        return generateReportWithScriptDiagnostics(template, f, true);
    }

    static File generateReportWithScriptDiagnostics(
            Template template, File f, boolean includeScriptDiagnosticsSection)
            throws IOException, DocumentException {
        ExtensionReports extRep = new ExtensionReports();
        ReportData reportData = new ReportData("test");
        reportData.setTitle("Test Title");
        reportData.setDescription("Test Description");
        reportData.setIncludeAllConfidences(true);
        reportData.setIncludeAllRisks(true);
        List<String> sections = new ArrayList<>(template.getSections());
        if (!includeScriptDiagnosticsSection) {
            sections.remove("scriptdiagnostics");
        }
        reportData.setSections(sections);

        AlertNode root = new AlertNode(0, "Test");
        reportData.setAlertTreeRootNode(root);

        return generateReportWithScriptDiagnostics(
                template, f, includeScriptDiagnosticsSection, defaultScriptDiagnosticRuns());
    }

    static List<ScriptRunReportData.Run> defaultScriptDiagnosticRuns() {
        return List.of(
                scriptRunReport(
                        "2026-04-01T12:00:00Z",
                        1,
                        "my-script",
                        "standalone",
                        -1,
                        "",
                        "Job: ... boom",
                        "boom"),
                scriptRunReport(
                        "2026-04-02T08:30:00Z",
                        1,
                        "chain-a",
                        "standalone",
                        13,
                        "ZestClientElementClick",
                        "Job: ... step failed",
                        "step failed"));
    }

    static File generateReportWithScriptDiagnostics(
            Template template, File f, List<ScriptRunReportData.Run> runs)
            throws IOException, DocumentException {
        return generateReportWithScriptDiagnostics(template, f, true, runs);
    }

    private static File generateReportWithScriptDiagnostics(
            Template template,
            File f,
            boolean includeScriptDiagnosticsSection,
            List<ScriptRunReportData.Run> runs)
            throws IOException, DocumentException {
        ExtensionReports extRep = new ExtensionReports();
        ReportData reportData = new ReportData("test");
        reportData.setTitle("Test Title");
        reportData.setDescription("Test Description");
        reportData.setIncludeAllConfidences(true);
        reportData.setIncludeAllRisks(true);
        List<String> sections = new ArrayList<>(template.getSections());
        if (!includeScriptDiagnosticsSection) {
            sections.remove("scriptdiagnostics");
        }
        reportData.setSections(sections);

        AlertNode root = new AlertNode(0, "Test");
        reportData.setAlertTreeRootNode(root);

        reportData.addReportObjects(
                ExtensionScriptsReport.SCRIPT_DIAGNOSTICS,
                new ScriptRunReportData.Diagnostics(runs));

        return extRep.generateReport(reportData, template, f.getAbsolutePath(), false);
    }

    static ScriptRunReportData.Run scriptRunReport(
            String created,
            int scriptOrder,
            String scriptName,
            String scriptType,
            int sourceStepIndex,
            String line,
            String summaryMessage,
            String outputDetailMessage) {
        return scriptRunReport(
                created,
                ScriptRunRecorder.OUTCOME_FAILED,
                scriptOrder,
                scriptName,
                scriptType,
                sourceStepIndex,
                line,
                ScriptRunRecorder.OUTPUT_KIND_ERROR,
                summaryMessage,
                outputDetailMessage);
    }

    static ScriptRunReportData.Run scriptRunReport(
            String created,
            String outcome,
            int scriptOrder,
            String scriptName,
            String scriptType,
            int sourceStepIndex,
            String line,
            String outputKind,
            String summaryMessage,
            String outputDetailMessage) {
        return new ScriptRunReportData.Run(
                created,
                outcome,
                summaryMessage,
                List.of(
                        new ScriptRunReportData.Script(
                                scriptOrder,
                                scriptName,
                                scriptType,
                                List.of(
                                        new ScriptRunReportData.Step(
                                                sourceStepIndex,
                                                line,
                                                List.of(
                                                        new ScriptRunReportData.Output(
                                                                outputKind,
                                                                outputDetailMessage)))))));
    }

    static Template getTemplateFromYamlFile(String templateName) throws Exception {
        return new Template(
                TestUtils.getResourcePath(
                                ExtensionReports.class,
                                "/reports/" + templateName + "/template.yaml")
                        .toFile());
    }

    static String readReportAsString(File report) throws IOException {
        return Files.readString(report.toPath(), StandardCharsets.UTF_8);
    }

    /** Shared assertions for script diagnostics content in traditional reports. */
    static final class ScriptDiagnosticsAssertions {

        private ScriptDiagnosticsAssertions() {}

        static void assertJsonScriptDiagnostics(JSONObject json) {
            JSONObject scriptDiagnostics = json.getJSONObject("scriptDiagnostics");
            assertThat(scriptDiagnostics.containsKey("runs"), is(true));
            JSONArray runs = scriptDiagnostics.getJSONArray("runs");
            assertThat(runs.size(), is(equalTo(2)));

            JSONObject run0 = runs.getJSONObject(0);
            assertJsonRunStructure(run0);
            assertThat(run0.getString("outcome"), is(equalTo("FAILED")));
            assertThat(run0.getString("summary"), is(equalTo("Job: ... boom")));
            assertThat(run0.getString("created"), is(equalTo("2026-04-01T12:00:00Z")));
            JSONObject script0 = run0.getJSONArray("scripts").getJSONObject(0);
            assertJsonScriptStructure(script0);
            assertThat(script0.getInt("order"), is(equalTo(1)));
            assertThat(script0.getString("scriptName"), is(equalTo("my-script")));
            assertThat(script0.getString("scriptType"), is(equalTo("standalone")));
            JSONObject step0 = script0.getJSONArray("steps").getJSONObject(0);
            assertJsonStepStructure(step0);
            assertThat(step0.getInt("sourceStepIndex"), is(equalTo(-1)));
            assertThat(step0.getString("line"), is(equalTo("")));
            JSONObject output0 = step0.getJSONArray("outputs").getJSONObject(0);
            assertJsonOutputStructure(output0);
            assertThat(output0.getString("kind"), is(equalTo("ERROR")));
            assertThat(output0.getString("message"), is(equalTo("boom")));

            JSONObject run1 = runs.getJSONObject(1);
            assertJsonRunStructure(run1);
            assertThat(run1.getString("summary"), is(equalTo("Job: ... step failed")));
            JSONObject script1 = run1.getJSONArray("scripts").getJSONObject(0);
            assertThat(script1.getString("scriptName"), is(equalTo("chain-a")));
            assertThat(script1.getInt("order"), is(equalTo(1)));
            JSONObject step1 = script1.getJSONArray("steps").getJSONObject(0);
            assertThat(step1.getInt("sourceStepIndex"), is(equalTo(13)));
            assertThat(step1.getString("line"), is(equalTo("ZestClientElementClick")));
        }

        static void assertJsonRunStructure(JSONObject run) {
            assertFalse(run.containsKey("createTimestamp"));
            assertThat(run.containsKey("created"), is(true));
            assertThat(run.containsKey("outcome"), is(true));
            assertThat(run.containsKey("summary"), is(true));
            assertThat(run.get("scripts"), is(not(nullValue())));
            assertThat(run.get("scripts"), is(instanceOf(JSONArray.class)));
        }

        static void assertJsonScriptStructure(JSONObject script) {
            assertThat(script.containsKey("order"), is(true));
            assertThat(script.containsKey("scriptName"), is(true));
            assertThat(script.containsKey("scriptType"), is(true));
            assertThat(script.get("steps"), is(not(nullValue())));
            assertThat(script.get("steps"), is(instanceOf(JSONArray.class)));
        }

        static void assertJsonStepStructure(JSONObject step) {
            assertThat(step.containsKey("sourceStepIndex"), is(true));
            assertThat(step.containsKey("line"), is(true));
            assertThat(step.get("outputs"), is(not(nullValue())));
            assertThat(step.get("outputs"), is(instanceOf(JSONArray.class)));
        }

        static void assertJsonOutputStructure(JSONObject output) {
            assertThat(output.containsKey("kind"), is(true));
            assertThat(output.containsKey("message"), is(true));
            assertThat(output.containsKey("detail"), is(false));
        }

        static void assertXmlScriptDiagnostics(NodeList scriptDiagnosticsNodes) {
            assertThat(scriptDiagnosticsNodes.getLength(), is(equalTo(1)));
            Element scriptDiagnostics = (Element) scriptDiagnosticsNodes.item(0);
            NodeList runs = scriptDiagnostics.getElementsByTagName("run");
            assertThat(runs.getLength(), is(equalTo(2)));

            assertXmlRun(
                    (Element) runs.item(0),
                    "2026-04-01T12:00:00Z",
                    "FAILED",
                    "Job: ... boom",
                    "my-script",
                    "standalone",
                    "-1",
                    "",
                    "ERROR",
                    "boom");
            assertXmlRun(
                    (Element) runs.item(1),
                    "2026-04-02T08:30:00Z",
                    "FAILED",
                    "Job: ... step failed",
                    "chain-a",
                    "standalone",
                    "13",
                    "ZestClientElementClick",
                    "ERROR",
                    "step failed");
        }

        private static void assertXmlRun(
                Element run,
                String created,
                String outcome,
                String summary,
                String scriptName,
                String scriptType,
                String sourceStepIndex,
                String line,
                String outputKind,
                String outputMessage) {
            assertThat(
                    run.getElementsByTagName("created").item(0).getTextContent(),
                    is(equalTo(created)));
            assertThat(
                    run.getElementsByTagName("outcome").item(0).getTextContent(),
                    is(equalTo(outcome)));
            assertThat(
                    run.getElementsByTagName("summary").item(0).getTextContent(),
                    is(equalTo(summary)));

            Element script = (Element) run.getElementsByTagName("script").item(0);
            assertThat(
                    script.getElementsByTagName("order").item(0).getTextContent(),
                    is(equalTo("1")));
            assertThat(
                    script.getElementsByTagName("scriptName").item(0).getTextContent(),
                    is(equalTo(scriptName)));
            assertThat(
                    script.getElementsByTagName("scriptType").item(0).getTextContent(),
                    is(equalTo(scriptType)));

            Element step = (Element) script.getElementsByTagName("step").item(0);
            assertThat(
                    step.getElementsByTagName("sourceStepIndex").item(0).getTextContent(),
                    is(equalTo(sourceStepIndex)));
            assertThat(
                    step.getElementsByTagName("line").item(0).getTextContent(), is(equalTo(line)));

            Element output = (Element) step.getElementsByTagName("output").item(0);
            assertThat(
                    output.getElementsByTagName("kind").item(0).getTextContent(),
                    is(equalTo(outputKind)));
            assertThat(
                    output.getElementsByTagName("message").item(0).getTextContent(),
                    is(equalTo(outputMessage)));
        }
    }
}
