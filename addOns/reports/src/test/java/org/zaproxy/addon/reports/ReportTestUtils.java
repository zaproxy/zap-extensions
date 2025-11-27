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

import com.lowagie.text.DocumentException;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.insights.internal.Insight;
import org.zaproxy.addon.insights.report.ExtensionInsightsReport;
import org.zaproxy.zap.extension.alert.AlertNode;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
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
                "Test " + prefix + "'Other\\",
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

    static Template getTemplateFromYamlFile(String templateName) throws Exception {
        return new Template(
                TestUtils.getResourcePath(
                                ExtensionReports.class,
                                "/reports/" + templateName + "/template.yaml")
                        .toFile());
    }
}
