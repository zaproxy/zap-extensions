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
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import com.lowagie.text.DocumentException;
import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
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
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.zaproxy.addon.automation.JobResultData;
import org.zaproxy.zap.extension.alert.AlertNode;
import org.zaproxy.zap.extension.sequence.StdActiveScanRunner.SequenceStepData;
import org.zaproxy.zap.extension.sequence.automation.SequenceAScanJobResultData;
import org.zaproxy.zap.extension.stats.ExtensionStats;
import org.zaproxy.zap.extension.stats.InMemoryStats;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class ExtensionReportsXmlUnitTest extends TestUtils {

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

    private static String cleanReport(String str) {
        return str.replaceFirst("generated=\".*\"", "generated=\"DATE\"")
                .replaceFirst("@generated\": \".*\"", "@generated\": \"DATE\"")
                .replaceFirst("created\": \".*\"", "created\": \"DATE\"")
                .replaceAll("basic-.*/", "dir")
                .replaceAll("[\\n\\r\\t ]+", " ");
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

    private static void checkXmlAlert(Document doc, boolean isXmlPlus) {

        NodeList sites = doc.getElementsByTagName("site");
        NodeList alerts = doc.getElementsByTagName("alerts");
        NodeList alertItems = doc.getElementsByTagName("alertitem");
        assertThat(sites.getLength(), is(equalTo(1)));
        assertThat(
                sites.item(0).getAttributes().getNamedItem("name").getTextContent(),
                is(equalTo("http://example.com")));
        assertThat(
                sites.item(0).getAttributes().getNamedItem("host").getTextContent(),
                is(equalTo("example.com")));
        assertThat(
                sites.item(0).getAttributes().getNamedItem("port").getTextContent(),
                is(equalTo("80")));
        assertThat(
                sites.item(0).getAttributes().getNamedItem("ssl").getTextContent(),
                is(equalTo("false")));

        assertThat(alerts.getLength(), is(equalTo(1)));
        assertThat(alertItems.getLength(), is(equalTo(1)));
        NodeList alertItemNodes = alertItems.item(0).getChildNodes();
        int alertItemCount = isXmlPlus ? 39 : 37;
        assertThat(alertItemNodes.getLength(), is(equalTo(alertItemCount)));
        int i = 0;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("#text"))); // Filler
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("pluginid")));
        assertThat(alertItemNodes.item(i).getTextContent(), is(equalTo("1")));
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("#text"))); // Filler
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("alertRef")));
        assertThat(alertItemNodes.item(i).getTextContent(), is(equalTo("1")));
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("#text"))); // Filler
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("alert")));
        assertThat(alertItemNodes.item(i).getTextContent(), is(equalTo("XSS")));
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("#text"))); // Filler
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("name")));
        assertThat(alertItemNodes.item(i).getTextContent(), is(equalTo("XSS")));
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("#text"))); // Filler
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("riskcode")));
        assertThat(alertItemNodes.item(i).getTextContent(), is(equalTo("3")));
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("#text"))); // Filler
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("confidence")));
        assertThat(alertItemNodes.item(i).getTextContent(), is(equalTo("2")));
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("#text"))); // Filler
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("riskdesc")));
        assertThat(alertItemNodes.item(i).getTextContent(), is(equalTo("High (Medium)")));
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("#text"))); // Filler
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("confidencedesc")));
        assertThat(alertItemNodes.item(i).getTextContent(), is(equalTo("Medium")));
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("#text"))); // Filler
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("desc")));
        String descTextContent = isXmlPlus ? "XSS Description" : "<p>XSS Description</p>";
        assertThat(alertItemNodes.item(i).getTextContent(), is(equalTo(descTextContent)));
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("#text"))); // Filler
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("instances")));
        NodeList instancesChildNodes = alertItemNodes.item(i).getChildNodes();
        assertThat(instancesChildNodes.getLength(), is(equalTo(5)));
        assertThat(instancesChildNodes.item(0).getNodeName(), is(equalTo("#text"))); // Filler
        assertThat(instancesChildNodes.item(1).getNodeName(), is(equalTo("instance"))); // Filler
        assertThat(instancesChildNodes.item(2).getNodeName(), is(equalTo("#text"))); // Filler

        checkXmlAlertInstance(instancesChildNodes, isXmlPlus, 1);
        checkXmlAlertInstance(instancesChildNodes, isXmlPlus, 3);

        // And back to the alertitem nodes
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("#text"))); // Filler
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("count")));
        assertThat(alertItemNodes.item(i).getTextContent(), is(equalTo("2")));
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("#text"))); // Filler
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("systemic")));
        assertThat(alertItemNodes.item(i).getTextContent(), is(equalTo("false")));
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("#text"))); // Filler
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("solution")));
        String solutionString = isXmlPlus ? "Test Solution" : "<p>Test Solution</p>";
        assertThat(alertItemNodes.item(i).getTextContent(), is(equalTo(solutionString)));
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("#text"))); // Filler
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("otherinfo")));
        String otherinfoString = isXmlPlus ? "Test 'Other\\" : "<p>Test 'Other\\</p>";
        assertThat(alertItemNodes.item(i).getTextContent(), is(equalTo(otherinfoString)));
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("#text"))); // Filler
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("reference")));
        String referenceString = isXmlPlus ? "Test Reference" : "<p>Test Reference</p>";
        assertThat(alertItemNodes.item(i).getTextContent(), is(equalTo(referenceString)));
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("#text"))); // Filler
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("cweid")));
        assertThat(alertItemNodes.item(i).getTextContent(), is(equalTo("123")));
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("#text"))); // Filler
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("wascid")));
        assertThat(alertItemNodes.item(i).getTextContent(), is(equalTo("456")));
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("#text"))); // Filler
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("sourceid")));
        assertThat(alertItemNodes.item(i).getTextContent(), is(equalTo("0")));
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("#text"))); // Filler
        if (!isXmlPlus) {
            return;
        }
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("tags")));
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("#text"))); // Filler
    }

    private static void checkXmlAlertInstance(
            NodeList instancesChildNodes, boolean isXmlPlus, int i) {
        NodeList instanceChildNodes = instancesChildNodes.item(i).getChildNodes();

        // Check the instance details
        int instanceItemCount = isXmlPlus ? 23 : 15;
        assertThat(instanceChildNodes.getLength(), is(equalTo(instanceItemCount)));
        int y = 0;
        assertThat(instanceChildNodes.item(y).getNodeName(), is(equalTo("#text"))); // Filler
        y++;
        assertThat(instanceChildNodes.item(y).getNodeName(), is(equalTo("uri")));
        assertThat(
                instanceChildNodes.item(y).getTextContent(),
                is(equalTo("http://example.com/example_3")));
        y++;
        assertThat(instanceChildNodes.item(y).getNodeName(), is(equalTo("#text"))); // Filler
        y++;
        assertThat(instanceChildNodes.item(y).getNodeName(), is(equalTo("nodeName")));
        assertThat(instanceChildNodes.item(y).getTextContent(), is(equalTo("")));
        y++;
        assertThat(instanceChildNodes.item(y).getNodeName(), is(equalTo("#text"))); // Filler
        y++;
        assertThat(instanceChildNodes.item(y).getNodeName(), is(equalTo("method")));
        assertThat(instanceChildNodes.item(y).getTextContent(), is(equalTo("GET")));
        y++;
        assertThat(instanceChildNodes.item(y).getNodeName(), is(equalTo("#text"))); // Filler
        y++;
        assertThat(instanceChildNodes.item(y).getNodeName(), is(equalTo("param")));
        assertThat(instanceChildNodes.item(y).getTextContent(), is(equalTo("Test Param")));
        y++;
        assertThat(instanceChildNodes.item(y).getNodeName(), is(equalTo("#text"))); // Filler
        y++;
        assertThat(instanceChildNodes.item(y).getNodeName(), is(equalTo("attack")));
        assertThat(instanceChildNodes.item(y).getTextContent(), is(equalTo("Test \"Attack\\\"")));
        y++;
        assertThat(instanceChildNodes.item(y).getNodeName(), is(equalTo("#text"))); // Filler
        y++;
        assertThat(instanceChildNodes.item(y).getNodeName(), is(equalTo("evidence")));
        assertThat(instanceChildNodes.item(y).getTextContent(), is(equalTo("Test <p>Evidence")));
        y++;
        assertThat(instanceChildNodes.item(y).getNodeName(), is(equalTo("#text"))); // Filler
        y++;
        assertThat(instanceChildNodes.item(y).getNodeName(), is(equalTo("otherinfo")));
        String otherInfo = i == 1 ? "Test 'Other\\" : "Test Another 'Other\\";
        assertThat(instanceChildNodes.item(y).getTextContent(), is(equalTo(otherInfo)));
        y++;
        if (isXmlPlus) {
            assertThat(instanceChildNodes.item(y).getNodeName(), is(equalTo("#text"))); // Filler
            y++;
            assertThat(instanceChildNodes.item(y).getNodeName(), is(equalTo("requestheader")));
            assertThat(
                    instanceChildNodes.item(y).getTextContent(),
                    is(
                            equalTo(
                                    "GET http://example.com/example_3 HTTP/1.1\nhost: example.com\nuser-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0\npragma: no-cache\ncache-control: no-cache\n\n")));
            y++;
            assertThat(instanceChildNodes.item(y).getNodeName(), is(equalTo("#text"))); // Filler
            y++;
            assertThat(instanceChildNodes.item(y).getNodeName(), is(equalTo("requestbody")));
            assertThat(
                    instanceChildNodes.item(y).getTextContent(), is(equalTo("Test Request Body")));
            y++;
            assertThat(instanceChildNodes.item(y).getNodeName(), is(equalTo("#text"))); // Filler
            y++;
            assertThat(instanceChildNodes.item(y).getNodeName(), is(equalTo("responseheader")));
            assertThat(instanceChildNodes.item(y).getTextContent(), is(equalTo("HTTP/1.0 0\n\n")));
            y++;
            assertThat(instanceChildNodes.item(y).getNodeName(), is(equalTo("#text"))); // Filler
            y++;
            assertThat(instanceChildNodes.item(y).getNodeName(), is(equalTo("responsebody")));
            assertThat(
                    instanceChildNodes.item(y).getTextContent(), is(equalTo("Test Response Body")));
            y++;
        }
        assertThat(instanceChildNodes.item(y).getNodeName(), is(equalTo("#text"))); // Filler
    }

    @Test
    void shouldGenerateValidXmlReport() throws Exception {
        // Given
        Template template = ReportTestUtils.getTemplateFromYamlFile("traditional-xml");
        String fileName = "basic-traditional-xml";
        File f = File.createTempFile(fileName, template.getExtension());
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        DocumentBuilder db = dbf.newDocumentBuilder();

        // When
        File r = ReportTestUtils.generateReportWithAlerts(template, f);
        Document doc = db.parse(r);
        Element root = doc.getDocumentElement();

        // Then
        checkXmlAlert(doc, false);
        assertThat(root.getNodeName(), is(equalTo("OWASPZAPReport")));
        assertThat(root.getAttribute("version"), is(equalTo("Dev Build")));
        assertThat(root.getAttribute("generated").length(), is(greaterThan(20)));
    }

    @Test
    void shouldGenerateValidXmlPlusReport() throws Exception {
        // Given
        Template template = ReportTestUtils.getTemplateFromYamlFile("traditional-xml-plus");
        String fileName = "basic-traditional-xml-plus";
        File f = File.createTempFile(fileName, template.getExtension());
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        DocumentBuilder db = dbf.newDocumentBuilder();

        // When
        File r = ReportTestUtils.generateReportWithAlerts(template, f);
        Document doc = db.parse(r);
        Element root = doc.getDocumentElement();

        // Then
        checkXmlAlert(doc, true);
        assertThat(root.getNodeName(), is(equalTo("OWASPZAPReport")));
        assertThat(root.getAttribute("version"), is(equalTo("Dev Build")));
        assertThat(root.getAttribute("generated").length(), is(greaterThan(20)));
    }

    @Test
    void shouldGenerateValidXmlPlusReportWithStats() throws Exception {
        // Given
        Template template = ReportTestUtils.getTemplateFromYamlFile("traditional-xml-plus");
        String fileName = "basic-traditional-xml-plus";
        File f = File.createTempFile(fileName, template.getExtension());
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        DocumentBuilder db = dbf.newDocumentBuilder();

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
        Document doc = db.parse(r);
        Element root = doc.getDocumentElement();

        // Then
        checkXmlAlert(doc, true);
        assertThat(root.getNodeName(), is(equalTo("OWASPZAPReport")));
        assertThat(root.getAttribute("version"), is(equalTo("Dev Build")));
        assertThat(root.getAttribute("generated").length(), is(greaterThan(20)));

        NodeList sites = doc.getElementsByTagName("site");

        assertThat(sites.getLength(), is(equalTo(1)));
        assertThat(sites.item(0).getChildNodes().getLength(), is(equalTo(5)));
        assertThat(sites.item(0).getChildNodes().item(3).getNodeName(), is(equalTo("statistics")));
        assertThat(
                sites.item(0).getChildNodes().item(3).getChildNodes().getLength(), is(equalTo(5)));

        assertThat(root.getChildNodes().getLength(), is(equalTo(5)));
        assertThat(root.getChildNodes().item(3).getNodeName(), is(equalTo("statistics")));
        assertThat(root.getChildNodes().item(3).getChildNodes().getLength(), is(equalTo(5)));
    }

    @Test
    void shouldGenerateValidInsightsXmlReport() throws Exception {
        Template template = ReportTestUtils.getTemplateFromYamlFile("traditional-xml");
        String fileName = "insights-traditional-xml";
        File f = File.createTempFile(fileName, template.getExtension());
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        DocumentBuilder db = dbf.newDocumentBuilder();

        // When
        File r = ReportTestUtils.generateReportWithInsights(template, f);
        Document doc = db.parse(r);
        Element root = doc.getDocumentElement();

        // Then
        assertThat(root.getNodeName(), is(equalTo("OWASPZAPReport")));
        assertThat(root.getAttribute("version"), is(equalTo("Dev Build")));
        assertThat(root.getAttribute("generated").length(), is(greaterThan(20)));

        NodeList insights = doc.getElementsByTagName("insights");
        assertThat(insights.getLength(), is(equalTo(1)));
        assertThat(insights.item(0).getChildNodes().getLength(), is(equalTo(7)));

        assertThat(insights.item(0).getChildNodes().item(3).getNodeName(), is(equalTo("insight")));
        validateInsight(
                insights.item(0).getChildNodes().item(1),
                "https://www.example.com",
                "insight.1",
                "Insight1 desc",
                "1");
        validateInsight(
                insights.item(0).getChildNodes().item(3),
                "https://www.example.com",
                "insight.2",
                "Insight2 desc",
                "2");
        validateInsight(
                insights.item(0).getChildNodes().item(5), "", "insight.3", "Insight3 desc", "30");
    }

    private static void validateInsight(
            Node insightNode, String site, String key, String desc, String stat) {
        assertThat(insightNode.getChildNodes().getLength(), is(equalTo(13)));

        assertThat(insightNode.getChildNodes().item(1).getNodeName(), is(equalTo("level")));
        assertThat(insightNode.getChildNodes().item(3).getNodeName(), is(equalTo("reason")));

        assertThat(insightNode.getChildNodes().item(5).getNodeName(), is(equalTo("site")));
        assertThat(insightNode.getChildNodes().item(5).getTextContent(), is(equalTo(site)));

        assertThat(insightNode.getChildNodes().item(7).getNodeName(), is(equalTo("key")));
        assertThat(insightNode.getChildNodes().item(7).getTextContent(), is(equalTo(key)));

        assertThat(insightNode.getChildNodes().item(9).getNodeName(), is(equalTo("description")));
        assertThat(insightNode.getChildNodes().item(9).getTextContent(), is(equalTo(desc)));

        assertThat(insightNode.getChildNodes().item(11).getNodeName(), is(equalTo("statistic")));
        assertThat(insightNode.getChildNodes().item(11).getTextContent(), is(equalTo(stat)));
    }
}
