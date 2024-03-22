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
package org.zaproxy.addon.reports;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.startsWith;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import com.lowagie.text.DocumentException;
import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Consumer;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.StringLayout;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Configurator;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.apache.logging.log4j.core.config.Property;
import org.apache.logging.log4j.core.layout.PatternLayout;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.zaproxy.addon.automation.jobs.PassiveScanJobResultData;
import org.zaproxy.zap.extension.alert.AlertNode;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.I18N;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class ExtensionReportsUnitTest extends TestUtils {

    private static final String ILLEGAL_XML_CHRS = "\u0000\u0013";
    // FIXME change everything that uses this to use ILLEGAL_XML_CHRS - these places currently fail
    private static final String NOT_ILLEGAL_XML_CHRS = "";

    private static final String HTML_REPORT_ALERT_SUMMARY_SECTION = "alertcount";
    private static final String HTML_REPORT_INSTANCE_SUMMARY_SECTION = "instancecount";
    private static final String HTML_REPORT_ALERT_DETAIL_SECTION = "alertdetails";
    private static final String HTML_REPORT_PASSING_RULES_SECTION = "passingrules";

    private static final String HTML_REPORT_ALERT_SUMMARY_SECTION_TITLE = "Summary of Alerts";
    private static final String HTML_REPORT_INSTANCE_SUMMARY_SECTION_TITLE = "Alerts";
    private static final String HTML_REPORT_ALERT_DETAILS_SECTION_TITLE = "Alert Detail";
    // The Passing rules section is defined in the report specific i18n file
    private static final String HTML_REPORT_PASSING_RULES_SECTION_TITLE = "Passing Rules";

    private List<String> logEvents;

    @BeforeEach
    void setUp() throws Exception {
        mockMessages(new ExtensionReports());

        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
        ExtensionLoader extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
        Model.getSingleton().getOptionsParam().load(new ZapXmlConfiguration());

        Constant.PROGRAM_VERSION = "Dev Build";
        HttpRequestHeader.setDefaultUserAgent(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0");
        logEvents = registerLogEvents();
    }

    @AfterEach
    void cleanup() throws URISyntaxException {
        Configurator.reconfigure(getClass().getResource("/log4j2-test.properties").toURI());
    }

    @Test
    void shouldReturnDefaultNoCounts() {
        // Given
        ExtensionReports extRep = new ExtensionReports();
        AlertNode root = new AlertNode(0, "Alerts");

        // When
        Map<Integer, Integer> counts = extRep.getAlertCountsByRule(root);

        // Then
        assertThat(counts.size(), is(equalTo(0)));
    }

    @Test
    void shouldReturnExpectedCounts() {
        // Given
        ExtensionReports extRep = new ExtensionReports();
        AlertNode root = new AlertNode(0, "Alerts");
        root.add(newAlertNode(1, Alert.RISK_HIGH, "Alert High 1", "https://www.example.com", 1));
        root.add(
                newAlertNode(2, Alert.RISK_MEDIUM, "Alert Medium 1", "https://www.example.com", 2));
        root.add(newAlertNode(3, Alert.RISK_LOW, "Alert Low 1", "https://www.example.com", 4));
        root.add(newAlertNode(4, Alert.RISK_LOW, "Alert Low 2", "https://www.example.com", 8));

        // When
        Map<Integer, Integer> counts = extRep.getAlertCountsByRule(root);

        // Then
        assertThat(counts.size(), is(equalTo(4)));
        assertThat(counts.get(1), is(equalTo(1)));
        assertThat(counts.get(2), is(equalTo(2)));
        assertThat(counts.get(3), is(equalTo(4)));
        assertThat(counts.get(4), is(equalTo(8)));
    }

    @Test
    void shouldReturnExpectedCountsWithSameAlertWithDifferentRisk() {
        // Given
        ExtensionReports extRep = new ExtensionReports();
        AlertNode root = new AlertNode(0, "Alerts");
        root.add(newAlertNode(1, Alert.RISK_HIGH, "Alert High 1", "https://www.example.com", 1));
        root.add(
                newAlertNode(1, Alert.RISK_MEDIUM, "Alert Medium 1", "https://www.example.com", 2));
        root.add(newAlertNode(2, Alert.RISK_LOW, "Alert Low 1", "https://www.example.com", 4));
        root.add(newAlertNode(2, Alert.RISK_LOW, "Alert Low 2", "https://www.example.com", 8));

        // When
        Map<Integer, Integer> counts = extRep.getAlertCountsByRule(root);

        // Then
        assertThat(counts.size(), is(equalTo(2)));
        assertThat(counts.get(1), is(equalTo(3)));
        assertThat(counts.get(2), is(equalTo(12)));
    }

    @Test
    void shouldReturnExpectedCountsIgnoringFalsePositives() {
        // Given
        ExtensionReports extRep = new ExtensionReports();
        AlertNode root = new AlertNode(0, "Alerts");
        root.add(newAlertNode(1, Alert.RISK_HIGH, "Alert High 1", "https://www.example.com", 1));
        root.add(
                newAlertNode(
                        1,
                        ExtensionReports.RISK_FALSE_POSITIVE,
                        "Alert Medium 1",
                        "https://www.example.com",
                        2));
        root.add(newAlertNode(2, Alert.RISK_LOW, "Alert Low 1", "https://www.example.com", 4));
        root.add(
                newAlertNode(
                        2,
                        ExtensionReports.RISK_FALSE_POSITIVE,
                        "Alert Low 2",
                        "https://www.example.com",
                        8));
        root.add(
                newAlertNode(
                        3,
                        ExtensionReports.RISK_FALSE_POSITIVE,
                        "Alert Low 3",
                        "https://www.example.com",
                        16));

        // When
        Map<Integer, Integer> counts = extRep.getAlertCountsByRule(root);

        // Then
        assertThat(counts.size(), is(equalTo(2)));
        assertThat(counts.get(1), is(equalTo(1)));
        assertThat(counts.get(2), is(equalTo(4)));
    }

    private static HttpMessage newMsg(String uri) {
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

    private static AlertNode newAlertNode(
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

    @Test
    void shouldReturnAllMessages() {
        // Given
        ExtensionReports extRep = new ExtensionReports();
        AlertNode root = new AlertNode(0, "Alerts");
        root.add(newAlertNode(1, Alert.RISK_HIGH, "Alert High 1", "https://www.example.com", 1));
        root.add(
                newAlertNode(2, Alert.RISK_MEDIUM, "Alert Medium 1", "https://www.example.com", 2));
        root.add(newAlertNode(3, Alert.RISK_LOW, "Alert Low 1", "https://www.example.com", 4));
        root.add(newAlertNode(4, Alert.RISK_LOW, "Alert Low 2", "https://www.example.com", 8));

        // When
        List<HttpMessage> msgs = extRep.getHttpMessagesForRule(root, 4, 10);

        // Then
        assertThat(msgs.size(), is(equalTo(8)));
    }

    @Test
    void shouldReturnMaxNumberOfMessages() {
        // Given
        ExtensionReports extRep = new ExtensionReports();
        AlertNode root = new AlertNode(0, "Alerts");
        root.add(newAlertNode(1, Alert.RISK_HIGH, "Alert High 1", "https://www.example.com", 1));
        root.add(
                newAlertNode(2, Alert.RISK_MEDIUM, "Alert Medium 1", "https://www.example.com", 2));
        root.add(newAlertNode(3, Alert.RISK_LOW, "Alert Low 1", "https://www.example.com", 4));
        root.add(newAlertNode(4, Alert.RISK_LOW, "Alert Low 2", "https://www.example.com", 8));

        // When
        List<HttpMessage> msgs = extRep.getHttpMessagesForRule(root, 4, 5);

        // Then
        assertThat(msgs.size(), is(equalTo(5)));
    }

    @Test
    void shouldIgnoreFalsePositiveAlertMessages() {
        // Given
        ExtensionReports extRep = new ExtensionReports();
        AlertNode root = new AlertNode(0, "Alerts");
        root.add(newAlertNode(1, Alert.RISK_HIGH, "Alert High 1", "https://www.example.com", 1));
        root.add(newAlertNode(2, Alert.RISK_LOW, "Alert Low 1", "https://www.example.com", 3));
        root.add(
                newAlertNode(
                        2,
                        ExtensionReports.RISK_FALSE_POSITIVE,
                        "Alert Low 2",
                        "https://www.example.com",
                        8));

        // When
        List<HttpMessage> msgs = extRep.getHttpMessagesForRule(root, 2, 5);

        // Then
        assertThat(msgs.size(), is(equalTo(3)));
    }

    @Test
    void shouldExtractExpectedParams() {
        // Given
        String pattern = ReportParam.DEFAULT_NAME_PATTERN;
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");

        // When
        String dateStr = sdf.format(new Date());
        String expectedName = dateStr + "-ZAP-Report-www.example.com";
        String name1 = ExtensionReports.getNameFromPattern(pattern, "https://www.example.com");
        String name2 = ExtensionReports.getNameFromPattern(pattern, "https://www.example.com/");
        String name3 =
                ExtensionReports.getNameFromPattern(pattern, "https://www.example.com:8443/");
        String name4 = ExtensionReports.getNameFromPattern(pattern, "https://www.example.com/path");

        // Then
        assertThat(name1, is(equalTo(expectedName)));
        assertThat(name2, is(equalTo(expectedName)));
        assertThat(name3, is(equalTo(expectedName)));
        assertThat(name4, is(equalTo(expectedName)));
    }

    @Test
    void shouldIncludeRelevantContextUrls() {
        // Given
        Context context = new Context(null, 1);
        context.addIncludeInContextRegex("https://www.example.com.*");
        context.addIncludeInContextRegex("https://www.example.com2/test.*");
        ReportData reportData = new ReportData(true, true);
        reportData.setContexts(Arrays.asList(context));

        Alert alert1 = new Alert(1);
        alert1.setUri("https://www.example.com/");

        Alert alert2 = new Alert(2);
        alert2.setUri("https://www.example.com/test/");

        Alert alert3 = new Alert(3);
        alert3.setUri("https://www.example.com2/test/");

        // When
        AlertNode alertNode1 = new AlertNode(-1, "Alert 1");
        alertNode1.setUserObject(alert1);
        AlertNode alertNode2 = new AlertNode(-2, "Alert 2");
        alertNode2.setUserObject(alert2);
        AlertNode alertNode3 = new AlertNode(-3, "Alert 3");
        alertNode3.setUserObject(alert3);

        // Then
        assertThat(ExtensionReports.isIncluded(reportData, alertNode1), is(equalTo(true)));
        assertThat(ExtensionReports.isIncluded(reportData, alertNode2), is(equalTo(true)));
        assertThat(ExtensionReports.isIncluded(reportData, alertNode3), is(equalTo(true)));
    }

    @Test
    void shouldExcludeRelevantContextUrls() {
        // Given
        Context context = new Context(null, 1);
        context.addIncludeInContextRegex("https://www.example.com/.*");
        context.addIncludeInContextRegex("https://www.example.com2/test.*");
        ReportData reportData = new ReportData(true, true);
        reportData.setContexts(Arrays.asList(context));

        Alert alert1 = new Alert(1);
        alert1.setUri("https://www.example.org/");

        Alert alert2 = new Alert(2);
        alert2.setUri("http://www.example.com/test/");

        Alert alert3 = new Alert(3);
        alert3.setUri("https://www.example.com2/");

        // When
        AlertNode alertNode1 = new AlertNode(-1, "Alert 1");
        alertNode1.setUserObject(alert1);
        AlertNode alertNode2 = new AlertNode(-2, "Alert 2");
        alertNode2.setUserObject(alert2);
        AlertNode alertNode3 = new AlertNode(-3, "Alert 3");
        alertNode3.setUserObject(alert3);

        // Then
        assertThat(ExtensionReports.isIncluded(reportData, alertNode1), is(equalTo(false)));
        assertThat(ExtensionReports.isIncluded(reportData, alertNode2), is(equalTo(false)));
        assertThat(ExtensionReports.isIncluded(reportData, alertNode3), is(equalTo(false)));
    }

    @Test
    void shouldIncludeRelevantSiteUrls() {
        // Given
        String site1 = "https://www.example.com";
        String site2 = "https://www.example.com2";

        ReportData reportData = new ReportData(true, true);
        reportData.setSites(Arrays.asList(site1, site2));

        Alert alert1 = new Alert(1);
        alert1.setUri("https://www.example.com/");

        Alert alert2 = new Alert(2);
        alert2.setUri("https://www.example.com/test/");

        Alert alert3 = new Alert(3);
        alert3.setUri("https://www.example.com2/test/");

        // When
        AlertNode alertNode1 = new AlertNode(-1, "Alert 1");
        alertNode1.setUserObject(alert1);
        AlertNode alertNode2 = new AlertNode(-2, "Alert 2");
        alertNode2.setUserObject(alert2);
        AlertNode alertNode3 = new AlertNode(-3, "Alert 3");
        alertNode3.setUserObject(alert3);

        // Then
        assertThat(ExtensionReports.isIncluded(reportData, alertNode1), is(equalTo(true)));
        assertThat(ExtensionReports.isIncluded(reportData, alertNode2), is(equalTo(true)));
        assertThat(ExtensionReports.isIncluded(reportData, alertNode3), is(equalTo(true)));
    }

    @Test
    void shouldExcludeRelevantSiteUrls() {
        // Given
        String site1 = "https://www.example.com/";
        String site2 = "https://www.example.com2/";

        ReportData reportData = new ReportData(true, true);
        reportData.setSites(Arrays.asList(site1, site2));

        Alert alert1 = new Alert(1);
        alert1.setUri("https://www.example.org/");

        Alert alert2 = new Alert(2);
        alert2.setUri("http://www.example.com/test/");

        Alert alert3 = new Alert(3);
        alert3.setUri("https://www.example.com3/");

        // When
        AlertNode alertNode1 = new AlertNode(-1, "Alert 1");
        alertNode1.setUserObject(alert1);
        AlertNode alertNode2 = new AlertNode(-2, "Alert 2");
        alertNode2.setUserObject(alert2);
        AlertNode alertNode3 = new AlertNode(-3, "Alert 3");
        alertNode3.setUserObject(alert3);

        // Then
        assertThat(ExtensionReports.isIncluded(reportData, alertNode1), is(equalTo(false)));
        assertThat(ExtensionReports.isIncluded(reportData, alertNode2), is(equalTo(false)));
        assertThat(ExtensionReports.isIncluded(reportData, alertNode3), is(equalTo(false)));
    }

    @Test
    void shouldIncludeRelevantContextAndSiteUrls() {
        // Given
        Context context = new Context(null, 1);
        context.addIncludeInContextRegex("https://www.example.com.*");
        context.addIncludeInContextRegex("https://www.example.com2/test.*");
        String site1 = "https://www.example.com";
        String site2 = "https://www.example.com2";

        ReportData reportData = new ReportData(true, true);
        reportData.setSites(Arrays.asList(site1, site2));
        reportData.setContexts(Arrays.asList(context));

        Alert alert1 = new Alert(1);
        alert1.setUri("https://www.example.com/");

        Alert alert2 = new Alert(2);
        alert2.setUri("https://www.example.com/test/");

        Alert alert3 = new Alert(3);
        alert3.setUri("https://www.example.com2/test/");

        // When
        AlertNode alertNode1 = new AlertNode(-1, "Alert 1");
        alertNode1.setUserObject(alert1);
        AlertNode alertNode2 = new AlertNode(-2, "Alert 2");
        alertNode2.setUserObject(alert2);
        AlertNode alertNode3 = new AlertNode(-3, "Alert 3");
        alertNode3.setUserObject(alert3);

        // Then
        assertThat(ExtensionReports.isIncluded(reportData, alertNode1), is(equalTo(true)));
        assertThat(ExtensionReports.isIncluded(reportData, alertNode2), is(equalTo(true)));
        assertThat(ExtensionReports.isIncluded(reportData, alertNode3), is(equalTo(true)));
    }

    @Test
    void shouldExcludeRelevantContextAndSiteUrls() {
        // Given
        Context context = new Context(null, 1);
        context.addIncludeInContextRegex("https://www.example.com/.*");
        context.addIncludeInContextRegex("https://www.example.com2/test.*");
        context.addExcludeFromContextRegex("https://www.example.com/test.*");
        String site1 = "https://www.example.org";
        String site2 = "https://www.example.com3";

        ReportData reportData = new ReportData(true, true);
        reportData.setSites(Arrays.asList(site1, site2));
        reportData.setContexts(Arrays.asList(context));

        Alert alert1 = new Alert(1);
        // In sites but not in contexts
        alert1.setUri("https://www.example.org/");

        Alert alert2 = new Alert(2);
        // In sites but excluded from contexts
        alert2.setUri("https://www.example.com/test/");

        Alert alert3 = new Alert(3);
        // In context but not in sites
        alert3.setUri("https://www.example.com2/test/");

        // When
        AlertNode alertNode1 = new AlertNode(-1, "Alert 1");
        alertNode1.setUserObject(alert1);
        AlertNode alertNode2 = new AlertNode(-2, "Alert 2");
        alertNode2.setUserObject(alert2);
        AlertNode alertNode3 = new AlertNode(-3, "Alert 3");
        alertNode3.setUserObject(alert3);

        // Then
        assertThat(ExtensionReports.isIncluded(reportData, alertNode1), is(equalTo(false)));
        assertThat(ExtensionReports.isIncluded(reportData, alertNode2), is(equalTo(false)));
        assertThat(ExtensionReports.isIncluded(reportData, alertNode3), is(equalTo(false)));
    }

    private static ReportData getTestReportData() {
        ReportData reportData = new ReportData();
        AlertNode root = new AlertNode(0, "Test");
        reportData.setAlertTreeRootNode(root);
        addSites(reportData);
        return reportData;
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "traditional-html",
                "traditional-html-plus",
                "traditional-md",
                "traditional-xml"
            })
    void shouldGenerateReport(String reportName) throws Exception {
        // Given
        ExtensionReports extRep = new ExtensionReports();
        ReportData reportData = getTestReportData();
        File f = File.createTempFile("zap.reports.test", "x");
        Template template = getTemplateFromYamlFile(reportName);

        // When
        File r = extRep.generateReport(reportData, template, f.getAbsolutePath(), false);

        // Then
        assertThat(r.length(), greaterThan(0L));
    }

    @ParameterizedTest
    @ValueSource(strings = {"traditional-html", "traditional-html-plus", "traditional-md"})
    void shouldIncludeAllSectionsInReport(String reportName) throws Exception {
        // Given
        ExtensionReports extRep = new ExtensionReports();
        ReportData reportData = getTestReportData();
        File f = File.createTempFile("zap.reports.test", "x");
        Template template = getTemplateFromYamlFile(reportName);

        // When
        reportData.addSection(HTML_REPORT_ALERT_SUMMARY_SECTION);
        reportData.addSection(HTML_REPORT_INSTANCE_SUMMARY_SECTION);
        reportData.addSection(HTML_REPORT_ALERT_DETAIL_SECTION);

        File r = extRep.generateReport(reportData, template, f.getAbsolutePath(), false);
        String report = new String(Files.readAllBytes(r.toPath()));

        // Then
        assertThat(report.contains(HTML_REPORT_ALERT_SUMMARY_SECTION_TITLE), is(true));
        assertThat(report.contains(HTML_REPORT_INSTANCE_SUMMARY_SECTION_TITLE), is(true));
        assertThat(report.contains(HTML_REPORT_ALERT_DETAILS_SECTION_TITLE), is(true));
    }

    @ParameterizedTest
    @ValueSource(strings = {"traditional-html", "traditional-html-plus", "traditional-md"})
    void shouldIncludeAlertSummarySectionInReport(String reportName) throws Exception {
        // Given
        ExtensionReports extRep = new ExtensionReports();
        ReportData reportData = getTestReportData();
        File f = File.createTempFile("zap.reports.test", "x");
        Template template = getTemplateFromYamlFile(reportName);

        // When
        reportData.addSection(HTML_REPORT_ALERT_SUMMARY_SECTION);

        File r = extRep.generateReport(reportData, template, f.getAbsolutePath(), false);
        String report = new String(Files.readAllBytes(r.toPath()));

        // Then
        assertThat(report.contains(HTML_REPORT_ALERT_SUMMARY_SECTION_TITLE), is(true));
        assertThat(report.contains(HTML_REPORT_INSTANCE_SUMMARY_SECTION_TITLE), is(true));
        assertThat(report.contains(HTML_REPORT_ALERT_DETAILS_SECTION_TITLE), is(false));
    }

    @ParameterizedTest
    @ValueSource(strings = {"traditional-html", "traditional-html-plus", "traditional-md"})
    void shouldIncludeInstanceSummarySectionInReport(String reportName) throws Exception {
        // Given
        ExtensionReports extRep = new ExtensionReports();
        ReportData reportData = getTestReportData();
        File f = File.createTempFile("zap.reports.test", "x");
        Template template = getTemplateFromYamlFile(reportName);

        // When
        reportData.addSection(HTML_REPORT_INSTANCE_SUMMARY_SECTION);

        File r = extRep.generateReport(reportData, template, f.getAbsolutePath(), false);
        String report = new String(Files.readAllBytes(r.toPath()));

        // Then
        assertThat(report.length(), greaterThan(0));
        assertThat(report.contains(HTML_REPORT_ALERT_SUMMARY_SECTION_TITLE), is(false));
        assertThat(report.contains(HTML_REPORT_INSTANCE_SUMMARY_SECTION_TITLE), is(true));
        assertThat(report.contains(HTML_REPORT_ALERT_DETAILS_SECTION_TITLE), is(false));
    }

    @ParameterizedTest
    @ValueSource(strings = {"traditional-html", "traditional-html-plus", "traditional-md"})
    void shouldIncludeAlertDetailsSectionInReport(String reportName) throws Exception {
        // Given
        ExtensionReports extRep = new ExtensionReports();
        ReportData reportData = getTestReportData();
        File f = File.createTempFile("zap.reports.test", "x");
        Template template = getTemplateFromYamlFile(reportName);

        // When
        reportData.addSection(HTML_REPORT_ALERT_DETAIL_SECTION);
        File r = extRep.generateReport(reportData, template, f.getAbsolutePath(), false);
        String report = new String(Files.readAllBytes(r.toPath()));

        // Then
        assertThat(report.length(), greaterThan(0));
        assertThat(report.contains(HTML_REPORT_ALERT_SUMMARY_SECTION_TITLE), is(false));
        assertThat(report.contains(HTML_REPORT_INSTANCE_SUMMARY_SECTION_TITLE), is(false));
        assertThat(report.contains(HTML_REPORT_ALERT_DETAILS_SECTION_TITLE), is(true));
    }

    @ParameterizedTest
    @ValueSource(strings = {"traditional-html-plus"})
    void shouldIncludePassingRulesSectionInReport(String reportName) throws Exception {
        // Given
        ExtensionReports extRep = new ExtensionReports();
        ReportData reportData = getTestReportData();
        PassiveScanJobResultData pscanData =
                new PassiveScanJobResultData("test", new ArrayList<>());
        reportData.addReportObjects(pscanData.getKey(), pscanData);
        File f = File.createTempFile("zap.reports.test", "x");
        Template template = getTemplateFromYamlFile(reportName);

        // When
        reportData.addSection(HTML_REPORT_PASSING_RULES_SECTION);
        File r = extRep.generateReport(reportData, template, f.getAbsolutePath(), false);
        String report = new String(Files.readAllBytes(r.toPath()));

        // Then
        assertThat(report.length(), greaterThan(0));
        assertThat(report.contains(HTML_REPORT_ALERT_SUMMARY_SECTION_TITLE), is(false));
        assertThat(report.contains(HTML_REPORT_INSTANCE_SUMMARY_SECTION_TITLE), is(false));
        assertThat(report.contains(HTML_REPORT_ALERT_DETAILS_SECTION_TITLE), is(false));
        assertThat(report.contains(HTML_REPORT_PASSING_RULES_SECTION_TITLE), is(true));
    }

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

    private static ReportData getTestReportDataWithAlerts()
            throws URIException, HttpMalformedHeaderException {
        ReportData reportData = new ReportData();
        reportData.setTitle("Test Title");
        reportData.setDescription("Test Description");
        reportData.setIncludeAllConfidences(true);
        reportData.setIncludeAllRisks(true);
        List<PluginPassiveScanner> list = new ArrayList<>();
        PassiveScanJobResultData pscanData = new PassiveScanJobResultData("passiveScan-wait", list);
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

    private static File generateReportWithAlerts(Template template, File f)
            throws IOException, DocumentException {
        ExtensionReports extRep = new ExtensionReports();
        ReportData reportData = getTestReportDataWithAlerts();
        reportData.setSections(template.getSections());
        return extRep.generateReport(reportData, template, f.getAbsolutePath(), false);
    }

    private static String cleanReport(String str) {
        return str.replaceFirst("generated=\".*\"", "generated=\"DATE\"")
                .replaceFirst("@generated\": \".*\"", "@generated\": \"DATE\"")
                .replaceAll("basic-.*/", "dir")
                .replaceAll("[\\n\\r\\t]", "");
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "high-level-report",
                "traditional-json",
                "traditional-json-plus",
                "traditional-md",
                "traditional-xml",
                "traditional-xml-plus",
                "traditional-html",
                "traditional-html-plus"
            })
    void shouldGenerateExpectedReport(String templateName) throws Exception {
        // Given
        Constant.messages = new I18N(Locale.ENGLISH);
        Template template = getTemplateFromYamlFile(templateName);
        String fileName = "basic-" + templateName;
        File f = File.createTempFile(fileName, template.getExtension());

        // If the test fails because of valid changes then uncomment the next line and copy the
        // generated file to the right file in src/test/resources
        // System.out.println(f.getAbsolutePath());

        // When
        File r = generateReportWithAlerts(template, f);
        String report = new String(Files.readAllBytes(r.toPath()));

        File expectedReport =
                new File(
                        "src/test/resources/org/zaproxy/addon/reports/resources/"
                                + fileName
                                + "."
                                + template.getExtension());
        String expected = new String(Files.readAllBytes(expectedReport.toPath()));

        // Then
        assertThat(cleanReport(report), is(equalTo(cleanReport(expected))));
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
        Template template = getTemplateFromYamlFile("traditional-json");
        String fileName = "basic-traditional-json";
        File f = File.createTempFile(fileName, template.getExtension());

        // When
        File r = generateReportWithAlerts(template, f);
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
    void shouldGenerateValidJsonPlusReport() throws Exception {
        // Given
        Template template = getTemplateFromYamlFile("traditional-json-plus");
        String fileName = "basic-traditional-json-plus";
        File f = File.createTempFile(fileName, template.getExtension());

        // When
        File r = generateReportWithAlerts(template, f);
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
        int alertItemCount = isXmlPlus ? 37 : 35;
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
        int instanceItemCount = isXmlPlus ? 21 : 13;
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
        Template template = getTemplateFromYamlFile("traditional-xml");
        String fileName = "basic-traditional-xml";
        File f = File.createTempFile(fileName, template.getExtension());
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        DocumentBuilder db = dbf.newDocumentBuilder();

        // When
        File r = generateReportWithAlerts(template, f);
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
        Template template = getTemplateFromYamlFile("traditional-xml-plus");
        String fileName = "basic-traditional-xml-plus";
        File f = File.createTempFile(fileName, template.getExtension());
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        DocumentBuilder db = dbf.newDocumentBuilder();

        // When
        File r = generateReportWithAlerts(template, f);
        Document doc = db.parse(r);
        Element root = doc.getDocumentElement();

        // Then
        checkXmlAlert(doc, true);
        assertThat(root.getNodeName(), is(equalTo("OWASPZAPReport")));
        assertThat(root.getAttribute("version"), is(equalTo("Dev Build")));
        assertThat(root.getAttribute("generated").length(), is(greaterThan(20)));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "modern",
                "high-level-report",
                "risk-confidence-html",
                "traditional-html",
                "traditional-html-plus",
                "traditional-json",
                "traditional-json-plus",
                "traditional-md",
                "traditional-pdf",
                "traditional-xml",
                "traditional-xml-plus"
            })
    void shouldGenerateReportsWithoutWarnings(String reportName) throws Exception {
        // Given
        ExtensionReports extRep = new ExtensionReports();
        ReportData reportData = setupReportData();
        File f = File.createTempFile("zap.reports.test", "x");
        Template template = getTemplateFromYamlFile(reportName);
        // When
        reportData.setSections(template.getSections());
        File r = extRep.generateReport(reportData, template, f.getAbsolutePath(), false);
        String report = new String(Files.readAllBytes(r.toPath()));
        // Then
        assertThat(report.length(), greaterThan(0));
        assertThat(logEvents, not(hasItem(startsWith("WARN"))));
        assertThat(logEvents, not(hasItem(startsWith("ERROR"))));
    }

    private static ReportData setupReportData() {
        ReportData reportData = getTestReportData();
        AlertNode root = new AlertNode(0, "Alerts");
        root.add(newAlertNode(1, Alert.RISK_HIGH, "Alert High 1", "https://www.example.com", 1));
        root.add(newAlertNode(2, Alert.RISK_LOW, "Alert Low 1", "https://www.example.com", 3));
        root.add(
                newAlertNode(
                        2,
                        ExtensionReports.RISK_FALSE_POSITIVE,
                        "Alert Low 2",
                        "https://www.example.com",
                        8));
        // Cover cases where the HTTP message is missing.
        AlertNode noMsgAlertNode =
                newAlertNode(
                        4, Alert.RISK_HIGH, "Alert No HTTP Message", "https://www.example.com", 2);
        noMsgAlertNode.getUserObject().setMessage(null);
        noMsgAlertNode.getChildAt(0).getUserObject().setMessage(null);
        root.add(noMsgAlertNode);

        reportData.setAlertTreeRootNode(root);
        String site1 = "https://www.example.com";
        reportData.setSites(List.of(site1 + NOT_ILLEGAL_XML_CHRS));
        reportData.setIncludeAllConfidences(true);
        reportData.setIncludeAllRisks(true);
        reportData.setDescription("desc" + ILLEGAL_XML_CHRS);
        reportData.setContexts(new ArrayList<>());
        return reportData;
    }

    private static void generateTestFile(String templateName) throws Exception {

        Template template = getTemplateFromYamlFile(templateName);
        generateReportWithAlerts(
                template,
                new File(
                        "src/test/resources/org/zaproxy/addon/reports/resources/basic-"
                                + templateName
                                + "."
                                + template.getExtension()));
    }

    /**
     * This can be used to either regenerate the test files when they are expected to have changed
     * so that they can be checked in or to make it easier to see the differences if the tests fail.
     *
     * @param args not used
     */
    public static void main(String[] args) {
        try {
            Constant.messages = new I18N(Locale.ENGLISH);

            Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
            Model.setSingletonForTesting(model);
            ExtensionLoader extensionLoader =
                    mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
            Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
            Model.getSingleton().getOptionsParam().load(new ZapXmlConfiguration());

            generateTestFile("high-level-report");
            generateTestFile("traditional-json");
            generateTestFile("traditional-md");
            generateTestFile("traditional-xml");
            generateTestFile("traditional-html");
            generateTestFile("traditional-html-plus");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static Template getTemplateFromYamlFile(String templateName) throws Exception {
        return new Template(
                TestUtils.getResourcePath(
                                ExtensionReports.class,
                                "/reports/" + templateName + "/template.yaml")
                        .toFile());
    }

    private static List<String> registerLogEvents() {
        List<String> logEvents = new ArrayList<>();
        TestLogAppender logAppender = new TestLogAppender("%p %m%n", logEvents::add);
        LoggerContext context = LoggerContext.getContext();
        LoggerConfig rootLoggerconfig = context.getConfiguration().getRootLogger();
        rootLoggerconfig.getAppenders().values().forEach(context.getRootLogger()::removeAppender);
        rootLoggerconfig.addAppender(logAppender, null, null);
        rootLoggerconfig.setLevel(Level.ALL);
        context.updateLoggers();
        return logEvents;
    }

    static class TestLogAppender extends AbstractAppender {

        private static final Property[] NO_PROPERTIES = {};

        private final Consumer<String> logConsumer;

        public TestLogAppender(Consumer<String> logConsumer) {
            this("%m%n", logConsumer);
        }

        public TestLogAppender(String pattern, Consumer<String> logConsumer) {
            super(
                    "TestLogAppender",
                    null,
                    PatternLayout.newBuilder()
                            .withDisableAnsi(true)
                            .withCharset(StandardCharsets.UTF_8)
                            .withPattern(pattern)
                            .build(),
                    true,
                    NO_PROPERTIES);
            this.logConsumer = logConsumer;
            start();
        }

        @Override
        public void append(LogEvent event) {
            logConsumer.accept(((StringLayout) getLayout()).toSerializable(event));
        }
    }
}
