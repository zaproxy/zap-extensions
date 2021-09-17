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
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import com.lowagie.text.DocumentException;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
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

class ExtensionReportsUnitTest {

    private static final String HTML_REPORT_ALERT_SUMMARY_SECTION = "alertcount";
    private static final String HTML_REPORT_INSTANCE_SUMMARY_SECTION = "instancecount";
    private static final String HTML_REPORT_ALERT_DETAIL_SECTION = "alertdetails";
    private static final String HTML_REPORT_PASSING_RULES_SECTION = "passingrules";

    private static final String HTML_REPORT_ALERT_SUMMARY_SECTION_TITLE =
            "!reports.report.alerts.summary!";
    private static final String HTML_REPORT_INSTANCE_SUMMARY_SECTION_TITLE =
            "!reports.report.alerts.list!";
    private static final String HTML_REPORT_ALERT_DETAILS_SECTION_TITLE =
            "!reports.report.alerts.detail!";
    // The Passing rules section is defined in the report specific i18n file
    private static final String HTML_REPORT_PASSING_RULES_SECTION_TITLE = "Passing Rules";

    @BeforeEach
    void setUp() throws Exception {
        Constant.messages = new I18N(Locale.ENGLISH);

        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
        ExtensionLoader extensionLoader = mock(ExtensionLoader.class, withSettings().lenient());
        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
        Model.getSingleton().getOptionsParam().load(new ZapXmlConfiguration());

        Constant.PROGRAM_VERSION = "Dev Build";
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

    private AlertNode newAlertNode(
            int pluginId, int level, String name, String uri, int childCount) {
        Alert alert = new Alert(pluginId);
        alert.setUri(uri);
        AlertNode alertNode = new AlertNode(level, name);
        alertNode.setUserObject(alert);
        for (int i = 0; i < childCount; i++) {
            AlertNode childNode = new AlertNode(level, name);
            childNode.setUserObject(new Alert(pluginId));
            alertNode.add(childNode);
        }
        return alertNode;
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

    private ReportData getTestReportData() {
        ReportData reportData = new ReportData();
        AlertNode root = new AlertNode(0, "Test");
        reportData.setAlertTreeRootNode(root);
        reportData.setSites(Arrays.asList("http://example.com"));
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
        assertThat(report.contains(HTML_REPORT_INSTANCE_SUMMARY_SECTION_TITLE), is(false));
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

    private static AlertNode getAlertNode(String name, String desc, int risk, int confidence)
            throws URIException, HttpMalformedHeaderException {
        AlertNode node = new AlertNode(risk, name);
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
                "Test 'Other\\",
                "Test Solution",
                "Test Reference",
                "Test <p>Evidence",
                123,
                456,
                msg);
        node.setUserObject(alert);

        AlertNode instance = new AlertNode(0, name);
        instance.setUserObject(alert);

        node.add(instance);

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
        reportData.setSites(Arrays.asList("http://example.com"));
        return reportData;
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
                "traditional-json",
                "traditional-md",
                "traditional-xml",
                "traditional-html",
                "traditional-html-plus"
            })
    void shouldGenerateExpectedReport(String templateName) throws Exception {
        // Given
        Template template = getTemplateFromYamlFile(templateName);
        String fileName = "basic-" + templateName;
        File f = File.createTempFile(fileName, template.getExtension());

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
        assertThat(site.getJSONObject(0).getString("@name"), is(equalTo("http://example.com")));
        assertThat(site.getJSONObject(0).getString("@host"), is(equalTo("example.com")));
        assertThat(site.getJSONObject(0).getString("@port"), is(equalTo("80")));
        assertThat(site.getJSONObject(0).getString("@ssl"), is(equalTo("false")));

        JSONArray alerts = site.getJSONObject(0).getJSONArray("alerts");
        assertThat(alerts.size(), is(equalTo(1)));
        assertThat(alerts.getJSONObject(0).getString("pluginid"), is(equalTo("1")));
        assertThat(alerts.getJSONObject(0).getString("alertRef"), is(equalTo("1")));
        assertThat(alerts.getJSONObject(0).getString("alert"), is(equalTo("XSS")));
        assertThat(alerts.getJSONObject(0).getString("name"), is(equalTo("XSS")));
        assertThat(alerts.getJSONObject(0).getString("riskcode"), is(equalTo("3")));
        assertThat(alerts.getJSONObject(0).getString("confidence"), is(equalTo("2")));
        assertThat(
                alerts.getJSONObject(0).getString("riskdesc"),
                is(equalTo("!reports.report.risk.3! (!reports.report.confidence.2!)")));
        assertThat(
                alerts.getJSONObject(0).getString("desc"), is(equalTo("<p>XSS Description</p>")));
        assertThat(alerts.getJSONObject(0).getString("count"), is(equalTo("1")));

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
        assertThat(instances.size(), is(equalTo(1)));
        assertThat(
                instances.getJSONObject(0).getString("uri"),
                is(equalTo("http://example.com/example_3")));
        assertThat(instances.getJSONObject(0).getString("method"), is(equalTo("GET")));
        assertThat(instances.getJSONObject(0).getString("param"), is(equalTo("Test Param")));
        assertThat(
                instances.getJSONObject(0).getString("attack"), is(equalTo("Test \"Attack\\\"")));
        assertThat(
                instances.getJSONObject(0).getString("evidence"), is(equalTo("Test <p>Evidence")));
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
        NodeList sites = doc.getElementsByTagName("site");
        NodeList alerts = doc.getElementsByTagName("alerts");
        NodeList alertItems = doc.getElementsByTagName("alertitem");

        // Then
        assertThat(root.getNodeName(), is(equalTo("OWASPZAPReport")));
        assertThat(root.getAttribute("version"), is(equalTo("Dev Build")));
        assertThat(root.getAttribute("generated").length(), is(greaterThan(20)));
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
        assertThat(alertItemNodes.getLength(), is(equalTo(35)));

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
        assertThat(
                alertItemNodes.item(i).getTextContent(),
                is(equalTo("!reports.report.risk.3! (!reports.report.confidence.2!)")));
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("#text"))); // Filler
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("confidencedesc")));
        assertThat(
                alertItemNodes.item(i).getTextContent(),
                is(equalTo("!reports.report.confidence.2!")));
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("#text"))); // Filler
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("desc")));
        assertThat(alertItemNodes.item(i).getTextContent(), is(equalTo("<p>XSS Description</p>")));
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("#text"))); // Filler
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("instances")));
        NodeList instancesChildNodes = alertItemNodes.item(i).getChildNodes();
        assertThat(instancesChildNodes.getLength(), is(equalTo(3)));
        assertThat(instancesChildNodes.item(0).getNodeName(), is(equalTo("#text"))); // Filler
        assertThat(instancesChildNodes.item(1).getNodeName(), is(equalTo("instance"))); // Filler
        assertThat(instancesChildNodes.item(2).getNodeName(), is(equalTo("#text"))); // Filler
        NodeList instanceChildNodes = instancesChildNodes.item(1).getChildNodes();

        // Check the instance details
        assertThat(instanceChildNodes.getLength(), is(equalTo(11)));
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

        // And back to the alertitem nodes
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("#text"))); // Filler
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("count")));
        assertThat(alertItemNodes.item(i).getTextContent(), is(equalTo("1")));
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("#text"))); // Filler
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("solution")));
        assertThat(alertItemNodes.item(i).getTextContent(), is(equalTo("<p>Test Solution</p>")));
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("#text"))); // Filler
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("otherinfo")));
        assertThat(alertItemNodes.item(i).getTextContent(), is(equalTo("<p>Test 'Other\\</p>")));
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("#text"))); // Filler
        i++;
        assertThat(alertItemNodes.item(i).getNodeName(), is(equalTo("reference")));
        assertThat(alertItemNodes.item(i).getTextContent(), is(equalTo("<p>Test Reference</p>")));
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
            ExtensionLoader extensionLoader = mock(ExtensionLoader.class, withSettings().lenient());
            Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
            Model.getSingleton().getOptionsParam().load(new ZapXmlConfiguration());

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
}
