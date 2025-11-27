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

import java.io.File;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Consumer;
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
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.extension.alert.AlertNode;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.I18N;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class ExtensionReportsUnitTest extends TestUtils {

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
        root.add(
                ReportTestUtils.newAlertNode(
                        1, Alert.RISK_HIGH, "Alert High 1", "https://www.example.com", 1));
        root.add(
                ReportTestUtils.newAlertNode(
                        2, Alert.RISK_MEDIUM, "Alert Medium 1", "https://www.example.com", 2));
        root.add(
                ReportTestUtils.newAlertNode(
                        3, Alert.RISK_LOW, "Alert Low 1", "https://www.example.com", 4));
        root.add(
                ReportTestUtils.newAlertNode(
                        4, Alert.RISK_LOW, "Alert Low 2", "https://www.example.com", 8));

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
        root.add(
                ReportTestUtils.newAlertNode(
                        1, Alert.RISK_HIGH, "Alert High 1", "https://www.example.com", 1));
        root.add(
                ReportTestUtils.newAlertNode(
                        1, Alert.RISK_MEDIUM, "Alert Medium 1", "https://www.example.com", 2));
        root.add(
                ReportTestUtils.newAlertNode(
                        2, Alert.RISK_LOW, "Alert Low 1", "https://www.example.com", 4));
        root.add(
                ReportTestUtils.newAlertNode(
                        2, Alert.RISK_LOW, "Alert Low 2", "https://www.example.com", 8));

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
        root.add(
                ReportTestUtils.newAlertNode(
                        1, Alert.RISK_HIGH, "Alert High 1", "https://www.example.com", 1));
        root.add(
                ReportTestUtils.newAlertNode(
                        1,
                        ExtensionReports.RISK_FALSE_POSITIVE,
                        "Alert Medium 1",
                        "https://www.example.com",
                        2));
        root.add(
                ReportTestUtils.newAlertNode(
                        2, Alert.RISK_LOW, "Alert Low 1", "https://www.example.com", 4));
        root.add(
                ReportTestUtils.newAlertNode(
                        2,
                        ExtensionReports.RISK_FALSE_POSITIVE,
                        "Alert Low 2",
                        "https://www.example.com",
                        8));
        root.add(
                ReportTestUtils.newAlertNode(
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

    @Test
    void shouldReturnAllMessages() {
        // Given
        ExtensionReports extRep = new ExtensionReports();
        AlertNode root = new AlertNode(0, "Alerts");
        root.add(
                ReportTestUtils.newAlertNode(
                        1, Alert.RISK_HIGH, "Alert High 1", "https://www.example.com", 1));
        root.add(
                ReportTestUtils.newAlertNode(
                        2, Alert.RISK_MEDIUM, "Alert Medium 1", "https://www.example.com", 2));
        root.add(
                ReportTestUtils.newAlertNode(
                        3, Alert.RISK_LOW, "Alert Low 1", "https://www.example.com", 4));
        root.add(
                ReportTestUtils.newAlertNode(
                        4, Alert.RISK_LOW, "Alert Low 2", "https://www.example.com", 8));

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
        root.add(
                ReportTestUtils.newAlertNode(
                        1, Alert.RISK_HIGH, "Alert High 1", "https://www.example.com", 1));
        root.add(
                ReportTestUtils.newAlertNode(
                        2, Alert.RISK_MEDIUM, "Alert Medium 1", "https://www.example.com", 2));
        root.add(
                ReportTestUtils.newAlertNode(
                        3, Alert.RISK_LOW, "Alert Low 1", "https://www.example.com", 4));
        root.add(
                ReportTestUtils.newAlertNode(
                        4, Alert.RISK_LOW, "Alert Low 2", "https://www.example.com", 8));

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
        root.add(
                ReportTestUtils.newAlertNode(
                        1, Alert.RISK_HIGH, "Alert High 1", "https://www.example.com", 1));
        root.add(
                ReportTestUtils.newAlertNode(
                        2, Alert.RISK_LOW, "Alert Low 1", "https://www.example.com", 3));
        root.add(
                ReportTestUtils.newAlertNode(
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
        ReportData reportData = ReportTestUtils.getTestReportData();
        File f = File.createTempFile("zap.reports.test", "x");
        Template template = ReportTestUtils.getTemplateFromYamlFile(reportName);

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
        ReportData reportData = ReportTestUtils.getTestReportData();
        File f = File.createTempFile("zap.reports.test", "x");
        Template template = ReportTestUtils.getTemplateFromYamlFile(reportName);

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
        ReportData reportData = ReportTestUtils.getTestReportData();
        File f = File.createTempFile("zap.reports.test", "x");
        Template template = ReportTestUtils.getTemplateFromYamlFile(reportName);

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
        ReportData reportData = ReportTestUtils.getTestReportData();
        File f = File.createTempFile("zap.reports.test", "x");
        Template template = ReportTestUtils.getTemplateFromYamlFile(reportName);

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
        ReportData reportData = ReportTestUtils.getTestReportData();
        File f = File.createTempFile("zap.reports.test", "x");
        Template template = ReportTestUtils.getTemplateFromYamlFile(reportName);

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
    @SuppressWarnings("removal")
    void shouldIncludePassingRulesSectionInReport(String reportName) throws Exception {
        // Given
        ExtensionReports extRep = new ExtensionReports();
        ReportData reportData = ReportTestUtils.getTestReportData();
        var pscanData =
                new org.zaproxy.addon.automation.jobs.PassiveScanJobResultData(
                        "test", new ArrayList<>());
        reportData.addReportObjects(pscanData.getKey(), pscanData);
        File f = File.createTempFile("zap.reports.test", "x");
        Template template = ReportTestUtils.getTemplateFromYamlFile(reportName);

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

    private static String cleanReport(String str) {
        return str.replaceFirst("generated=\".*\"", "generated=\"DATE\"")
                .replaceFirst("@generated\": \".*\"", "@generated\": \"DATE\"")
                .replaceFirst("created\": \".*\"", "created\": \"DATE\"")
                .replaceAll("basic-.*/", "dir")
                .replaceAll("[\\n\\r\\t ]+", " ");
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
        Template template = ReportTestUtils.getTemplateFromYamlFile(templateName);
        String fileName = "basic-" + templateName;
        File f = File.createTempFile(fileName, "." + template.getExtension());

        // If the test fails because of valid changes then uncomment the next line and copy the
        // generated file to the right file in src/test/resources
        /*
        System.out.println(
                "cp "
                        + f.getAbsolutePath()
                        + " addOns/reports/src/test/resources/org/zaproxy/addon/reports/resources/"
                        + fileName
                        + "."
                        + template.getExtension());
                        */

        // When
        File r = ReportTestUtils.generateReportWithAlerts(template, f);
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
        Template template = ReportTestUtils.getTemplateFromYamlFile(reportName);
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
        ReportData reportData = ReportTestUtils.getTestReportData();
        AlertNode root = new AlertNode(0, "Alerts");
        root.add(
                ReportTestUtils.newAlertNode(
                        1, Alert.RISK_HIGH, "Alert High 1", "https://www.example.com", 1));
        root.add(
                ReportTestUtils.newAlertNode(
                        2, Alert.RISK_LOW, "Alert Low 1", "https://www.example.com", 3));
        root.add(
                ReportTestUtils.newAlertNode(
                        2,
                        ExtensionReports.RISK_FALSE_POSITIVE,
                        "Alert Low 2",
                        "https://www.example.com",
                        8));
        // Cover cases where the HTTP message is missing.
        AlertNode noMsgAlertNode =
                ReportTestUtils.newAlertNode(
                        4, Alert.RISK_HIGH, "Alert No HTTP Message", "https://www.example.com", 2);
        noMsgAlertNode.getUserObject().setMessage(null);
        noMsgAlertNode.getChildAt(0).getUserObject().setMessage(null);
        root.add(noMsgAlertNode);

        reportData.setAlertTreeRootNode(root);
        String site1 = "https://www.example.com";
        reportData.setSites(List.of(site1 + ReportTestUtils.NOT_ILLEGAL_XML_CHRS));
        reportData.setIncludeAllConfidences(true);
        reportData.setIncludeAllRisks(true);
        reportData.setDescription("desc" + ReportTestUtils.ILLEGAL_XML_CHRS);
        reportData.setContexts(new ArrayList<>());
        return reportData;
    }

    private static void generateTestFile(String templateName) throws Exception {

        Template template = ReportTestUtils.getTemplateFromYamlFile(templateName);
        ReportTestUtils.generateReportWithAlerts(
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
            generateTestFile("traditional-json-plus");
            generateTestFile("traditional-md");
            generateTestFile("traditional-xml");
            generateTestFile("traditional-xml-plus");
            generateTestFile("traditional-html");
            generateTestFile("traditional-html-plus");

        } catch (Exception e) {
            e.printStackTrace();
        }
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
