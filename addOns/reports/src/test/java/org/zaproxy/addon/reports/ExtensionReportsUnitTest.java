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
import javax.xml.parsers.ParserConfigurationException;
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
import org.xml.sax.SAXException;
import org.zaproxy.addon.automation.jobs.PassiveScanJobResultData;
import org.zaproxy.zap.extension.alert.AlertNode;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.model.Context;
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
    }

    @Test
    void shouldExtractExpectedParams() {
        // Given
        String pattern = ReportParam.DEFAULT_NAME_PATTERN;
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");

        // When
        String dateStr = sdf.format(new Date());
        String name = ExtensionReports.getNameFromPattern(pattern, "https://www.example.com");

        // Then
        assertThat(name, is(equalTo(dateStr + "-ZAP-Report-www.example.com")));
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
    void shouldGenerateReport(String reportName) throws IOException, DocumentException {
        // Given
        ExtensionReports extRep = new ExtensionReports();
        ReportData reportData = getTestReportData();
        File f = File.createTempFile("zap.reports.test", "x");
        File t = new File("src/main/zapHomeFiles/reports/" + reportName + "/template.yaml");
        Template template = new Template(t);

        // When
        File r = extRep.generateReport(reportData, template, f.getAbsolutePath(), false);

        // Then
        assertThat(r.length(), greaterThan(0L));
    }

    @ParameterizedTest
    @ValueSource(strings = {"traditional-html", "traditional-html-plus", "traditional-md"})
    void shouldIncludeAllSectionsInReport(String reportName) throws IOException, DocumentException {
        // Given
        ExtensionReports extRep = new ExtensionReports();
        ReportData reportData = getTestReportData();
        File f = File.createTempFile("zap.reports.test", "x");
        File t = new File("src/main/zapHomeFiles/reports/" + reportName + "/template.yaml");
        Template template = new Template(t);

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
    void shouldIncludeAlertSummarySectionInReport(String reportName)
            throws IOException, DocumentException {
        // Given
        ExtensionReports extRep = new ExtensionReports();
        ReportData reportData = getTestReportData();
        File f = File.createTempFile("zap.reports.test", "x");
        File t = new File("src/main/zapHomeFiles/reports/" + reportName + "/template.yaml");
        Template template = new Template(t);

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
    void shouldIncludeInstanceSummarySectionInReport(String reportName)
            throws IOException, DocumentException {
        // Given
        ExtensionReports extRep = new ExtensionReports();
        ReportData reportData = getTestReportData();
        File f = File.createTempFile("zap.reports.test", "x");
        File t = new File("src/main/zapHomeFiles/reports/" + reportName + "/template.yaml");
        Template template = new Template(t);

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
    void shouldIncludeAlertDetailsSectionInReport(String reportName)
            throws IOException, DocumentException {
        // Given
        ExtensionReports extRep = new ExtensionReports();
        ReportData reportData = getTestReportData();
        File f = File.createTempFile("zap.reports.test", "x");
        File t = new File("src/main/zapHomeFiles/reports/" + reportName + "/template.yaml");
        Template template = new Template(t);

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
    void shouldIncludePassingRulesSectionInReport(String reportName)
            throws IOException, DocumentException {
        // Given
        ExtensionReports extRep = new ExtensionReports();
        ReportData reportData = getTestReportData();
        PassiveScanJobResultData pscanData =
                new PassiveScanJobResultData("test", new ArrayList<PluginPassiveScanner>());
        reportData.addReportObjects(pscanData.getKey(), pscanData);
        File f = File.createTempFile("zap.reports.test", "x");
        File t = new File("src/main/zapHomeFiles/reports/" + reportName + "/template.yaml");
        Template template = new Template(t);

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
                "Test Attack",
                "Test Other",
                "Test Solution",
                "Test Reference",
                "Test Evidence",
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
        List<PluginPassiveScanner> list = new ArrayList<PluginPassiveScanner>();
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
                .replaceAll("basic-.*/", "dir")
                .replaceAll("[\\n\\r\\t]", "");
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "traditional-md",
                "traditional-xml",
                "traditional-html",
                "traditional-html-plus"
            })
    void shouldGenerateExpectedReport(String templateName)
            throws IOException, DocumentException, SAXException, ParserConfigurationException {
        // Given
        File t = new File("src/main/zapHomeFiles/reports/" + templateName + "/template.yaml");
        Template template = new Template(t);
        String fileName = "basic-" + templateName;
        File f = File.createTempFile(fileName, template.getExtension());

        // When
        File r = generateReportWithAlerts(template, f);
        String report = new String(Files.readAllBytes(r.toPath()));

        File expectedReport =
                new File(
                        "src/test/resources/org/zaproxy/addon/automation/resources/"
                                + fileName
                                + "."
                                + template.getExtension());
        String expected = new String(Files.readAllBytes(expectedReport.toPath()));

        // Then
        assertThat(cleanReport(report), is(equalTo(cleanReport(expected))));
    }

    private static void generateTestFile(String templateName)
            throws IOException, DocumentException {

        Template template =
                new Template(
                        new File(
                                "src/main/zapHomeFiles/reports/"
                                        + templateName
                                        + "/template.yaml"));
        generateReportWithAlerts(
                template,
                new File(
                        "src/test/resources/org/zaproxy/addon/automation/resources/basic-"
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

            generateTestFile("traditional-md");
            generateTestFile("traditional-xml");
            generateTestFile("traditional-html");
            generateTestFile("traditional-html-plus");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
