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
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collections;
import java.util.Locale;
import net.sf.json.JSONObject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.utils.I18N;

class ReportApiUnitTest {

    private ExtensionReports extReports;
    private ReportApi reportApi;
    private JSONObject params;
    private Template template;
    private ArgumentCaptor<ReportData> reportDataCaptor;

    @BeforeAll
    static void initModel() {
        Constant.messages = new I18N(Locale.ENGLISH);
        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
    }

    @BeforeEach
    void setUp() throws Exception {
        extReports = mock(ExtensionReports.class);
        reportApi = new ReportApi(extReports);
        params = new JSONObject();
        params.put(ReportApi.PARAM_TITLE, "Default Title");
        params.put(ReportApi.PARAM_TEMPLATE, "traditional-html-plus");
        template = ExtensionReportsUnitTest.getTemplateFromYamlFile("traditional-html-plus");
        when(extReports.getTemplateByConfigName(anyString())).thenReturn(template);
        reportDataCaptor = ArgumentCaptor.forClass(ReportData.class);
    }

    @Test
    void shouldPopulateReportTitle() throws Exception {
        // Given
        String title = "My 31337 Report";
        params.put(ReportApi.PARAM_TITLE, title);

        // When
        reportApi.handleApiAction(ReportApi.ACTION_GENERATE, params);

        // Then
        verify(extReports)
                .generateReport(reportDataCaptor.capture(), any(), anyString(), anyBoolean());
        ReportData reportData = reportDataCaptor.getValue();
        assertThat(reportData.getTitle(), is(title));
    }

    @Test
    void shouldPopulateReportTemplate() throws Exception {
        // Given
        String templateName = "traditional-pdf";
        template = ExtensionReportsUnitTest.getTemplateFromYamlFile(templateName);
        params.put(ReportApi.PARAM_TEMPLATE, templateName);
        ArgumentCaptor<Template> templateCaptor = ArgumentCaptor.forClass(Template.class);
        when(extReports.getTemplateByConfigName(templateName)).thenReturn(template);

        // When
        reportApi.handleApiAction(ReportApi.ACTION_GENERATE, params);

        // Then
        verify(extReports)
                .generateReport(any(), templateCaptor.capture(), anyString(), anyBoolean());
        assertThat(templateCaptor.getValue(), is(template));
    }

    @Test
    void shouldPopulateReportTheme() throws Exception {
        // Given
        String theme = "dark";
        params.put(ReportApi.PARAM_THEME, theme);

        // When
        reportApi.handleApiAction(ReportApi.ACTION_GENERATE, params);

        // Then
        verify(extReports)
                .generateReport(reportDataCaptor.capture(), any(), anyString(), anyBoolean());
        ReportData reportData = reportDataCaptor.getValue();
        assertThat(reportData.getTheme(), is(theme));
    }

    @Test
    void shouldPopulateReportDescription() throws Exception {
        // Given
        String description =
                "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.";
        params.put(ReportApi.PARAM_DESCRIPTION, description);

        // When
        reportApi.handleApiAction(ReportApi.ACTION_GENERATE, params);

        // Then
        verify(extReports)
                .generateReport(reportDataCaptor.capture(), any(), anyString(), anyBoolean());
        ReportData reportData = reportDataCaptor.getValue();
        assertThat(reportData.getDescription(), is(description));
    }

    @Test
    void shouldPopulateReportContexts() throws Exception {
        // Given
        String contexts = "Default Context";
        params.put(ReportApi.PARAM_CONTEXTS, contexts);
        Model testModel = mock(Model.class, RETURNS_DEEP_STUBS);
        Model.setSingletonForTesting(testModel);
        Context context = mock(Context.class);
        when(testModel.getSession().getContext(contexts)).thenReturn(context);

        // When
        reportApi.handleApiAction(ReportApi.ACTION_GENERATE, params);

        // Then
        verify(extReports)
                .generateReport(reportDataCaptor.capture(), any(), anyString(), anyBoolean());
        ReportData reportData = reportDataCaptor.getValue();
        assertThat(reportData.getContexts(), is(Collections.singletonList(context)));
    }

    @Test
    void shouldPopulateReportSites() throws Exception {
        // Given
        String sites = "https://example.org";
        params.put(ReportApi.PARAM_SITES, sites);

        // When
        reportApi.handleApiAction(ReportApi.ACTION_GENERATE, params);

        // Then
        verify(extReports)
                .generateReport(reportDataCaptor.capture(), any(), anyString(), anyBoolean());
        ReportData reportData = reportDataCaptor.getValue();
        assertThat(reportData.getSites(), is(Collections.singletonList(sites)));
    }

    @Test
    void shouldPopulateReportSections() throws Exception {
        // Given
        String sections = "chart";
        params.put(ReportApi.PARAM_SECTIONS, sections);

        // When
        reportApi.handleApiAction(ReportApi.ACTION_GENERATE, params);

        // Then
        verify(extReports)
                .generateReport(reportDataCaptor.capture(), any(), anyString(), anyBoolean());
        ReportData reportData = reportDataCaptor.getValue();
        assertThat(reportData.getSections(), is(Collections.singletonList(sections)));
    }

    @Test
    void shouldPopulateReportConfidences() throws Exception {
        // Given
        String confidences = "high";
        params.put(ReportApi.PARAM_INC_CONFIDENCES, confidences);

        // When
        reportApi.handleApiAction(ReportApi.ACTION_GENERATE, params);

        // Then
        verify(extReports)
                .generateReport(reportDataCaptor.capture(), any(), anyString(), anyBoolean());
        ReportData reportData = reportDataCaptor.getValue();
        assertThat(reportData.isIncludeConfidence(Alert.CONFIDENCE_FALSE_POSITIVE), is(false));
        assertThat(reportData.isIncludeConfidence(Alert.CONFIDENCE_LOW), is(false));
        assertThat(reportData.isIncludeConfidence(Alert.CONFIDENCE_MEDIUM), is(false));
        assertThat(reportData.isIncludeConfidence(Alert.CONFIDENCE_HIGH), is(true));
        assertThat(reportData.isIncludeConfidence(Alert.CONFIDENCE_USER_CONFIRMED), is(false));
    }

    @Test
    void shouldPopulateReportRisks() throws Exception {
        // Given
        String risks = "high";
        params.put(ReportApi.PARAM_INC_RISKS, risks);

        // When
        reportApi.handleApiAction(ReportApi.ACTION_GENERATE, params);

        // Then
        verify(extReports)
                .generateReport(reportDataCaptor.capture(), any(), anyString(), anyBoolean());
        ReportData reportData = reportDataCaptor.getValue();
        assertThat(reportData.isIncludeRisk(Alert.RISK_INFO), is(false));
        assertThat(reportData.isIncludeRisk(Alert.RISK_LOW), is(false));
        assertThat(reportData.isIncludeRisk(Alert.RISK_MEDIUM), is(false));
        assertThat(reportData.isIncludeRisk(Alert.RISK_HIGH), is(true));
    }

    @Test
    void shouldPopulateReportFileName() throws Exception {
        // Given
        String reportDirectory = "src/main/zapHomeFiles";
        String reportFileName = "my31337Report";
        params.put(ReportApi.PARAM_REPORT_FILE_NAME, reportFileName);
        params.put(ReportApi.PARAM_REPORT_DIRECTORY, reportDirectory);
        ArgumentCaptor<String> reportFilePathCaptor = ArgumentCaptor.forClass(String.class);

        // When
        reportApi.handleApiAction(ReportApi.ACTION_GENERATE, params);

        // Then
        verify(extReports)
                .generateReport(any(), any(), reportFilePathCaptor.capture(), anyBoolean());
        String expectedReportFilePath =
                Paths.get(reportDirectory, reportFileName + '.' + template.getExtension())
                        .toString();
        assertThat(reportFilePathCaptor.getValue(), is(expectedReportFilePath));
    }

    @Test
    void shouldPopulateReportFileNamePattern() throws Exception {
        // Given
        String reportDirectory = "src/main/zapHomeFiles";
        String reportFileNamePattern = "my31337Report";
        params.put(ReportApi.PARAM_REPORT_FILE_NAME_PATTERN, reportFileNamePattern);
        params.put(ReportApi.PARAM_REPORT_DIRECTORY, reportDirectory);
        ArgumentCaptor<String> reportFilePathCaptor = ArgumentCaptor.forClass(String.class);

        // When
        reportApi.handleApiAction(ReportApi.ACTION_GENERATE, params);

        // Then
        verify(extReports)
                .generateReport(any(), any(), reportFilePathCaptor.capture(), anyBoolean());
        String expectedReportFilePath =
                Paths.get(reportDirectory, reportFileNamePattern + '.' + template.getExtension())
                        .toString();
        assertThat(reportFilePathCaptor.getValue(), is(expectedReportFilePath));
    }

    @Test
    void shouldPopulateReportDisplay() throws Exception {
        // Given
        boolean display = true;
        params.put(ReportApi.PARAM_DISPLAY, display);
        ArgumentCaptor<Boolean> displayCaptor = ArgumentCaptor.forClass(boolean.class);

        // When
        reportApi.handleApiAction(ReportApi.ACTION_GENERATE, params);

        // Then
        verify(extReports).generateReport(any(), any(), anyString(), displayCaptor.capture());
        assertThat(displayCaptor.getValue(), is(display));
    }

    @Test
    void shouldPopulateOptionalParamsWithDefaultValues() throws Exception {
        // Given
        ArgumentCaptor<String> reportFilePathCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Boolean> displayCaptor = ArgumentCaptor.forClass(boolean.class);
        String expectedReportFilePath =
                Paths.get(
                                System.getProperty("user.home"),
                                ExtensionReports.getNameFromPattern(
                                        ReportParam.DEFAULT_NAME_PATTERN, ".html"))
                        .toString();

        // When
        reportApi.handleApiAction(ReportApi.ACTION_GENERATE, params);

        // Then
        verify(extReports)
                .generateReport(
                        reportDataCaptor.capture(),
                        any(),
                        reportFilePathCaptor.capture(),
                        displayCaptor.capture());
        ReportData reportData = reportDataCaptor.getValue();
        assertAll(
                () -> assertThat(reportData.getDescription(), is("")),
                () -> assertThat(reportData.getContexts().size(), is(0)),
                () -> assertThat(reportData.getSites().size(), is(0)),
                () -> assertThat(reportData.getSections(), is(template.getSections())),
                () ->
                        assertThat(
                                reportData.isIncludeConfidence(Alert.CONFIDENCE_FALSE_POSITIVE),
                                is(true)),
                () -> assertThat(reportData.isIncludeConfidence(Alert.CONFIDENCE_LOW), is(true)),
                () -> assertThat(reportData.isIncludeConfidence(Alert.CONFIDENCE_MEDIUM), is(true)),
                () -> assertThat(reportData.isIncludeConfidence(Alert.CONFIDENCE_HIGH), is(true)),
                () ->
                        assertThat(
                                reportData.isIncludeConfidence(Alert.CONFIDENCE_USER_CONFIRMED),
                                is(true)),
                () -> assertThat(reportData.isIncludeRisk(Alert.RISK_INFO), is(true)),
                () -> assertThat(reportData.isIncludeRisk(Alert.RISK_LOW), is(true)),
                () -> assertThat(reportData.isIncludeRisk(Alert.RISK_MEDIUM), is(true)),
                () -> assertThat(reportData.isIncludeRisk(Alert.RISK_HIGH), is(true)),
                () -> assertThat(reportFilePathCaptor.getValue(), is(expectedReportFilePath)),
                () -> assertThat(displayCaptor.getValue(), is(false)));
    }

    @Test
    void shouldPopulateReportContextsWithDelimiter() throws Exception {
        // Given
        String contextOneName = "Context One";
        String contextTwoName = "Context Two";
        String contexts = contextOneName + '|' + contextTwoName;
        params.put(ReportApi.PARAM_CONTEXTS, contexts);
        Model testModel = mock(Model.class, RETURNS_DEEP_STUBS);
        Model.setSingletonForTesting(testModel);
        Context contextOne = mock(Context.class);
        Context contextTwo = mock(Context.class);
        when(testModel.getSession().getContext(contextOneName)).thenReturn(contextOne);
        when(testModel.getSession().getContext(contextTwoName)).thenReturn(contextTwo);

        // When
        reportApi.handleApiAction(ReportApi.ACTION_GENERATE, params);

        // Then
        verify(extReports)
                .generateReport(reportDataCaptor.capture(), any(), anyString(), anyBoolean());
        ReportData reportData = reportDataCaptor.getValue();
        assertThat(reportData.getContexts(), is(Arrays.asList(contextOne, contextTwo)));
    }

    @Test
    void shouldPopulateReportSitesWithDelimiter() throws Exception {
        // Given
        String siteOne = "https://example.org";
        String siteTwo = "https://example.com";
        String sites = siteOne + '|' + siteTwo;
        params.put(ReportApi.PARAM_SITES, sites);

        // When
        reportApi.handleApiAction(ReportApi.ACTION_GENERATE, params);

        // Then
        verify(extReports)
                .generateReport(reportDataCaptor.capture(), any(), anyString(), anyBoolean());
        ReportData reportData = reportDataCaptor.getValue();
        assertThat(reportData.getSites(), is(Arrays.asList(siteOne, siteTwo)));
    }

    @Test
    void shouldPopulateReportSectionsWithDelimiter() throws Exception {
        // Given
        String sections = "chart| alertdetails";
        params.put(ReportApi.PARAM_SECTIONS, sections);

        // When
        reportApi.handleApiAction(ReportApi.ACTION_GENERATE, params);

        // Then
        verify(extReports)
                .generateReport(reportDataCaptor.capture(), any(), anyString(), anyBoolean());
        ReportData reportData = reportDataCaptor.getValue();
        assertThat(reportData.getSections(), is(Arrays.asList("chart", "alertdetails")));
    }

    @Test
    void shouldErrorOnInvalidSections() throws Exception {
        // Given
        String sections = "chart|alertdetails|badone";
        params.put(ReportApi.PARAM_SECTIONS, sections);

        // When
        ApiException exception =
                assertThrows(
                        ApiException.class,
                        () -> reportApi.handleApiAction(ReportApi.ACTION_GENERATE, params));

        // Then
        assertThat(exception.getMessage(), is("illegal_parameter"));
        assertThat(
                exception.toString(true),
                is(
                        "Provided parameter has illegal or unrecognized value (illegal_parameter) : !reports.api.error.badSections!"));
    }

    @Test
    void shouldPopulateReportConfidencesWithDelimiter() throws Exception {
        // Given
        String confidences = "mEdIuM| fAlSe PoSiTiVe ";
        params.put(ReportApi.PARAM_INC_CONFIDENCES, confidences);

        // When
        reportApi.handleApiAction(ReportApi.ACTION_GENERATE, params);

        // Then
        verify(extReports)
                .generateReport(reportDataCaptor.capture(), any(), anyString(), anyBoolean());
        ReportData reportData = reportDataCaptor.getValue();
        assertThat(reportData.isIncludeConfidence(Alert.CONFIDENCE_FALSE_POSITIVE), is(true));
        assertThat(reportData.isIncludeConfidence(Alert.CONFIDENCE_LOW), is(false));
        assertThat(reportData.isIncludeConfidence(Alert.CONFIDENCE_MEDIUM), is(true));
        assertThat(reportData.isIncludeConfidence(Alert.CONFIDENCE_HIGH), is(false));
        assertThat(reportData.isIncludeConfidence(Alert.CONFIDENCE_USER_CONFIRMED), is(false));
    }

    @Test
    void shouldPopulateReportRisksWithDelimiter() throws Exception {
        // Given
        String risks = " iNfOrMaTiOnAl |mEdIuM";
        params.put(ReportApi.PARAM_INC_RISKS, risks);

        // When
        reportApi.handleApiAction(ReportApi.ACTION_GENERATE, params);

        // Then
        verify(extReports)
                .generateReport(reportDataCaptor.capture(), any(), anyString(), anyBoolean());
        ReportData reportData = reportDataCaptor.getValue();
        assertThat(reportData.isIncludeRisk(Alert.RISK_INFO), is(true));
        assertThat(reportData.isIncludeRisk(Alert.RISK_LOW), is(false));
        assertThat(reportData.isIncludeRisk(Alert.RISK_MEDIUM), is(true));
        assertThat(reportData.isIncludeRisk(Alert.RISK_HIGH), is(false));
    }

    @Test
    void fileNameShouldOverrideFileNamePattern() throws Exception {
        // Given
        String reportDirectory = "src/main/zapHomeFiles";
        String reportFileName = "my Report";
        String reportFileNamePattern = "tropeR ym";
        params.put(ReportApi.PARAM_REPORT_DIRECTORY, reportDirectory);
        params.put(ReportApi.PARAM_REPORT_FILE_NAME, reportFileName);
        params.put(ReportApi.PARAM_REPORT_FILE_NAME_PATTERN, reportFileNamePattern);
        ArgumentCaptor<String> reportFilePathCaptor = ArgumentCaptor.forClass(String.class);

        // When
        reportApi.handleApiAction(ReportApi.ACTION_GENERATE, params);

        // Then
        verify(extReports)
                .generateReport(any(), any(), reportFilePathCaptor.capture(), anyBoolean());
        String fileNamePath =
                Paths.get(reportDirectory, reportFileName + '.' + template.getExtension())
                        .toString();
        String fileNamePatternPath =
                Paths.get(reportDirectory, reportFileNamePattern + '.' + template.getExtension())
                        .toString();
        assertAll(
                () -> assertThat(reportFilePathCaptor.getValue(), is(fileNamePath)),
                () -> assertThat(reportFilePathCaptor.getValue(), is(not(fileNamePatternPath))));
    }
}
