/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.yaml.snakeyaml.Yaml;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationPlan;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.ContextWrapper;
import org.zaproxy.addon.reports.ExtensionReports;
import org.zaproxy.addon.reports.ReportData;
import org.zaproxy.addon.reports.ReportParam;
import org.zaproxy.addon.reports.Template;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link ReportJob}. */
class ReportJobUnitTest extends TestUtils {

    private ExtensionReports extensionReports;

    @BeforeEach
    void setUp() {
        ExtensionLoader extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        extensionReports =
                mock(ExtensionReports.class, withSettings().strictness(Strictness.LENIENT));
        given(extensionReports.getReportParam()).willReturn(new ReportParam());
        given(extensionLoader.getExtension(ExtensionReports.class)).willReturn(extensionReports);
        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);

        mockMessages(new ExtensionReports());
    }

    @AfterEach
    void cleanUp() {
        Constant.messages = null;
    }

    @Test
    void shouldReturnDefaultFields() {
        // Given / When
        ReportJob job = new ReportJob();

        // Then
        assertThat(job.getType(), is(equalTo("report")));
        assertThat(job.getName(), is(equalTo("report")));
        assertThat(job.getOrder(), is(equalTo(AutomationJob.Order.REPORT)));
        assertThat(job.getData().getRisks(), is(nullValue()));
        assertThat(job.getData().getConfidences(), is(nullValue()));
        assertThat(job.getData().getSections(), is(nullValue()));
        assertThat(job.getData().getSites(), is(nullValue()));
        assertThat(job.getParamMethodObject(), is(nullValue()));
        assertThat(job.getParamMethodName(), is(nullValue()));
    }

    @Test
    void shouldApplyCustomData() {
        // Given
        ReportJob job =
                createReportJob(
                        "risks:\n"
                                + "- low\n"
                                + "- high\n"
                                + "confidences:\n"
                                + "- medium\n"
                                + "- confirmed\n"
                                + "sections:\n"
                                + "- siteRiskCounts\n"
                                + "- summaries\n"
                                + "sites:\n"
                                + "- example.com\n"
                                + "- test.com");

        AutomationProgress progress = new AutomationProgress();

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(job.getData().getRisks(), contains("low", "high"));
        assertThat(job.getData().getConfidences(), contains("medium", "confirmed"));
        assertThat(job.getData().getSections(), contains("siteRiskCounts", "summaries"));
        assertThat(job.getData().getSites(), contains("example.com", "test.com"));
    }

    @Test
    void shouldReturnCustomConfigParams() {
        // Given
        ReportJob job = new ReportJob();

        // When
        Map<String, String> params = job.getCustomConfigParameters();

        // Then
        assertThat(params.size(), is(equalTo(7)));
        assertThat(
                params,
                allOf(
                        hasKey("template"),
                        hasKey("reportFile"),
                        hasKey("reportDir"),
                        hasKey("reportTitle"),
                        hasKey("reportDescription"),
                        hasKey("theme"),
                        hasKey("displayReport")));
    }

    @Test
    void shouldApplyCustomConfigParams() {
        // Given
        String template = "template";
        String reportFile = "reportFile";
        String reportDir = "reportDir";
        String reportTitle = "reportTitle";
        String reportDescription = "reportDescription";
        String theme = "theme";
        Boolean displayReport = Boolean.TRUE;
        ReportJob job =
                createReportJob(
                        "parameters:\n"
                                + "  template: "
                                + template
                                + "\n"
                                + "  reportFile: "
                                + reportFile
                                + "\n"
                                + "  reportDir: "
                                + reportDir
                                + "\n"
                                + "  reportTitle: "
                                + reportTitle
                                + "\n"
                                + "  reportDescription: "
                                + reportDescription
                                + "\n"
                                + "  theme: "
                                + theme
                                + "\n"
                                + "  displayReport: "
                                + displayReport);
        AutomationProgress progress = new AutomationProgress();

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(job.getParameters().getTemplate(), is(equalTo(template)));
        assertThat(job.getParameters().getReportFile(), is(equalTo(reportFile)));
        assertThat(job.getParameters().getReportDir(), is(equalTo(reportDir)));
        assertThat(job.getParameters().getReportTitle(), is(equalTo(reportTitle)));
        assertThat(job.getParameters().getReportDescription(), is(equalTo(reportDescription)));
        assertThat(job.getParameters().getTheme(), is(equalTo(theme)));
        assertThat(job.getParameters().getDisplayReport(), is(equalTo(displayReport)));
    }

    @Test
    void shouldReplaceVarInReportFileWhenRunning() throws IOException {
        // Given
        String templateName = "template";
        String reportFile = "${reportFile}";
        ReportJob job =
                createReportJob(
                        "parameters:\n"
                                + "  template: "
                                + templateName
                                + "\n"
                                + "  reportFile: "
                                + reportFile);
        AutomationPlan plan = new AutomationPlan();
        AutomationProgress progress = plan.getProgress();
        AutomationEnvironment env = plan.getEnv();
        env.getData().getVars().put("reportFile", "report-file");
        ContextWrapper contextWrapper = mock(ContextWrapper.class);
        given(contextWrapper.getUrls()).willReturn(Collections.singletonList(""));
        env.setContexts(Arrays.asList(contextWrapper));
        Template template = mock(Template.class);
        given(template.getExtension()).willReturn("ext");
        given(extensionReports.getTemplateByConfigName(templateName)).willReturn(template);
        given(extensionReports.generateReport(any(), any(), anyString(), anyBoolean()))
                .willReturn(mock(File.class));
        job.verifyParameters(progress);
        job.setPlan(plan);

        // When
        job.runJob(env, progress);

        // Then
        ArgumentCaptor<String> captorReportFileName = ArgumentCaptor.forClass(String.class);
        verify(extensionReports)
                .generateReport(any(), any(), captorReportFileName.capture(), anyBoolean());
        assertThat(captorReportFileName.getValue(), endsWith(fsPath("report-file.ext")));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldReplaceVarInReportDirWhenRunning() throws IOException {
        // Given
        String templateName = "template";
        String reportFile = "report-file";
        String reportDir = "${reportDir}";
        ReportJob job =
                createReportJob(
                        "parameters:\n"
                                + "  template: "
                                + templateName
                                + "\n"
                                + "  reportFile: "
                                + reportFile
                                + "\n"
                                + "  reportDir: "
                                + reportDir);
        AutomationPlan plan = new AutomationPlan();
        AutomationProgress progress = plan.getProgress();
        AutomationEnvironment env = plan.getEnv();
        env.getData().getVars().put("reportDir", "report-dir");
        ContextWrapper contextWrapper = mock(ContextWrapper.class);
        given(contextWrapper.getUrls()).willReturn(Collections.singletonList(""));
        env.setContexts(Arrays.asList(contextWrapper));
        Template template = mock(Template.class);
        given(template.getExtension()).willReturn("ext");
        given(extensionReports.getTemplateByConfigName(templateName)).willReturn(template);
        given(extensionReports.generateReport(any(), any(), anyString(), anyBoolean()))
                .willReturn(mock(File.class));
        job.verifyParameters(progress);
        job.setPlan(plan);

        // When
        job.runJob(env, progress);

        // Then
        ArgumentCaptor<String> captorReportFileName = ArgumentCaptor.forClass(String.class);
        verify(extensionReports)
                .generateReport(any(), any(), captorReportFileName.capture(), anyBoolean());
        assertThat(
                captorReportFileName.getValue(), endsWith(fsPath("report-dir", "report-file.ext")));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldReplaceVarInSiteWhenRunning() throws IOException {
        // Given
        String templateName = "template";
        String reportFile = "ZAP-Report-[[site]]";
        ReportJob job =
                createReportJob(
                        "parameters:\n"
                                + "  template: "
                                + templateName
                                + "\n"
                                + "  reportFile: "
                                + reportFile);
        AutomationPlan plan = new AutomationPlan();
        AutomationProgress progress = plan.getProgress();
        AutomationEnvironment env = plan.getEnv();
        env.getData().getVars().put("reportDir", "report-dir");
        env.getData().getVars().put("ZAP_TARGET", "https://www.example.com/");
        ContextWrapper contextWrapper = mock(ContextWrapper.class);
        given(contextWrapper.getUrls()).willReturn(Collections.singletonList("${ZAP_TARGET}"));
        env.setContexts(Arrays.asList(contextWrapper));
        Template template = mock(Template.class);
        given(template.getExtension()).willReturn("ext");
        given(extensionReports.getTemplateByConfigName(templateName)).willReturn(template);
        given(extensionReports.generateReport(any(), any(), anyString(), anyBoolean()))
                .willReturn(mock(File.class));
        job.verifyParameters(progress);
        job.setPlan(plan);

        // When
        job.runJob(env, progress);

        // Then
        ArgumentCaptor<String> captorReportFileName = ArgumentCaptor.forClass(String.class);
        verify(extensionReports)
                .generateReport(any(), any(), captorReportFileName.capture(), anyBoolean());
        assertThat(
                new File(captorReportFileName.getValue()).getName(),
                is(equalTo("ZAP-Report-www.example.com.ext")));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldDefaultToCwdDirName() throws IOException {
        // Given
        String templateName = "template";
        String reportFile = "report-file";
        File planFile = Files.createTempFile("plan", ".yaml").toFile();
        ReportJob job =
                createReportJob(
                        "parameters:\n"
                                + "  template: "
                                + templateName
                                + "\n"
                                + "  reportFile: "
                                + reportFile);
        AutomationPlan plan = new AutomationPlan();
        AutomationProgress progress = plan.getProgress();
        AutomationEnvironment env = plan.getEnv();
        ContextWrapper contextWrapper = mock(ContextWrapper.class);
        given(contextWrapper.getUrls()).willReturn(Collections.singletonList(""));
        env.setContexts(Arrays.asList(contextWrapper));
        Template template = mock(Template.class);
        given(template.getExtension()).willReturn("ext");
        given(extensionReports.getTemplateByConfigName(templateName)).willReturn(template);
        given(extensionReports.generateReport(any(), any(), anyString(), anyBoolean()))
                .willReturn(mock(File.class));
        plan.setFile(planFile);
        job.verifyParameters(progress);
        job.setPlan(plan);

        // When
        job.runJob(env, progress);

        // Then
        ArgumentCaptor<String> captorReportFileName = ArgumentCaptor.forClass(String.class);
        verify(extensionReports)
                .generateReport(any(), any(), captorReportFileName.capture(), anyBoolean());
        assertThat(
                new File(captorReportFileName.getValue()).getParent(),
                is(equalTo(planFile.getParent())));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldSupportRelativeDirName() throws IOException {
        // Given
        String templateName = "template";
        String reportFile = "report-file";
        File planFile = Files.createTempFile("plan", ".yaml").toFile();
        ReportJob job =
                createReportJob(
                        "parameters:\n"
                                + "  template: "
                                + templateName
                                + "\n"
                                + "  reportFile: "
                                + reportFile
                                + "\n"
                                + "  reportDir: test");
        AutomationPlan plan = new AutomationPlan();
        AutomationProgress progress = plan.getProgress();
        AutomationEnvironment env = plan.getEnv();
        ContextWrapper contextWrapper = mock(ContextWrapper.class);
        given(contextWrapper.getUrls()).willReturn(Collections.singletonList(""));
        env.setContexts(Arrays.asList(contextWrapper));
        Template template = mock(Template.class);
        given(template.getExtension()).willReturn("ext");
        given(extensionReports.getTemplateByConfigName(templateName)).willReturn(template);
        given(extensionReports.generateReport(any(), any(), anyString(), anyBoolean()))
                .willReturn(mock(File.class));
        plan.setFile(planFile);
        job.verifyParameters(progress);
        job.setPlan(plan);

        // When
        job.runJob(env, progress);

        // Then
        ArgumentCaptor<String> captorReportFileName = ArgumentCaptor.forClass(String.class);
        verify(extensionReports)
                .generateReport(any(), any(), captorReportFileName.capture(), anyBoolean());
        assertThat(
                captorReportFileName.getValue().startsWith(planFile.getParent()),
                is(equalTo(true)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldErrorOnInvalidTemplate() throws Exception {
        // Given
        String templateName = "template-a";
        ReportJob job =
                createReportJob(
                        "parameters:\n"
                                + "  template: "
                                + templateName
                                + "\n"
                                + "  reportFile: report-file"
                                + "\n"
                                + "  reportDir: test");
        AutomationPlan plan = new AutomationPlan();
        AutomationProgress progress = plan.getProgress();
        AutomationEnvironment env = plan.getEnv();
        var templates = List.of("template-b", "template-c");
        given(extensionReports.getTemplateConfigNames()).willReturn(templates);
        job.verifyParameters(progress);
        job.setPlan(plan);

        // When
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(
                progress.getErrors().get(0),
                allOf(
                        containsString("invalid"),
                        containsString(templateName),
                        containsString(templates.toString())));
    }

    @Test
    void shouldIncludeAllSitesByDefault() throws IOException {
        // Given
        String templateName = "template";
        File planFile = Files.createTempFile("plan", ".yaml").toFile();
        ReportJob job =
                createReportJob(
                        "parameters:\n"
                                + "  template: "
                                + templateName
                                + "\n"
                                + "  reportFile: report-file\n  reportDir: repord-dir");

        AutomationPlan plan = new AutomationPlan();
        AutomationProgress progress = plan.getProgress();
        AutomationEnvironment env = plan.getEnv();
        ContextWrapper contextWrapper = mock(ContextWrapper.class);
        given(contextWrapper.getUrls()).willReturn(Collections.singletonList(""));
        env.setContexts(Arrays.asList(contextWrapper));
        Template template = mock(Template.class);
        given(template.getExtension()).willReturn("ext");
        given(extensionReports.getTemplateByConfigName(templateName)).willReturn(template);
        plan.setFile(planFile);

        try (MockedStatic<ExtensionReports> extReport =
                Mockito.mockStatic(ExtensionReports.class)) {
            extReport
                    .when(ExtensionReports::getSites)
                    .thenReturn(Arrays.asList("https://example1.com", "https://example2.org"));
            extReport
                    .when(() -> ExtensionReports.getNameFromPattern(anyString(), anyString()))
                    .thenReturn("filename");

            ArgumentCaptor<ReportData> reportDataCapture =
                    ArgumentCaptor.forClass(ReportData.class);
            given(
                            extensionReports.generateReport(
                                    reportDataCapture.capture(), any(), anyString(), anyBoolean()))
                    .willReturn(mock(File.class));

            job.verifyParameters(progress);
            job.setPlan(plan);

            // When
            job.runJob(env, progress);

            // Then
            List<String> sites = reportDataCapture.getValue().getSites();
            assertThat(sites.size(), is(equalTo(2)));
            assertThat(sites.get(0), is(equalTo("https://example1.com")));
            assertThat(sites.get(1), is(equalTo("https://example2.org")));
            assertThat(progress.hasWarnings(), is(equalTo(false)));
            assertThat(progress.hasErrors(), is(equalTo(false)));
        }
    }

    @Test
    void shouldIncludeOnlySpecifiedSites() throws IOException {
        // Given
        String templateName = "template";
        File planFile = Files.createTempFile("plan", ".yaml").toFile();
        ReportJob job =
                createReportJob(
                        "parameters:\n"
                                + "  template: "
                                + templateName
                                + "\n"
                                + "  reportFile: report-file\n"
                                + "  reportDir: report-dir\n"
                                + "sites:\n - example2");

        AutomationPlan plan = new AutomationPlan();
        AutomationProgress progress = plan.getProgress();
        AutomationEnvironment env = plan.getEnv();
        ContextWrapper contextWrapper = mock(ContextWrapper.class);
        given(contextWrapper.getUrls()).willReturn(Collections.singletonList(""));
        env.setContexts(Arrays.asList(contextWrapper));
        Template template = mock(Template.class);
        given(template.getExtension()).willReturn("ext");
        given(extensionReports.getTemplateByConfigName(templateName)).willReturn(template);
        plan.setFile(planFile);

        try (MockedStatic<ExtensionReports> extReport =
                Mockito.mockStatic(ExtensionReports.class)) {
            extReport
                    .when(ExtensionReports::getSites)
                    .thenReturn(Arrays.asList("https://example1.com", "https://example2.org"));
            extReport
                    .when(() -> ExtensionReports.getNameFromPattern(anyString(), anyString()))
                    .thenReturn("filename");

            ArgumentCaptor<ReportData> reportDataCapture =
                    ArgumentCaptor.forClass(ReportData.class);
            given(
                            extensionReports.generateReport(
                                    reportDataCapture.capture(), any(), anyString(), anyBoolean()))
                    .willReturn(mock(File.class));

            job.verifyParameters(progress);
            job.setPlan(plan);

            // When
            job.runJob(env, progress);

            // Then
            List<String> sites = reportDataCapture.getValue().getSites();
            assertThat(sites.size(), is(equalTo(1)));
            assertThat(sites.get(0), is(equalTo("https://example2.org")));
            assertThat(progress.hasWarnings(), is(equalTo(false)));
            assertThat(progress.hasErrors(), is(equalTo(false)));
        }
    }

    @Test
    void shouldWarnIfUnknownSiteString() throws IOException {
        // Given
        String templateName = "template";
        File planFile = Files.createTempFile("plan", ".yaml").toFile();
        ReportJob job =
                createReportJob(
                        "parameters:\n"
                                + "  template: "
                                + templateName
                                + "\n"
                                + "  reportFile: report-file\n"
                                + "  reportDir: report-dir\n"
                                + "sites:\n - example3");

        AutomationPlan plan = new AutomationPlan();
        AutomationProgress progress = plan.getProgress();
        AutomationEnvironment env = plan.getEnv();
        ContextWrapper contextWrapper = mock(ContextWrapper.class);
        given(contextWrapper.getUrls()).willReturn(Collections.singletonList(""));
        env.setContexts(Arrays.asList(contextWrapper));
        Template template = mock(Template.class);
        given(template.getExtension()).willReturn("ext");
        given(extensionReports.getTemplateByConfigName(templateName)).willReturn(template);
        plan.setFile(planFile);

        try (MockedStatic<ExtensionReports> extReport =
                Mockito.mockStatic(ExtensionReports.class)) {
            extReport
                    .when(ExtensionReports::getSites)
                    .thenReturn(Arrays.asList("https://example1.com", "https://example2.org"));
            extReport
                    .when(() -> ExtensionReports.getNameFromPattern(anyString(), anyString()))
                    .thenReturn("filename");

            ArgumentCaptor<ReportData> reportDataCapture =
                    ArgumentCaptor.forClass(ReportData.class);
            given(
                            extensionReports.generateReport(
                                    reportDataCapture.capture(), any(), anyString(), anyBoolean()))
                    .willReturn(mock(File.class));

            job.verifyParameters(progress);
            job.setPlan(plan);

            // When
            job.runJob(env, progress);

            // Then
            List<String> sites = reportDataCapture.getValue().getSites();
            assertThat(sites.size(), is(equalTo(0)));
            assertThat(progress.hasWarnings(), is(equalTo(true)));
            assertThat(progress.getWarnings().size(), is(equalTo(1)));
            assertThat(
                    progress.getWarnings().get(0),
                    is(
                            equalTo(
                                    "Job report invalid site example3, valid sites: [https://example1.com, https://example2.org]")));
            assertThat(progress.hasErrors(), is(equalTo(false)));
        }
    }

    private static ReportJob createReportJob(String data) {
        ReportJob job = new ReportJob();
        job.setJobData(new Yaml().load(data));
        return job;
    }

    private static String fsPath(String... elements) {
        String separator = FileSystems.getDefault().getSeparator();
        return separator + String.join(separator, elements);
    }
}
