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
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.io.File;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.util.List;
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
import org.zaproxy.addon.insights.internal.Insight;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class ExtensionReportsMdUnitTest extends TestUtils {

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

    @Test
    void shouldGenerateValidInsightsJsonReport() throws Exception {
        // Given
        Template template = ReportTestUtils.getTemplateFromYamlFile("traditional-md");
        String fileName = "insights-traditional-md";
        File f = File.createTempFile(fileName, template.getExtension());

        // When
        File r = ReportTestUtils.generateReportWithInsights(template, f);
        String report = new String(Files.readAllBytes(r.toPath()));

        // Then
        String expected =
                """
                # Test Title

                ZAP by [Checkmarx](https://checkmarx.com/).




                ## Insights

                | Level | Reason | Site | Description | Statistic |
                | --- | --- | --- | --- | --- |
                |  |  | https://www.example.com | Insight1 desc |  |
                |  |  | https://www.example.com | Insight2 desc |  |
                |  |  |  | Insight3 desc |  |
                """;
        assertThat(report.trim(), is(equalTo(expected.trim())));
    }

    @Test
    void shouldRenderStoppingInsightInMdReport() throws Exception {
        // Given
        Template template = ReportTestUtils.getTemplateFromYamlFile("traditional-md");
        File f = File.createTempFile("insights-stop-traditional-md", template.getExtension());
        Insight stopping =
                new Insight(
                        Insight.Level.HIGH,
                        Insight.Reason.EXCEEDED_HIGH,
                        "https://www.example.com",
                        "insight.auth.failure",
                        "Auth failure",
                        75,
                        true);

        // When
        File r = ReportTestUtils.generateReportWithInsights(template, f, stopping);
        String report = new String(Files.readAllBytes(r.toPath()));

        // Then
        assertThat(report, containsString("Auth failure"));
        assertThat(report, containsString("https://www.example.com"));
    }

    @Test
    void shouldGenerateTraditionalMdWithScriptDiagnostics() throws Exception {
        // Given
        Template template = ReportTestUtils.getTemplateFromYamlFile("traditional-md");
        File reportOutputFile =
                File.createTempFile("script-diagnostics-traditional-md", template.getExtension());

        // When
        File generatedReportFile =
                ReportTestUtils.generateReportWithScriptDiagnostics(template, reportOutputFile);
        String report = ReportTestUtils.readReportAsString(generatedReportFile);

        // Then
        assertThat(report, is(containsString("## Script Diagnostics")));
        assertThat(report, is(containsString("### 2026-04-01T12:00:00Z (FAILED)")));
        assertThat(report, is(containsString("Job: ... boom")));
        assertThat(report, is(containsString("#### 1. my-script (standalone)")));
        assertThat(report, is(containsString("| -1 |  | ERROR | boom |")));
        assertThat(report, is(containsString("### 2026-04-02T08:30:00Z (FAILED)")));
        assertThat(
                report,
                is(containsString("| 13 | ZestClientElementClick | ERROR | step failed |")));
        assertThat(report, is(containsString("### 2026-04-03T10:00:00Z (SUCCESS)")));
        assertThat(report, is(containsString("| 3 | ZestActionPrint | OUTPUT | logged in |")));
        assertThat(report, is(not(containsString("abc64png"))));
    }

    @Test
    void shouldNotIncludeScriptDiagnosticScreenshotsSection() throws Exception {
        Template template = ReportTestUtils.getTemplateFromYamlFile("traditional-md");

        assertThat(template.getSections(), is(not(hasItem("scriptdiagnosticsscreenshots"))));
    }

    @Test
    void shouldOmitScriptDiagnosticStdoutWhenOutputSectionDisabled() throws Exception {
        Template template = ReportTestUtils.getTemplateFromYamlFile("traditional-md");
        File reportOutputFile =
                File.createTempFile("traditional-md-no-script-stdout", template.getExtension());

        File generatedReportFile =
                ReportTestUtils.generateReportWithScriptDiagnostics(
                        template,
                        reportOutputFile,
                        true,
                        List.of(ReportTestUtils.defaultScriptDiagnosticRunWithStdoutAndError()),
                        "scriptdiagnosticsoutput");
        String report = ReportTestUtils.readReportAsString(generatedReportFile);

        assertThat(report, is(containsString("boom")));
        assertThat(report, is(not(containsString("logged in"))));
    }

    @Test
    void shouldOmitScriptDiagnosticsFromMdWhenSectionDisabled() throws Exception {
        // Given
        Template template = ReportTestUtils.getTemplateFromYamlFile("traditional-md");
        File reportOutputFile =
                File.createTempFile(
                        "script-diagnostics-traditional-md-disabled", template.getExtension());

        // When
        File generatedReportFile =
                ReportTestUtils.generateReportWithScriptDiagnostics(
                        template, reportOutputFile, false);
        String report = ReportTestUtils.readReportAsString(generatedReportFile);

        // Then
        assertThat(report, is(not(containsString("Script Diagnostics"))));
    }
}
