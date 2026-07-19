/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.zap.extension.scripts.report;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mockStatic;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.zaproxy.addon.reports.ReportData;
import org.zaproxy.zap.extension.scripts.internal.db.ScriptRunRecorder;
import org.zaproxy.zap.extension.scripts.internal.db.ScriptRunReportQuery;

/** Unit tests for {@link ExtensionScriptsReport}. */
class ExtensionScriptsReportUnitTest {

    private static final ExtensionScriptsReport.ScriptsReportDataHandler HANDLER =
            new ExtensionScriptsReport.ScriptsReportDataHandler();

    private static final List<ScriptRunReportData.Run> SAMPLE_RUNS =
            List.of(
                    new ScriptRunReportData.Run(
                            "2026-04-01T12:00:00Z",
                            ScriptRunRecorder.OUTCOME_FAILED,
                            "Job: ... boom",
                            List.of()));

    @Test
    void shouldNotAddScriptDiagnosticsWhenSectionNotIncluded() {
        // Given
        ReportData reportData = new ReportData("traditional-json");
        reportData.setSections(List.of());

        // When
        try (MockedStatic<ScriptRunReportQuery> query = mockStatic(ScriptRunReportQuery.class)) {
            query.when(() -> ScriptRunReportQuery.loadRunsForReport(any())).thenReturn(SAMPLE_RUNS);

            HANDLER.handle(reportData);

            // Then
            assertThat(
                    reportData.getReportObjects().get(ExtensionScriptsReport.SCRIPT_DIAGNOSTICS),
                    is(nullValue()));
        }
    }

    @Test
    void shouldAddScriptDiagnosticsWhenSectionEnabled() {
        // Given
        ReportData reportData = new ReportData("traditional-html");
        reportData.setSections(List.of("alertcount", "scriptdiagnostics"));

        // When
        try (MockedStatic<ScriptRunReportQuery> query = mockStatic(ScriptRunReportQuery.class)) {
            query.when(() -> ScriptRunReportQuery.loadRunsForReport(any())).thenReturn(SAMPLE_RUNS);

            HANDLER.handle(reportData);

            // Then
            assertThat(
                    reportData.getReportObjects().get(ExtensionScriptsReport.SCRIPT_DIAGNOSTICS),
                    is(notNullValue()));
        }
    }

    @Test
    void shouldNotAddScriptDiagnosticsWhenSectionDisabled() {
        // Given
        ReportData reportData = new ReportData("traditional-html");
        reportData.setSections(List.of("alertcount", "insights"));

        // When
        try (MockedStatic<ScriptRunReportQuery> query = mockStatic(ScriptRunReportQuery.class)) {
            query.when(() -> ScriptRunReportQuery.loadRunsForReport(any())).thenReturn(SAMPLE_RUNS);

            HANDLER.handle(reportData);

            // Then
            assertThat(
                    reportData.getReportObjects().get(ExtensionScriptsReport.SCRIPT_DIAGNOSTICS),
                    is(nullValue()));
        }
    }

    @Test
    void shouldNotAddScriptDiagnosticsWhenNoRuns() {
        // Given
        ReportData reportData = new ReportData("traditional-html");
        reportData.setSections(
                List.of(
                        "scriptdiagnostics",
                        "scriptdiagnosticsscreenshots",
                        "scriptdiagnosticsoutput"));

        // When
        try (MockedStatic<ScriptRunReportQuery> query = mockStatic(ScriptRunReportQuery.class)) {
            query.when(() -> ScriptRunReportQuery.loadRunsForReport(any())).thenReturn(List.of());

            HANDLER.handle(reportData);

            // Then
            assertThat(
                    reportData.getReportObjects().get(ExtensionScriptsReport.SCRIPT_DIAGNOSTICS),
                    is(nullValue()));
        }
    }

    @ParameterizedTest
    @CsvSource({
        "scriptdiagnosticsscreenshots, true, false",
        "scriptdiagnosticsoutput, false, true"
    })
    void shouldPassSectionOptionsToQuery(
            String optionalSection, boolean includeScreenshots, boolean includeScriptOutput) {
        // Given
        ReportData reportData = new ReportData("traditional-html");
        reportData.setSections(List.of("scriptdiagnostics", optionalSection));

        // When
        ArgumentCaptor<ScriptRunReportQuery.Options> optionsCaptor =
                ArgumentCaptor.forClass(ScriptRunReportQuery.Options.class);
        try (MockedStatic<ScriptRunReportQuery> query = mockStatic(ScriptRunReportQuery.class)) {
            query.when(() -> ScriptRunReportQuery.loadRunsForReport(optionsCaptor.capture()))
                    .thenReturn(SAMPLE_RUNS);

            HANDLER.handle(reportData);

            // Then
            ScriptRunReportQuery.Options options = optionsCaptor.getValue();
            assertThat(options.includeScreenshots(), is(includeScreenshots));
            assertThat(options.includeScriptOutput(), is(includeScriptOutput));
        }
    }
}
