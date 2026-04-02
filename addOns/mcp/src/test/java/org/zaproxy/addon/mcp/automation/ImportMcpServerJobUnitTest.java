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
package org.zaproxy.addon.mcp.automation;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.util.LinkedHashMap;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.quality.Strictness;
import org.yaml.snakeyaml.Yaml;
import org.zaproxy.addon.automation.AutomationJob.Order;
import org.zaproxy.addon.automation.AutomationPlan;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.mcp.ExtensionMcp;
import org.zaproxy.addon.mcp.importer.McpImporter;
import org.zaproxy.addon.mcp.importer.McpImporter.ImportResults;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit tests for {@link ImportMcpServerJob}. */
class ImportMcpServerJobUnitTest extends TestUtils {

    private McpImporter importer;

    @BeforeEach
    void setUp() {
        mockMessages(new ExtensionMcp());

        importer = mock(McpImporter.class, withSettings().strictness(Strictness.LENIENT));
        given(importer.importServer(any())).willReturn(new ImportResults(0, List.of()));
    }

    // ---- metadata ----

    @Test
    void shouldReturnCorrectDefaults() {
        assertThat(new ImportMcpServerJob(importer).getType(), is(equalTo("mcp-import")));
        assertThat(new ImportMcpServerJob(importer).getOrder(), is(equalTo(Order.EXPLORE)));
    }

    @Test
    void shouldProvideValidTemplates() {
        ImportMcpServerJob job = new ImportMcpServerJob(importer);
        assertValidTemplate(job.getTemplateDataMin());
        assertValidTemplate(job.getTemplateDataMax());
    }

    // ---- verifyParameters ----

    @Test
    void shouldErrorWhenServerUrlIsMissing() {
        // Given — no serverUrl in YAML
        ImportMcpServerJob job = jobFromYaml("parameters:\n  securityKey: somekey");
        AutomationProgress progress = new AutomationProgress();

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(true));
        assertThat(progress.getErrors().size(), is(1));
        assertThat(progress.getErrors().get(0), is("The serverUrl parameter is required"));
    }

    @Test
    void shouldErrorWhenServerUrlIsBlank() {
        // Given
        ImportMcpServerJob job = jobFromYaml("parameters:\n  serverUrl: ''");
        AutomationProgress progress = new AutomationProgress();

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(true));
        assertThat(progress.getErrors().size(), is(1));
        assertThat(progress.getErrors().get(0), is("The serverUrl parameter is required"));
    }

    @Test
    void shouldNotErrorWhenServerUrlIsValid() {
        // Given
        ImportMcpServerJob job = jobFromYaml("parameters:\n  serverUrl: 'http://localhost:8282'");
        AutomationProgress progress = new AutomationProgress();

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(false));
    }

    // ---- runJob ----

    @Test
    void shouldPassImportErrorsAsWarningsToProgress() {
        // Given
        given(importer.importServer(any()))
                .willReturn(new ImportResults(0, List.of("connect refused", "timeout")));
        ImportMcpServerJob job = jobFromYaml("parameters:\n  serverUrl: 'http://localhost:8282'");
        AutomationPlan plan = new AutomationPlan();
        job.verifyParameters(plan.getProgress());

        // When
        job.runJob(plan.getEnv(), plan.getProgress());

        // Then
        assertThat(plan.getProgress().hasWarnings(), is(true));
        assertThat(plan.getProgress().getWarnings().size(), is(2));
        assertThat(plan.getProgress().getWarnings().get(0), is("connect refused"));
        assertThat(plan.getProgress().getWarnings().get(1), is("timeout"));
    }

    @Test
    void shouldReportImportedRequestCountInProgress() {
        // Given
        given(importer.importServer(any())).willReturn(new ImportResults(7, List.of()));
        ImportMcpServerJob job = jobFromYaml("parameters:\n  serverUrl: 'http://localhost:8282'");
        AutomationPlan plan = new AutomationPlan();
        job.verifyParameters(plan.getProgress());

        // When
        job.runJob(plan.getEnv(), plan.getProgress());

        // Then
        assertThat(plan.getProgress().hasErrors(), is(false));
        String infoMessage =
                plan.getProgress().getInfos().get(plan.getProgress().getInfos().size() - 1);
        assertThat(infoMessage, containsString("7"));
    }

    @Test
    void shouldPassServerUrlAndSecurityKeyToImporter() {
        // Given
        ImportMcpServerJob job =
                jobFromYaml(
                        "parameters:\n"
                                + "  serverUrl: 'http://mcp.example.com'\n"
                                + "  securityKey: 'Bearer token123'");
        AutomationPlan plan = new AutomationPlan();
        job.verifyParameters(plan.getProgress());

        // When
        job.runJob(plan.getEnv(), plan.getProgress());

        // Then — verify the importer received the correct config
        org.mockito.ArgumentCaptor<McpImporter.ImportConfig> captor =
                org.mockito.ArgumentCaptor.forClass(McpImporter.ImportConfig.class);
        org.mockito.Mockito.verify(importer).importServer(captor.capture());
        assertThat(captor.getValue().serverUrl(), is(equalTo("http://mcp.example.com")));
        assertThat(captor.getValue().securityKey(), is(equalTo("Bearer token123")));
    }

    // ---- helpers ----

    private ImportMcpServerJob jobFromYaml(String yaml) {
        Object data = new Yaml().load(yaml);
        ImportMcpServerJob job = new ImportMcpServerJob(importer);
        job.setJobData((LinkedHashMap<?, ?>) data);
        return job;
    }

    private static void assertValidTemplate(String value) {
        assertThat(value, is(not(equalTo(""))));
        assertDoesNotThrow(() -> new Yaml().load(value));
    }
}
