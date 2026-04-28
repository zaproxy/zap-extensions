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
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import java.util.LinkedHashMap;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.quality.Strictness;
import org.yaml.snakeyaml.Yaml;
import org.zaproxy.addon.automation.AutomationJob.Order;
import org.zaproxy.addon.automation.AutomationPlan;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.mcp.ExtensionMcp;
import org.zaproxy.addon.mcp.McpParam;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit tests for {@link McpConfigJob}. */
class McpConfigJobUnitTest extends TestUtils {

    private ExtensionMcp extMcp;
    private McpParam mcpParam;

    @BeforeEach
    void setUp() {
        mockMessages(new ExtensionMcp());

        mcpParam = new McpParam();
        mcpParam.load(new ZapXmlConfiguration());

        extMcp = mock(ExtensionMcp.class, withSettings().strictness(Strictness.LENIENT));
        given(extMcp.getMcpParam()).willReturn(mcpParam);
    }

    // ---- metadata ----

    @Test
    void shouldReturnCorrectDefaults() {
        assertThat(new McpConfigJob(extMcp).getType(), is(equalTo("mcp-config")));
        assertThat(new McpConfigJob(extMcp).getOrder(), is(equalTo(Order.CONFIGS)));
    }

    @Test
    void shouldProvideValidTemplates() {
        McpConfigJob job = new McpConfigJob(extMcp);
        assertValidTemplate(job.getTemplateDataMin());
        assertValidTemplate(job.getTemplateDataMax());
    }

    // ---- verifyParameters ----

    @Test
    void shouldNotErrorOnValidParameters() {
        // Given
        McpConfigJob job =
                jobFromYaml(
                        "parameters:\n"
                                + "  port: 8080\n"
                                + "  securityKeyEnabled: true\n"
                                + "  securityKey: mysecretkey");
        AutomationProgress progress = new AutomationProgress();

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(false));
    }

    @Test
    void shouldErrorWhenPortIsTooLow() {
        // Given
        McpConfigJob job = jobFromYaml("parameters:\n  port: 0");
        AutomationProgress progress = new AutomationProgress();

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(true));
        assertThat(progress.getErrors().size(), is(1));
        assertThat(progress.getErrors().get(0), is("Port must be between 1 and 65535."));
    }

    @Test
    void shouldErrorWhenPortIsTooHigh() {
        // Given
        McpConfigJob job = jobFromYaml("parameters:\n  port: 65536");
        AutomationProgress progress = new AutomationProgress();

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(true));
        assertThat(progress.getErrors().size(), is(1));
        assertThat(progress.getErrors().get(0), is("Port must be between 1 and 65535."));
    }

    @Test
    void shouldErrorWhenSecurityKeyEnabledButKeyIsEmpty() {
        // Given
        McpConfigJob job =
                jobFromYaml("parameters:\n  securityKeyEnabled: true\n  securityKey: ''");
        AutomationProgress progress = new AutomationProgress();

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(true));
        assertThat(progress.getErrors().size(), is(1));
        assertThat(progress.getErrors().get(0), is("Security key is required when enabled."));
    }

    @Test
    void shouldNotThrowWhenSecurityKeyEnabledIsOmitted() {
        // Boolean field is null when YAML omits securityKeyEnabled — must not NPE on auto-unbox
        McpConfigJob job = jobFromYaml("parameters:\n  port: 8282");
        AutomationProgress progress = new AutomationProgress();

        assertDoesNotThrow(() -> job.verifyParameters(progress));
        assertThat(progress.hasErrors(), is(false));
    }

    // ---- runJob ----

    @Test
    void shouldApplyPortToMcpParam() {
        // Given
        McpConfigJob job = new McpConfigJob(extMcp);
        job.getParameters().setPort(9090);

        // When
        job.runJob(new AutomationPlan().getEnv(), new AutomationProgress());

        // Then
        assertThat(mcpParam.getPort(), is(9090));
    }

    @Test
    void shouldApplyEnabledFlagToMcpParam() {
        // Given
        McpConfigJob job = new McpConfigJob(extMcp);
        job.getParameters().setEnabled(false);

        // When
        job.runJob(new AutomationPlan().getEnv(), new AutomationProgress());

        // Then
        assertThat(mcpParam.isEnabled(), is(false));
    }

    @Test
    void shouldApplySecurityKeyEnabledToMcpParam() {
        // Given
        McpConfigJob job = new McpConfigJob(extMcp);
        job.getParameters().setSecurityKeyEnabled(false);

        // When
        job.runJob(new AutomationPlan().getEnv(), new AutomationProgress());

        // Then
        assertThat(mcpParam.isSecurityKeyEnabled(), is(false));
    }

    @Test
    void shouldApplySecurityKeyToMcpParam() {
        // Given
        McpConfigJob job = new McpConfigJob(extMcp);
        job.getParameters().setSecurityKey("new-secret");

        // When
        job.runJob(new AutomationPlan().getEnv(), new AutomationProgress());

        // Then
        assertThat(mcpParam.getSecurityKey(), is(equalTo("new-secret")));
    }

    @Test
    void shouldSkipNullPortParameter() {
        // Given — null means the YAML did not specify this field
        McpConfigJob job = new McpConfigJob(extMcp);
        job.getParameters().setPort(null);
        int portBefore = mcpParam.getPort();

        // When
        job.runJob(new AutomationPlan().getEnv(), new AutomationProgress());

        // Then
        assertThat(mcpParam.getPort(), is(portBefore));
    }

    @Test
    void shouldCallApplyServerConfigAfterApplyingParameters() {
        // Given
        McpConfigJob job = new McpConfigJob(extMcp);

        // When
        job.runJob(new AutomationPlan().getEnv(), new AutomationProgress());

        // Then
        verify(extMcp).applyServerConfig();
    }

    // ---- helpers ----

    private McpConfigJob jobFromYaml(String yaml) {
        Object data = new Yaml().load(yaml);
        McpConfigJob job = new McpConfigJob(extMcp);
        job.setJobData((LinkedHashMap<?, ?>) data);
        return job;
    }

    private static void assertValidTemplate(String value) {
        assertThat(value, is(not(equalTo(""))));
        assertDoesNotThrow(() -> new Yaml().load(value));
    }
}
