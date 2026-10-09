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
package org.zaproxy.addon.llm.automation;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.Mockito.mock;

import java.util.LinkedHashMap;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionHook;
import org.yaml.snakeyaml.Yaml;
import org.zaproxy.addon.automation.AutomationJob.Order;
import org.zaproxy.addon.automation.AutomationPlan;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.llm.ExtensionLlm;
import org.zaproxy.addon.llm.LlmProvider;
import org.zaproxy.addon.llm.LlmProviderConfig;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit tests for {@link LlmConfigJob}. */
class LlmConfigJobUnitTest extends TestUtils {

    private static final String VALID_PLAN =
            """
            parameters:
              defaultModel: m2
            providers:
              - name: local
                type: ollama
                endpoint: http://localhost:11434/
                models: [m1, m2]
                timeout: 30
            """;

    private ExtensionLlm extLlm;

    @BeforeEach
    void setUp() {
        mockMessages(new ExtensionLlm());
        Control.initSingletonForTesting();
        extLlm = new ExtensionLlm();
        extLlm.hook(mock(ExtensionHook.class));
        extLlm.getOptions().load(new ZapXmlConfiguration());
    }

    @Test
    void shouldReturnCorrectDefaults() {
        // Given
        LlmConfigJob job = new LlmConfigJob(extLlm);

        // When / Then
        assertThat(job.getType(), is(equalTo("llm-config")));
        assertThat(job.getOrder(), is(Order.CONFIGS));
    }

    @Test
    void shouldProvideValidTemplates() {
        // Given
        LlmConfigJob job = new LlmConfigJob(extLlm);

        // When / Then
        assertValidTemplate(job.getTemplateDataMin());
        assertValidTemplate(job.getTemplateDataMax());
    }

    @Test
    void shouldNotErrorOnValidPlan() {
        // Given
        LlmConfigJob job = jobFromYaml(VALID_PLAN);
        AutomationProgress progress = new AutomationProgress();

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.getErrors(), is(empty()));
        assertThat(job.getData().getProviders().size(), is(1));
        assertThat(job.getData().getProviders().get(0).getType(), is(LlmProvider.OLLAMA));
    }

    @Test
    void shouldErrorOnInvalidProviderType() {
        // Given
        LlmConfigJob job =
                jobFromYaml(
                        """
                        providers:
                          - name: a
                            type: nope
                        """);
        AutomationProgress progress = new AutomationProgress();

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(true));
    }

    @Test
    void shouldErrorOnBadProvidersList() {
        // Given
        LlmConfigJob job = jobFromYaml("providers: nope");
        AutomationProgress progress = new AutomationProgress();

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(
                progress.getErrors(),
                contains("Job llm-config providers must be a list, got: nope"));
    }

    @Test
    void shouldErrorOnBadProviderItem() {
        // Given
        LlmConfigJob job = jobFromYaml("providers:\n  - nope");
        AutomationProgress progress = new AutomationProgress();

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(true));
    }

    @Test
    void shouldReportMergeErrorsOnVerify() {
        // Given
        LlmConfigJob job = jobFromYaml("parameters:\n  defaultProvider: missing");
        AutomationProgress progress = new AutomationProgress();

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(
                progress.getErrors(),
                contains("The default provider 'missing' is not a configured provider"));
    }

    @Test
    void shouldApplyProvidersAndDefaultsOnRun() {
        // Given
        LlmConfigJob job = jobFromYaml(VALID_PLAN);
        job.verifyParameters(new AutomationProgress());
        AutomationProgress progress = new AutomationProgress();

        // When
        job.runJob(new AutomationPlan().getEnv(), progress);

        // Then
        assertThat(progress.hasErrors(), is(false));
        LlmProviderConfig config = extLlm.getOptions().getProviderConfig("local");
        assertThat(config.getProvider(), is(LlmProvider.OLLAMA));
        assertThat(config.getEndpoint(), is(equalTo("http://localhost:11434/")));
        assertThat(config.getTimeoutSeconds(), is(30));
        assertThat(extLlm.getDefaultProviderConfig().getName(), is(equalTo("local")));
        assertThat(extLlm.getDefaultModelName(), is(equalTo("m2")));
        assertThat(extLlm.isConfigured(), is(true));
    }

    @Test
    void shouldNotChangeOptionsOnRunWhenInvalid() {
        // Given
        LlmConfigJob job = jobFromYaml("parameters:\n  defaultProvider: missing");
        job.verifyParameters(new AutomationProgress());
        AutomationProgress progress = new AutomationProgress();

        // When
        job.runJob(new AutomationPlan().getEnv(), progress);

        // Then
        assertThat(progress.hasErrors(), is(true));
        assertThat(extLlm.getOptions().getProviderConfigs().size(), is(0));
    }

    @Test
    void shouldReturnFirstProviderProblem() {
        // Given
        LlmConfigJob job = new LlmConfigJob(extLlm);
        LlmConfigJob.Provider provider = new LlmConfigJob.Provider();
        provider.setName("a");
        provider.setType(LlmProvider.OPENAI_COMPATIBLE);

        // When
        String problem = job.validateProvider(provider, false);

        // Then
        assertThat(problem, is(equalTo("The provider 'a' requires an endpoint")));
    }

    @Test
    void shouldReturnNoProblemForValidProvider() {
        // Given
        LlmConfigJob job = new LlmConfigJob(extLlm);
        LlmConfigJob.Provider provider = new LlmConfigJob.Provider();
        provider.setName("a");
        provider.setType(LlmProvider.CLAUDE);
        provider.setModels(List.of("m"));

        // When / Then
        assertThat(job.validateProvider(provider, false), is(nullValue()));
    }

    private LlmConfigJob jobFromYaml(String yaml) {
        LlmConfigJob job = new LlmConfigJob(extLlm);
        job.setJobData((LinkedHashMap<?, ?>) new Yaml().load(yaml));
        return job;
    }

    private static void assertValidTemplate(String value) {
        assertThat(value, is(not(equalTo(""))));
        assertDoesNotThrow(() -> new Yaml().load(value));
    }
}
