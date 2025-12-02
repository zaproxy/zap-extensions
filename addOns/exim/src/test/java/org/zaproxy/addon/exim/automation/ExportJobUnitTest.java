/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.exim.automation;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.aMapWithSize;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.model.Model;
import org.yaml.snakeyaml.Yaml;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationPlan;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.ContextWrapper;
import org.zaproxy.addon.exim.Exporter;
import org.zaproxy.addon.exim.ExporterOptions;
import org.zaproxy.addon.exim.ExporterOptions.Source;
import org.zaproxy.addon.exim.ExporterOptions.Type;
import org.zaproxy.addon.exim.ExporterResult;
import org.zaproxy.addon.exim.ExtensionExim;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link ExportJob}. */
class ExportJobUnitTest extends TestUtils {

    private ExtensionExim extension;
    private Exporter exporter;
    private ExportJob job;

    @BeforeAll
    static void setupMessages() {
        mockMessages(new ExtensionExim());
    }

    @BeforeEach
    void setUp() {
        mockMessages(new ExtensionExim());

        Model model = mock(Model.class);
        Model.setSingletonForTesting(model);
        extension = mock(ExtensionExim.class, withSettings().strictness(Strictness.LENIENT));
        exporter = mock();
        given(extension.getExporter()).willReturn(exporter);

        job = new ExportJob(extension);
    }

    @Test
    void shouldReturnDefaultFields() {
        assertThat(job.getType(), is(equalTo("export")));
        assertThat(job.getName(), is(equalTo("export")));
        assertThat(job.getOrder(), is(equalTo(AutomationJob.Order.AFTER_ATTACK)));
        assertValidTemplate(job.getTemplateDataMin());
        assertValidTemplate(job.getTemplateDataMax());
        assertThat(job.getParamMethodObject(), is(nullValue()));
        assertThat(job.getParamMethodName(), is(nullValue()));
    }

    @Test
    void shouldReturnCustomConfigParams() {
        // Given / When
        Map<String, String> params = job.getCustomConfigParameters();

        // Then
        assertThat(params, is(aMapWithSize(4)));
        assertThat(
                params,
                allOf(
                        hasEntry("type", ""),
                        hasEntry("fileName", ""),
                        hasEntry("source", ""),
                        hasEntry("context", "")));
    }

    @Test
    void shouldApplyCustomConfigParams() {
        // Given
        AutomationProgress progress = new AutomationProgress();
        String type = "har";
        String source = "all";
        String fileName = "/output/data";
        String context = "My Context";
        String yamlStr =
                "parameters:\n"
                        + "  type: "
                        + type
                        + "\n"
                        + "  source: "
                        + source
                        + "\n"
                        + "  fileName: "
                        + fileName
                        + "\n"
                        + "  context: "
                        + context;
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);

        job.setJobData(((LinkedHashMap<?, ?>) data));

        // When
        job.verifyParameters(progress);
        job.applyParameters(progress);

        // Then
        assertThat(job.getParameters().getType(), is(equalTo(ExporterOptions.Type.HAR)));
        assertThat(job.getParameters().getSource(), is(equalTo(ExporterOptions.Source.ALL)));
        assertThat(job.getParameters().getFileName(), is(equalTo(fileName)));
        assertThat(job.getParameters().getContext(), is(equalTo(context)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldReportExporterCount() throws IOException {
        // Given
        AutomationPlan plan = new AutomationPlan();
        AutomationProgress progress = plan.getProgress();
        AutomationEnvironment env = mock(AutomationEnvironment.class);
        ContextWrapper contextWrapper = new ContextWrapper(mock(Context.class), env);
        given(env.getContextWrapper(any())).willReturn(contextWrapper);
        Path file = Files.createTempFile("zap", "export");
        String yamlStr = "parameters:\n  fileName: " + file.toString();
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);
        ExporterResult result = mock();
        given(result.getCount()).willReturn(42);
        given(exporter.export(any())).willReturn(result);

        job.setJobData(((LinkedHashMap<?, ?>) data));
        job.setPlan(plan);

        // When
        job.verifyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(
                progress.getInfos(),
                hasItem(
                        "Job export: Exported 42 message(s) / node(s) to %s."
                                .formatted(file.toString())));
    }

    @Test
    void shouldReportExporterErrors() {
        // Given
        AutomationPlan plan = new AutomationPlan();
        AutomationProgress progress = plan.getProgress();
        AutomationEnvironment env = mock(AutomationEnvironment.class);
        ContextWrapper contextWrapper = new ContextWrapper(mock(Context.class), env);
        given(env.getContextWrapper(any())).willReturn(contextWrapper);
        String yamlStr = "parameters:\n  fileName: /some/file";
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);
        ExporterResult result = mock();
        String exporterError = "Error while exporting";
        given(result.getErrors()).willReturn(List.of(exporterError));
        given(exporter.export(any())).willReturn(result);

        job.setJobData(((LinkedHashMap<?, ?>) data));
        job.setPlan(plan);

        // When
        job.verifyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors(), contains("Job export Error: Error while exporting"));
    }

    @ParameterizedTest
    @EnumSource(
            value = Type.class,
            names = {"HAR", "URL"})
    void shouldReportErrorSiteTreeExportWithNonYamlFormat(Type type) {
        // Given
        AutomationPlan plan = new AutomationPlan();
        AutomationProgress progress = plan.getProgress();
        AutomationEnvironment env = mock(AutomationEnvironment.class);
        ContextWrapper contextWrapper = new ContextWrapper(mock(Context.class), env);
        given(env.getContextWrapper(any())).willReturn(contextWrapper);
        String yamlStr =
                "parameters:\n"
                        + "  source: SitesTree\n"
                        + "  type: "
                        + type.getId()
                        + "\n"
                        + "  fileName: /some/file";
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);
        ExporterResult result = mock();
        given(exporter.export(any())).willReturn(result);

        job.setJobData(((LinkedHashMap<?, ?>) data));
        job.setPlan(plan);

        // When
        job.verifyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(
                progress.getErrors(),
                contains(
                        "Job export Invalid type for Sites Tree, only YAML is supported: " + type));
    }

    @ParameterizedTest
    @EnumSource(
            value = Source.class,
            names = {"HISTORY", "ALL"})
    void shouldReportErrorNonSitesTreeExportWithYamlFormat(Source source) {
        // Given
        AutomationPlan plan = new AutomationPlan();
        AutomationProgress progress = plan.getProgress();
        AutomationEnvironment env = mock(AutomationEnvironment.class);
        ContextWrapper contextWrapper = new ContextWrapper(mock(Context.class), env);
        given(env.getContextWrapper(any())).willReturn(contextWrapper);
        String yamlStr =
                "parameters:\n"
                        + "  source: "
                        + source.getId()
                        + "\n"
                        + "  type: YAML\n"
                        + "  fileName: /some/file";
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);
        ExporterResult result = mock();
        given(exporter.export(any())).willReturn(result);

        job.setJobData(((LinkedHashMap<?, ?>) data));
        job.setPlan(plan);

        // When
        job.verifyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(
                progress.getErrors(),
                contains("Job export Invalid type for " + source + ", YAML is not supported"));
    }

    private static void assertValidTemplate(String value) {
        assertThat(value, is(not(equalTo(""))));
        assertDoesNotThrow(() -> new Yaml().load(value));
    }
}
