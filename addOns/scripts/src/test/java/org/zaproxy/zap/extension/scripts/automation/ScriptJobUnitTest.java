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
package org.zaproxy.zap.extension.scripts.automation;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.stringContainsInOrder;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

import java.io.File;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Locale;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.MockedStatic;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.yaml.snakeyaml.Yaml;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.I18N;

public class ScriptJobUnitTest extends TestUtils {

    private static ExtensionLoader extensionLoader;
    private static MockedStatic<CommandLine> mockedCmdLine;
    private ExtensionScript extScript;
    private AutomationEnvironment env;
    private AutomationProgress progress;

    @BeforeAll
    static void setUpAll() {
        Constant.messages = new I18N(Locale.ENGLISH);
        mockedCmdLine = mockStatic(CommandLine.class);
        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
        extensionLoader = mock(ExtensionLoader.class, withSettings().lenient());
        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
    }

    @AfterAll
    static void close() {
        mockedCmdLine.close();
    }

    @BeforeEach
    void setUpEach() {
        extScript = mock(ExtensionScript.class);
        given(extensionLoader.getExtension(ExtensionScript.class)).willReturn(extScript);
        progress = new AutomationProgress();
        env = new AutomationEnvironment(progress);
    }

    @Test
    void shouldFailIfNoConfigs() {
        // Given
        ScriptJob job = new ScriptJob();

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors(), contains("!scripts.automation.error.actionNull!"));
    }

    @Test
    void shouldFailIfActionNull() {
        // Given
        ScriptJob job = new ScriptJob();
        String yamlStr = String.join("\n", "parameters:");
        setJobData(job, yamlStr);

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors(), contains("!scripts.automation.error.actionNull!"));
    }

    @Test
    void shouldFailIfActionNotFound() {
        // Given
        ScriptJob job = new ScriptJob();
        String yamlStr = String.join("\n", "parameters:", "  action: noAction");
        setJobData(job, yamlStr);

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors(), contains("!scripts.automation.error.actionNotDefined!"));
    }

    @Test
    void shouldFailToRunIfScriptTypeIsNull() {
        // Given
        ScriptJob job = new ScriptJob();
        String yamlStr = String.join("\n", "parameters:", "  action: RuN");
        setJobData(job, yamlStr);

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors(), contains("!scripts.automation.error.scriptTypeIsNull!"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "-", "UNKNOWN"})
    void shouldFailToRunIfScriptTypeIsUnknown(String scriptType) {
        // Given
        ScriptJob job = new ScriptJob();
        String yamlStr =
                String.join("\n", "parameters:", "  action: RuN", "  type: \"" + scriptType + "\"");
        setJobData(job, yamlStr);

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(
                progress.getErrors(),
                contains("!scripts.automation.error.scriptTypeNotSupported!"));
    }

    @Test
    void shouldFailToRunIfScriptIsNull() {
        // Given
        ScriptJob job = new ScriptJob();
        String yamlStr =
                String.join("\n", "parameters:", "  action: RuN", "  type: \"standalone\"");
        setJobData(job, yamlStr);

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors(), contains("!scripts.automation.error.scriptNameNotFound!"));
    }

    @Test
    void shouldFailToRunIfScriptNotFound() {
        // Given
        ScriptJob job = new ScriptJob();
        String yamlStr =
                String.join(
                        "\n",
                        "parameters:",
                        "  action: RuN",
                        "  type: \"standalone\"",
                        "  name: NotExisting");
        setJobData(job, yamlStr);

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors(), contains("!scripts.automation.error.scriptNameNotFound!"));
    }

    @Test
    void shouldSucceedIfScriptFound() {
        // Given
        ScriptJob job = new ScriptJob();
        String yamlStr =
                String.join(
                        "\n",
                        "parameters:",
                        "  action: RuN",
                        "  type: \"standalone\"",
                        "  name: myScript");
        setJobData(job, yamlStr);
        ScriptWrapper scriptWrapper = mock(ScriptWrapper.class);
        when(scriptWrapper.getName()).thenReturn("myScript");
        when(extScript.getScripts(ExtensionScript.TYPE_STANDALONE))
                .thenReturn(Arrays.asList(scriptWrapper));

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldExecuteIfScriptFound() throws Exception {
        // Given
        ScriptJob job = new ScriptJob();
        String yamlStr =
                String.join(
                        "\n",
                        "parameters:",
                        "  action: RuN",
                        "  type: \"standalone\"",
                        "  name: myScript");
        setJobData(job, yamlStr);
        ScriptWrapper scriptWrapper = mock(ScriptWrapper.class);
        when(scriptWrapper.getName()).thenReturn("myScript");
        when(extScript.getScripts(ExtensionScript.TYPE_STANDALONE))
                .thenReturn(Arrays.asList(scriptWrapper));

        // When
        job.verifyParameters(progress);
        job.applyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        verify(extScript, times(1)).invokeScript(scriptWrapper);
    }

    @Test
    void shouldCreateMinTemplateFile() throws Exception {
        // Given
        ExtensionAutomation extAuto = new ExtensionAutomation();
        extAuto.registerAutomationJob(new ScriptJob());

        // When
        File f = File.createTempFile("ZAP-min-template-test", ".yaml");
        extAuto.generateTemplateFile(f.getAbsolutePath(), false);
        String generatedTemplate = new String(Files.readAllBytes(f.toPath()));

        // Then
        assertThat(
                generatedTemplate,
                stringContainsInOrder("- type: script", "action:", "type:", "name:"));
    }

    @Test
    void shouldCreateMaxTemplateFile() throws Exception {
        // Given
        ExtensionAutomation extAuto = new ExtensionAutomation();
        extAuto.registerAutomationJob(new ScriptJob());

        // When
        File f = File.createTempFile("ZAP-max-template-test", ".yaml");
        extAuto.generateTemplateFile(f.getAbsolutePath(), true);
        String generatedTemplate = new String(Files.readAllBytes(f.toPath()));

        // Then
        assertThat(
                generatedTemplate,
                stringContainsInOrder("- type: script", "action:", "type:", "name:"));
    }

    private ScriptJob setJobData(ScriptJob job, String yamlStr) {
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);
        job.setJobData((LinkedHashMap<?, ?>) data);
        return job;
    }
}
