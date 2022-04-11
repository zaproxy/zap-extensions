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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Locale;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
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
import org.zaproxy.zap.extension.script.ScriptEngineWrapper;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.I18N;

class ScriptJobUnitTest extends TestUtils {

    private static ExtensionLoader extensionLoader;
    private static MockedStatic<CommandLine> mockedCmdLine;
    private static final String TEST_JS_ENGINE = "TestJsEngine";
    private ExtensionScript extScript;
    private AutomationEnvironment env;
    private AutomationProgress progress;
    private ScriptEngineWrapper engineWrapper;

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
        engineWrapper = mock(ScriptEngineWrapper.class);
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
        assertThat(progress.hasWarnings(), is(equalTo(false)));
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
        assertThat(progress.hasWarnings(), is(equalTo(false)));
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
        assertThat(progress.hasWarnings(), is(equalTo(false)));
    }

    @Test
    void shouldFailToRunIfScriptTypeIsNull() {
        // Given
        ScriptJob job = new ScriptJob();
        String yamlStr = String.join("\n", "parameters:", "  name: test", "  action: RuN");
        setJobData(job, yamlStr);

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors(), contains("!scripts.automation.error.scriptTypeIsNull!"));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
    }

    @ParameterizedTest
    @CsvSource({"RuN,", "Run,-", "ruN,UNKNOWN"})
    void shouldFailToRunIfScriptTypeIsUnknown(String action, String scriptType) {
        // Given
        ScriptJob job = new ScriptJob();
        String yamlStr =
                String.join(
                        "\n",
                        "parameters:",
                        "  action: " + action,
                        "  name: test",
                        "  type: \"" + scriptType + "\"");
        setJobData(job, yamlStr);

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(
                progress.getErrors(),
                contains("!scripts.automation.error.scriptTypeNotSupported!"));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"Remove", "Run"})
    void shouldFailToRunJobIfScriptIsNull(String action) {
        // Given
        ScriptJob job = new ScriptJob();
        String yamlStr =
                String.join("\n", "parameters:", "  action: " + action, "  type: \"standalone\"");
        setJobData(job, yamlStr);

        // When
        job.verifyParameters(progress);
        job.applyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(
                progress.getErrors(),
                contains(
                        "!scripts.automation.error.scriptNameIsNull!",
                        "!scripts.automation.error.scriptNameNotFound!"));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"Remove", "Run"})
    void shouldFailToRunJobIfScriptIsEmpty(String action) {
        // Given
        ScriptJob job = new ScriptJob();
        String yamlStr =
                String.join(
                        "\n",
                        "parameters:",
                        "  action: " + action,
                        "  type: \"standalone\"",
                        "  name: \"\"");
        setJobData(job, yamlStr);

        // When
        job.verifyParameters(progress);
        job.applyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(
                progress.getErrors(),
                contains(
                        "!scripts.automation.error.scriptNameIsNull!",
                        "!scripts.automation.error.scriptNameNotFound!"));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
    }

    @Test
    void shouldFailToRunIfScriptNotFound() {
        // Given
        ScriptJob job = new ScriptJob();
        String yamlStr =
                String.join(
                        "\n",
                        "parameters:",
                        "  action: RUN",
                        "  type: \"standalone\"",
                        "  name: NotExisting");
        setJobData(job, yamlStr);

        // When
        job.verifyParameters(progress);
        job.applyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors(), contains("!scripts.automation.error.scriptNameNotFound!"));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
    }

    @Test
    void shouldFailToRunTargetedScriptIfNoEngineFound() {
        // Given
        given(extScript.getEngineWrapper(null)).willReturn(null);

        ScriptJob job = new ScriptJob();
        String yamlStr =
                String.join(
                        "\n",
                        "parameters:",
                        "  action: run",
                        "  type: \"targeted\"",
                        "  name: NotExisting",
                        "  target: https://testurl.com");
        setJobData(job, yamlStr);

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), equalTo(1));
        assertThat(
                progress.getErrors(), contains("!scripts.automation.error.scriptEngineNotFound!"));
    }

    @Test
    void shouldFailToRunTargetedScriptIfTargetIsNull() {
        // Given
        given(extScript.getEngineWrapper(TEST_JS_ENGINE)).willReturn(engineWrapper);

        ScriptJob job = new ScriptJob();
        String yamlStr =
                String.join(
                        "\n",
                        "parameters:",
                        "  action: run",
                        "  type: \"targeted\"",
                        "  engine: " + TEST_JS_ENGINE,
                        "  name: NotExisting");
        setJobData(job, yamlStr);

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), equalTo(1));
        assertThat(progress.getErrors(), contains("!scripts.automation.error.scriptTargetIsNull!"));
    }

    @Test
    void shouldFailToRemoveIfScriptNotFound() {
        // Given
        ScriptJob job = new ScriptJob();
        String yamlStr =
                String.join(
                        "\n",
                        "parameters:",
                        "  action: REMOVE",
                        "  type: \"standalone\"",
                        "  name: NotExisting");
        setJobData(job, yamlStr);

        // When
        job.verifyParameters(progress);
        job.applyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors(), contains("!scripts.automation.error.scriptNameNotFound!"));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
    }

    @Test
    void shouldSucceedIfRunScriptFound() {
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

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
    }

    @Test
    void shouldWarnIfRunFileSpecified() {
        // Given
        ScriptJob job = new ScriptJob();
        String yamlStr =
                String.join(
                        "\n",
                        "parameters:",
                        "  action: run",
                        "  type: \"standalone\"",
                        "  name: myScript",
                        "  file: notNeeded");
        setJobData(job, yamlStr);

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.getWarnings().size(), equalTo(1));
        assertThat(progress.getWarnings(), contains("!scripts.automation.warn.fileNotNeeded!"));
    }

    @Test
    void shouldWarnIfRemoveFileSpecified() {
        // Given
        ScriptJob job = new ScriptJob();
        String yamlStr =
                String.join(
                        "\n",
                        "parameters:",
                        "  action: remove",
                        "  type: \"standalone\"",
                        "  name: myScript",
                        "  file: notNeeded");
        setJobData(job, yamlStr);

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.getWarnings().size(), equalTo(1));
        assertThat(progress.getWarnings(), contains("!scripts.automation.warn.fileNotNeeded!"));
    }

    @Test
    void shouldExecuteIfRunScriptFound() throws Exception {
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
        when(extScript.getScript("myScript")).thenReturn(scriptWrapper);

        // When
        job.verifyParameters(progress);
        job.applyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        verify(extScript, times(1)).invokeScript(scriptWrapper);
    }

    @Test
    void shouldExecuteIfRemoveScriptFound() throws Exception {
        // Given
        ScriptJob job = new ScriptJob();
        String yamlStr =
                String.join(
                        "\n",
                        "parameters:",
                        "  action: removE",
                        "  type: \"standalone\"",
                        "  name: myScript");
        setJobData(job, yamlStr);
        ScriptWrapper scriptWrapper = mock(ScriptWrapper.class);
        when(extScript.getScript("myScript")).thenReturn(scriptWrapper);

        // When
        job.verifyParameters(progress);
        job.applyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        verify(extScript, times(1)).removeScript(scriptWrapper);
        assertThat(progress.hasWarnings(), is(equalTo(false)));
    }

    @Test
    void shouldFailToAddIfNoType() throws IOException {
        // Given
        given(extScript.getEngineWrapper(TEST_JS_ENGINE)).willReturn(engineWrapper);

        ScriptJob job = new ScriptJob();
        File f = File.createTempFile("scriptFileNoType", ".js");
        String yamlStr =
                String.join(
                        "\n",
                        "parameters:",
                        "  action: add",
                        "  engine: " + TEST_JS_ENGINE,
                        "  name: NotExisting",
                        "  file: " + f.getAbsolutePath());
        setJobData(job, yamlStr);

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), equalTo(1));
        assertThat(progress.getErrors(), contains("!scripts.automation.error.scriptTypeIsNull!"));
    }

    @Test
    void shouldFailToAddIfUnknownType() throws IOException {
        // Given
        given(extScript.getEngineWrapper(TEST_JS_ENGINE)).willReturn(engineWrapper);

        ScriptJob job = new ScriptJob();
        File f = File.createTempFile("scriptFileNoType", ".js");
        String yamlStr =
                String.join(
                        "\n",
                        "parameters:",
                        "  action: add",
                        "  type: \"unknown\"",
                        "  engine: " + TEST_JS_ENGINE,
                        "  name: NotExisting",
                        "  file: " + f.getAbsolutePath());
        setJobData(job, yamlStr);

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), equalTo(1));
        assertThat(
                progress.getErrors(),
                contains("!scripts.automation.error.scriptTypeNotSupported!"));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
    }

    @Test
    void shouldFailToAddIfNoFile() throws IOException {
        // Given
        given(extScript.getEngineWrapper(TEST_JS_ENGINE)).willReturn(engineWrapper);
        Collection<ScriptType> types =
                new ArrayList<>(Arrays.asList(new ScriptType("standalone", null, null, false)));
        given(extScript.getScriptTypes()).willReturn(types);

        ScriptJob job = new ScriptJob();
        String yamlStr =
                String.join(
                        "\n",
                        "parameters:",
                        "  action: add",
                        "  type: \"standalone\"",
                        "  engine: " + TEST_JS_ENGINE,
                        "  name: NotExisting");
        setJobData(job, yamlStr);

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), equalTo(1));
        assertThat(progress.getErrors(), contains("!scripts.automation.error.file.missing!"));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
    }

    @Test
    void shouldFailToAddIfFileNotReadable() throws IOException {
        // Given
        given(extScript.getEngineWrapper(TEST_JS_ENGINE)).willReturn(engineWrapper);
        Collection<ScriptType> types =
                new ArrayList<>(Arrays.asList(new ScriptType("standalone", null, null, false)));
        given(extScript.getScriptTypes()).willReturn(types);
        File f = File.createTempFile("scriptFileNoType", ".js");
        f.setReadable(false);

        ScriptJob job = new ScriptJob();
        String yamlStr =
                String.join(
                        "\n",
                        "parameters:",
                        "  action: add",
                        "  type: \"standalone\"",
                        "  engine: " + TEST_JS_ENGINE,
                        "  name: CannotRead",
                        "  file: " + f.getAbsolutePath());
        setJobData(job, yamlStr);

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), equalTo(1));
        assertThat(progress.getErrors(), contains("!scripts.automation.error.file.cannotRead!"));
    }

    @Test
    void shouldFailToAddIfFileIsDir() throws IOException {
        // Given
        given(extScript.getEngineWrapper(TEST_JS_ENGINE)).willReturn(engineWrapper);
        Collection<ScriptType> types =
                new ArrayList<>(Arrays.asList(new ScriptType("standalone", null, null, false)));
        given(extScript.getScriptTypes()).willReturn(types);
        File f = File.createTempFile("scriptFileNoType", ".js");

        ScriptJob job = new ScriptJob();
        String yamlStr =
                String.join(
                        "\n",
                        "parameters:",
                        "  action: add",
                        "  type: \"standalone\"",
                        "  engine: " + TEST_JS_ENGINE,
                        "  name: NotExisting",
                        "  file: " + f.getParent());
        setJobData(job, yamlStr);

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), equalTo(1));
        assertThat(progress.getErrors(), contains("!scripts.automation.error.file.notFile!"));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
    }

    @Test
    void shouldFailToAddIfNoEngineAndUnknownExt() throws IOException {
        // Given
        given(extScript.getEngineWrapper(null)).willReturn(null);
        Collection<ScriptType> types =
                new ArrayList<>(Arrays.asList(new ScriptType("standalone", null, null, false)));
        given(extScript.getScriptTypes()).willReturn(types);

        ScriptJob job = new ScriptJob();
        File f = File.createTempFile("scriptFileNoEngine", "");
        String yamlStr =
                String.join(
                        "\n",
                        "parameters:",
                        "  action: add",
                        "  type: \"standalone\"",
                        "  name: NotExisting",
                        "  file: " + f.getAbsolutePath());
        setJobData(job, yamlStr);

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), equalTo(1));
        assertThat(
                progress.getErrors(), contains("!scripts.automation.error.scriptEngineNotFound!"));
    }

    @Test
    void shouldVerifyAddIfExtOk() throws IOException {
        // Given
        given(extScript.getEngineWrapper(TEST_JS_ENGINE)).willReturn(engineWrapper);
        Collection<ScriptType> types =
                new ArrayList<>(Arrays.asList(new ScriptType("standalone", null, null, false)));
        given(extScript.getScriptTypes()).willReturn(types);

        ScriptJob job = new ScriptJob();
        File f = File.createTempFile("scriptExtOk", ".js");
        String yamlStr =
                String.join(
                        "\n",
                        "parameters:",
                        "  action: add",
                        "  type: \"standalone\"",
                        "  engine: " + TEST_JS_ENGINE,
                        "  name: NotExisting",
                        "  file: " + f.getAbsolutePath());
        setJobData(job, yamlStr);

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
    }

    @Test
    void shouldAddScriptWithGivenName() throws IOException {
        // Given
        given(extScript.getEngineWrapper(TEST_JS_ENGINE)).willReturn(engineWrapper);
        Collection<ScriptType> types =
                new ArrayList<>(Arrays.asList(new ScriptType("standalone", null, null, false)));
        given(extScript.getScriptTypes()).willReturn(types);

        ScriptJob job = new ScriptJob();
        File f = File.createTempFile("scriptExtOk", ".js");
        String yamlStr =
                String.join(
                        "\n",
                        "parameters:",
                        "  action: add",
                        "  type: \"standalone\"",
                        "  engine: " + TEST_JS_ENGINE,
                        "  name: NotExisting",
                        "  file: " + f.getAbsolutePath());
        setJobData(job, yamlStr);
        ArgumentCaptor<ScriptWrapper> argument = ArgumentCaptor.forClass(ScriptWrapper.class);

        // When
        job.verifyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        verify(extScript).addScript(argument.capture());
        assertEquals("NotExisting", argument.getValue().getName());
    }

    @Test
    void shouldAddScriptWithFileName() throws IOException {
        // Given
        given(extScript.getEngineWrapper(TEST_JS_ENGINE)).willReturn(engineWrapper);
        Collection<ScriptType> types =
                new ArrayList<>(Arrays.asList(new ScriptType("standalone", null, null, false)));
        given(extScript.getScriptTypes()).willReturn(types);

        ScriptJob job = new ScriptJob();
        File f = File.createTempFile("scriptExtFileOk", ".js");
        String yamlStr =
                String.join(
                        "\n",
                        "parameters:",
                        "  action: add",
                        "  type: \"standalone\"",
                        "  engine: " + TEST_JS_ENGINE,
                        "  file: " + f.getAbsolutePath());
        setJobData(job, yamlStr);
        ArgumentCaptor<ScriptWrapper> argument = ArgumentCaptor.forClass(ScriptWrapper.class);

        // When
        job.verifyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        verify(extScript).addScript(argument.capture());
        assertEquals(f.getName(), argument.getValue().getName());
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

    @Test
    void shouldFailToEnableIfScriptNameIsNull() {
        // Given
        ScriptJob job = new ScriptJob();
        String yamlStr = String.join("\n", "parameters:", "  action: enable");
        setJobData(job, yamlStr);

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors(), contains("!scripts.automation.error.scriptNameIsNull!"));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
    }

    @Test
    void shouldFailToEnableIfScriptNotFound() {
        // Given
        ScriptJob job = new ScriptJob();
        String yamlStr =
                String.join("\n", "parameters:", "  action: enable", "  name: NotExisting");
        setJobData(job, yamlStr);

        // When
        job.verifyParameters(progress);
        job.applyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors(), contains("!scripts.automation.error.scriptNameNotFound!"));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
    }

    @Test
    void shouldFailToEnableIfScriptIsNotEnableable() {
        // Given
        ScriptJob job = new ScriptJob();
        String yamlStr = String.join("\n", "parameters:", "  action: enable", "  name: myScript");
        setJobData(job, yamlStr);
        ScriptWrapper scriptWrapper = mock(ScriptWrapper.class);
        when(extScript.getScript("myScript")).thenReturn(scriptWrapper);
        when(scriptWrapper.getType()).thenReturn(new ScriptType("standalone", null, null, false));

        // When
        job.verifyParameters(progress);
        job.applyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(
                progress.getErrors(),
                contains("!scripts.automation.error.scriptTypeNotEnableable!"));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
    }

    @Test
    void shouldWarnIfEnableFileSpecified() {
        // Given
        ScriptJob job = new ScriptJob();
        String yamlStr =
                String.join(
                        "\n",
                        "parameters:",
                        "  action: enable",
                        "  name: myScript",
                        "  file: notNeeded");
        setJobData(job, yamlStr);

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.getWarnings().size(), equalTo(1));
        assertThat(progress.getWarnings(), contains("!scripts.automation.warn.fileNotNeeded!"));
    }

    @Test
    void shouldExecuteIfEnableScriptFound() {
        // Given
        ScriptJob job = new ScriptJob();
        String yamlStr = String.join("\n", "parameters:", "  action: enable", "  name: myScript");
        setJobData(job, yamlStr);
        ScriptWrapper scriptWrapper = mock(ScriptWrapper.class);
        when(extScript.getScript("myScript")).thenReturn(scriptWrapper);
        when(scriptWrapper.getType()).thenReturn(new ScriptType("httpsender", null, null, true));

        // When
        job.verifyParameters(progress);
        job.applyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        verify(extScript).setEnabled(scriptWrapper, true);
        assertThat(progress.hasWarnings(), is(equalTo(false)));
    }

    @Test
    void shouldFailToDisableIfScriptNameIsNull() {
        // Given
        ScriptJob job = new ScriptJob();
        String yamlStr = String.join("\n", "parameters:", "  action: disable");
        setJobData(job, yamlStr);

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors(), contains("!scripts.automation.error.scriptNameIsNull!"));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
    }

    @Test
    void shouldFailToDisableIfScriptNotFound() {
        // Given
        ScriptJob job = new ScriptJob();
        String yamlStr =
                String.join("\n", "parameters:", "  action: disable", "  name: NotExisting");
        setJobData(job, yamlStr);

        // When
        job.verifyParameters(progress);
        job.applyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors(), contains("!scripts.automation.error.scriptNameNotFound!"));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
    }

    @Test
    void shouldFailToDisableIfScriptIsNotEnableable() {
        // Given
        ScriptJob job = new ScriptJob();
        String yamlStr = String.join("\n", "parameters:", "  action: disable", "  name: myScript");
        setJobData(job, yamlStr);
        ScriptWrapper scriptWrapper = mock(ScriptWrapper.class);
        when(extScript.getScript("myScript")).thenReturn(scriptWrapper);
        when(scriptWrapper.getType()).thenReturn(new ScriptType("standalone", null, null, false));

        // When
        job.verifyParameters(progress);
        job.applyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(
                progress.getErrors(),
                contains("!scripts.automation.error.scriptTypeNotEnableable!"));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
    }

    @Test
    void shouldWarnIfDisableFileSpecified() {
        // Given
        ScriptJob job = new ScriptJob();
        String yamlStr =
                String.join(
                        "\n",
                        "parameters:",
                        "  action: disable",
                        "  name: myScript",
                        "  file: notNeeded");
        setJobData(job, yamlStr);

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.getWarnings().size(), equalTo(1));
        assertThat(progress.getWarnings(), contains("!scripts.automation.warn.fileNotNeeded!"));
    }

    @Test
    void shouldExecuteIfDisableScriptFound() {
        // Given
        ScriptJob job = new ScriptJob();
        String yamlStr = String.join("\n", "parameters:", "  action: disable", "  name: myScript");
        setJobData(job, yamlStr);
        ScriptWrapper scriptWrapper = mock(ScriptWrapper.class);
        when(extScript.getScript("myScript")).thenReturn(scriptWrapper);
        when(scriptWrapper.getType()).thenReturn(new ScriptType("httpsender", null, null, true));

        // When
        job.verifyParameters(progress);
        job.applyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        verify(extScript).setEnabled(scriptWrapper, false);
        assertThat(progress.hasWarnings(), is(equalTo(false)));
    }

    private ScriptJob setJobData(ScriptJob job, String yamlStr) {
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);
        job.setJobData((LinkedHashMap<?, ?>) data);
        return job;
    }
}
