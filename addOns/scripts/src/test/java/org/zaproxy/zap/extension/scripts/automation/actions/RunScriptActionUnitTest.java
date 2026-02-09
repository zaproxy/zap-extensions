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
package org.zaproxy.zap.extension.scripts.automation.actions;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.SiteMap;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptEngineWrapper;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.scripts.ExtensionScriptsUI;
import org.zaproxy.zap.extension.scripts.automation.ScriptJobParameters;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link RunScriptAction}. */
class RunScriptActionUnitTest extends TestUtils {

    private static final String JOB_NAME = "TestJob";
    private static final String ZEST_ENGINE_NAME = "Mozilla Zest";

    private ExtensionScript extScript;
    private ExtensionLoader extensionLoader;
    private Model model;
    private AutomationProgress progress;
    private AutomationEnvironment env;
    private ScriptJobParameters parameters;
    private RunScriptAction action;

    @BeforeAll
    static void setUpAll() {
        mockMessages(new ExtensionScriptsUI());
    }

    private static String msg(String key, Object... args) {
        return Constant.messages.getString(key, args);
    }

    private static final ScriptWrapper MERGED_CHAIN_SCRIPT =
            createMockZestWrapper("merged-chain-script");
    private static List<ScriptWrapper> capturedChainScripts;
    private static String capturedChainRunName;
    private static int getChainScriptCalls;

    /** Stub for chain tests (no Zest): returns merged chain script wrapper. */
    private static final ExtensionAdaptor ZEST_CHAIN_SCRIPT_STUB =
            new ExtensionAdaptor("ExtensionZest") {
                @SuppressWarnings("unused")
                public ScriptWrapper getChainScript(List<ScriptWrapper> scripts, String runName) {
                    capturedChainScripts = scripts;
                    capturedChainRunName = runName;
                    getChainScriptCalls++;
                    return scripts.isEmpty() ? null : MERGED_CHAIN_SCRIPT;
                }
            };

    @BeforeEach
    void setUp() {
        extScript = mock(ExtensionScript.class);
        extensionLoader = mock(ExtensionLoader.class);
        model = mock(Model.class);
        given(extensionLoader.getExtension(ExtensionScript.class)).willReturn(extScript);
        lenient()
                .when(extensionLoader.getExtension("ExtensionZest"))
                .thenReturn(ZEST_CHAIN_SCRIPT_STUB);
        Model.setSingletonForTesting(model);
        Control.initSingletonForTesting(model, extensionLoader);
        capturedChainScripts = null;
        capturedChainRunName = null;
        getChainScriptCalls = 0;

        progress = new AutomationProgress();
        env = new AutomationEnvironment(progress);
        parameters =
                new ScriptJobParameters(
                        RunScriptAction.NAME,
                        ExtensionScript.TYPE_STANDALONE,
                        null,
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        null);
        action = new RunScriptAction(parameters);
    }

    /** Zest standalone script wrapper for run-action tests. */
    private static ScriptWrapper createMockZestWrapper(String name) {
        ScriptWrapper wrapper = new ScriptWrapper();
        wrapper.setName(name);
        wrapper.setEngineName(ZEST_ENGINE_NAME);
        wrapper.setType(new ScriptType(ExtensionScript.TYPE_STANDALONE, null, null, false));
        return wrapper;
    }

    /** Chain Validation Tests */
    @Test
    void shouldValidateChainWithValidZestStandaloneScripts() {
        // Given
        ScriptWrapper script1 = createMockZestWrapper("script1");
        ScriptWrapper script2 = createMockZestWrapper("script2");
        given(extScript.getScript("script1")).willReturn(script1);
        given(extScript.getScript("script2")).willReturn(script2);

        parameters.setChain(List.of("script1", "script2"));

        // When
        action.runJob(JOB_NAME, env, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldRejectChainWithNonExistentScript() {
        // Given
        ScriptWrapper script1 = createMockZestWrapper("script1");
        given(extScript.getScript("script1")).willReturn(script1);
        given(extScript.getScript("nonExistent")).willReturn(null);

        parameters.setChain(List.of("script1", "nonExistent"));

        // When
        action.runJob(JOB_NAME, env, progress);

        // Then
        assertThat(progress.getErrors(), hasSize(1));
        assertThat(
                progress.getErrors(),
                contains(
                        msg(
                                "scripts.automation.error.chainScriptNotFound",
                                JOB_NAME,
                                "nonExistent")));
    }

    @Test
    void shouldRejectChainWithNonStandaloneScript() {
        // Given
        ScriptWrapper script1 = createMockZestWrapper("script1");
        ScriptWrapper script2 = mock(ScriptWrapper.class);
        lenient().when(script2.getName()).thenReturn("script2");
        lenient().when(script2.getEngineName()).thenReturn(ZEST_ENGINE_NAME);
        lenient().when(script2.getTypeName()).thenReturn("targeted");

        given(extScript.getScript("script1")).willReturn(script1);
        given(extScript.getScript("script2")).willReturn(script2);

        parameters.setChain(List.of("script1", "script2"));

        // When
        action.runJob(JOB_NAME, env, progress);

        // Then
        assertThat(progress.getErrors(), hasSize(1));
        assertThat(
                progress.getErrors(),
                contains(
                        msg(
                                "scripts.automation.error.chainScriptNotZestStandalone",
                                JOB_NAME,
                                "script2")));
    }

    @Test
    void shouldRejectChainWithNonZestScript() {
        // Given
        ScriptWrapper script1 = createMockZestWrapper("script1");
        ScriptWrapper script2 = mock(ScriptWrapper.class);
        lenient().when(script2.getName()).thenReturn("script2");
        lenient().when(script2.getEngineName()).thenReturn("JavaScript");
        lenient().when(script2.getTypeName()).thenReturn(ExtensionScript.TYPE_STANDALONE);

        given(extScript.getScript("script1")).willReturn(script1);
        given(extScript.getScript("script2")).willReturn(script2);

        parameters.setChain(List.of("script1", "script2"));

        // When
        action.runJob(JOB_NAME, env, progress);

        // Then
        assertThat(progress.getErrors(), hasSize(1));
        assertThat(
                progress.getErrors(),
                contains(
                        msg(
                                "scripts.automation.error.chainScriptNotZestStandalone",
                                JOB_NAME,
                                "script2")));
    }

    @Test
    void shouldHandleEmptyChain() {
        // Given
        parameters.setChain(List.of());

        // When
        action.runJob(JOB_NAME, env, progress);

        // Then
        // Empty chain → no name, findScript fails
        assertThat(progress.getErrors(), hasSize(1));
        assertThat(
                progress.getErrors(),
                contains(msg("scripts.automation.error.scriptNameNotFound", JOB_NAME, "")));
    }

    /** Chain Execution Tests (including single-script chain path) */
    @Test
    void shouldExecuteChainWithTwoScripts() throws Exception {
        // Given
        ScriptWrapper script1 = createMockZestWrapper("script1");
        ScriptWrapper script2 = createMockZestWrapper("script2");
        given(extScript.getScript("script1")).willReturn(script1);
        given(extScript.getScript("script2")).willReturn(script2);

        parameters.setChain(List.of("script1", "script2"));

        // When
        action.runJob(JOB_NAME, env, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(getChainScriptCalls, is(equalTo(1)));
        assertThat(capturedChainScripts, contains(script1, script2));
        assertThat(capturedChainRunName, is(equalTo("chain_script1")));
        verify(extScript, times(1)).invokeScript(MERGED_CHAIN_SCRIPT);
    }

    @Test
    void shouldExecuteChainWithThreeScripts() throws Exception {
        // Given
        ScriptWrapper script1 = createMockZestWrapper("script1");
        ScriptWrapper script2 = createMockZestWrapper("script2");
        ScriptWrapper script3 = createMockZestWrapper("script3");
        given(extScript.getScript("script1")).willReturn(script1);
        given(extScript.getScript("script2")).willReturn(script2);
        given(extScript.getScript("script3")).willReturn(script3);

        parameters.setChain(List.of("script1", "script2", "script3"));

        // When
        action.runJob(JOB_NAME, env, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(getChainScriptCalls, is(equalTo(1)));
        assertThat(capturedChainScripts, contains(script1, script2, script3));
        assertThat(capturedChainRunName, is(equalTo("chain_script1")));
        verify(extScript, times(1)).invokeScript(MERGED_CHAIN_SCRIPT);
    }

    @Test
    void shouldReportErrorWhenMergedChainExecutionFails() throws Exception {
        // Given
        ScriptWrapper script1 = createMockZestWrapper("script1");
        ScriptWrapper script2 = createMockZestWrapper("script2");
        ScriptWrapper script3 = createMockZestWrapper("script3");
        given(extScript.getScript("script1")).willReturn(script1);
        given(extScript.getScript("script2")).willReturn(script2);
        given(extScript.getScript("script3")).willReturn(script3);
        when(extScript.invokeScript(MERGED_CHAIN_SCRIPT))
                .thenThrow(new RuntimeException("Script failed"));

        parameters.setChain(List.of("script1", "script2", "script3"));

        // When
        action.runJob(JOB_NAME, env, progress);

        // Then
        assertThat(progress.getErrors(), hasSize(1));
        assertThat(
                progress.getErrors(),
                contains(
                        msg(
                                "scripts.automation.error.chainExecutionFailed",
                                JOB_NAME,
                                "Script failed")));
        assertThat(getChainScriptCalls, is(equalTo(1)));
        assertThat(capturedChainScripts, contains(script1, script2, script3));
        assertThat(capturedChainRunName, is(equalTo("chain_script1")));
        verify(extScript, times(1)).invokeScript(MERGED_CHAIN_SCRIPT);
    }

    @Test
    void shouldExecuteSingleScriptChainViaZestChainPath() throws Exception {
        // Given
        ScriptWrapper script1 = createMockZestWrapper("script1");
        given(extScript.getScript("script1")).willReturn(script1);

        parameters.setName("script1");
        parameters.setChain(List.of("script1"));

        // When
        action.runJob(JOB_NAME, env, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(getChainScriptCalls, is(equalTo(1)));
        assertThat(capturedChainScripts, contains(script1));
        assertThat(capturedChainRunName, is(equalTo("chain_script1")));
        verify(extScript, times(1)).invokeScript(MERGED_CHAIN_SCRIPT);
        verify(extensionLoader, times(1)).getExtension("ExtensionZest");
    }

    /** Targeted Script Execution Tests */
    @Test
    void shouldExecuteTargetedScriptWhenTypeTargetedAndTargetFound() throws Exception {
        // Given
        parameters.setType(ExtensionScript.TYPE_TARGETED);
        parameters.setName("myScript");
        parameters.setTarget("http://example.com/");
        ScriptWrapper script = createMockZestWrapper("myScript");
        given(extScript.getScript("myScript")).willReturn(script);

        HttpMessage httpMessage = new HttpMessage();
        HistoryReference historyRef = mock(HistoryReference.class);
        given(historyRef.getHttpMessage()).willReturn(httpMessage);
        SiteNode siteNode = mock(SiteNode.class);
        given(siteNode.getHistoryReference()).willReturn(historyRef);
        SiteMap siteMap = mock(SiteMap.class);
        given(siteMap.findNode(any(URI.class))).willReturn(siteNode);
        Session session = mock(Session.class);
        given(session.getSiteTree()).willReturn(siteMap);
        given(model.getSession()).willReturn(session);

        // When
        action.runJob(JOB_NAME, env, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
        verify(extScript, times(1)).invokeTargetedScript(script, httpMessage);
    }

    /** Single Script Execution Tests (non-chain) */
    @Test
    void shouldExecuteSingleStandaloneScript() throws Exception {
        // Given
        ScriptWrapper script = createMockZestWrapper("myScript");
        given(extScript.getScript("myScript")).willReturn(script);

        parameters.setName("myScript");

        // When
        action.runJob(JOB_NAME, env, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
        verify(extScript, times(1)).invokeScript(script);
    }

    @Test
    void shouldReportErrorIfSingleScriptNotFound() {
        // Given
        given(extScript.getScript("nonExistent")).willReturn(null);

        parameters.setName("nonExistent");

        // When
        action.runJob(JOB_NAME, env, progress);

        // Then
        assertThat(progress.getErrors(), hasSize(1));
        assertThat(
                progress.getErrors(),
                contains(
                        msg(
                                "scripts.automation.error.scriptNameNotFound",
                                JOB_NAME,
                                "nonExistent")));
    }

    /** Chain error and runtime rejection tests */
    @Test
    void shouldHandleReflectionFailureGracefully() {
        // Given
        ScriptWrapper script1 = createMockZestWrapper("script1");
        ScriptWrapper script2 = createMockZestWrapper("script2");
        given(extensionLoader.getExtension("ExtensionZest"))
                .willReturn(new ExtensionAdaptor("ExtensionZest") {});
        given(extScript.getScript("script1")).willReturn(script1);
        given(extScript.getScript("script2")).willReturn(script2);

        parameters.setChain(List.of("script1", "script2"));

        // When
        action.runJob(JOB_NAME, env, progress);

        // Then
        assertThat(progress.getErrors(), hasSize(1));
        assertThat(
                progress.getErrors(),
                contains(
                        msg(
                                "scripts.automation.error.chainReflectionFailed",
                                JOB_NAME,
                                "script1")));
    }

    @Test
    void shouldReportChainReflectionFailedWhenZestNotLoaded() {
        // Given
        given(extensionLoader.getExtension("ExtensionZest")).willReturn(null);
        ScriptWrapper script1 = createMockZestWrapper("script1");
        ScriptWrapper script2 = createMockZestWrapper("script2");
        given(extScript.getScript("script1")).willReturn(script1);
        given(extScript.getScript("script2")).willReturn(script2);
        parameters.setChain(List.of("script1", "script2"));

        // When
        action.runJob(JOB_NAME, env, progress);

        // Then
        assertThat(progress.getErrors(), hasSize(1));
        assertThat(
                progress.getErrors(),
                contains(
                        msg(
                                "scripts.automation.error.chainReflectionFailed",
                                JOB_NAME,
                                "script1")));
    }

    @Test
    void shouldRejectChainAtRuntimeWhenTypeNotStandalone() throws Exception {
        // Given: type targeted + chain set → runScriptChain rejects early
        parameters.setType(ExtensionScript.TYPE_TARGETED);
        parameters.setChain(List.of("script1", "script2"));
        lenient().when(extScript.getScript("script1")).thenReturn(createMockZestWrapper("script1"));
        lenient().when(extScript.getScript("script2")).thenReturn(createMockZestWrapper("script2"));

        // When
        action.runJob(JOB_NAME, env, progress);

        // Then
        assertThat(progress.getErrors(), hasSize(1));
        assertThat(
                progress.getErrors(),
                contains(msg("scripts.automation.error.chainRequiresStandalone", JOB_NAME)));
        verify(extScript, times(0)).invokeScript(any());
    }

    /** Parameter Validation Tests */
    @Test
    void shouldWarnWhenBothNameAndChainSpecified() {
        // Given
        parameters.setName("myScript");
        parameters.setChain(List.of("script1", "script2"));

        // When
        action.verifyParameters(JOB_NAME, parameters, progress);

        // Then
        assertThat(progress.getWarnings(), hasSize(1));
        assertThat(
                progress.getWarnings(),
                contains(msg("scripts.automation.warn.chainAndNameBothSpecified", JOB_NAME)));
    }

    @Test
    void shouldRejectChainWithTargetedScriptType() {
        // Given
        ScriptJobParameters targetedParams =
                new ScriptJobParameters(
                        RunScriptAction.NAME,
                        ExtensionScript.TYPE_TARGETED,
                        ZEST_ENGINE_NAME,
                        "",
                        "",
                        "http://example.com/",
                        "",
                        "",
                        "",
                        null);
        targetedParams.setChain(List.of("script1", "script2"));
        given(extScript.getEngineWrapper(ZEST_ENGINE_NAME))
                .willReturn(mock(ScriptEngineWrapper.class));
        RunScriptAction targetedAction = new RunScriptAction(targetedParams);

        // When
        List<String> issues = targetedAction.verifyParameters(JOB_NAME, targetedParams, progress);

        // Then
        assertThat(progress.getErrors(), hasSize(1));
        assertThat(
                issues, hasItem(msg("scripts.automation.error.chainRequiresStandalone", JOB_NAME)));
    }

    @Test
    void shouldReportOnlyScriptTypeIsNullWhenChainProvidedAndTypeIsNull() {
        // Given
        ScriptJobParameters nullTypeParams =
                new ScriptJobParameters(
                        RunScriptAction.NAME, null, null, "", "", "", "", "", "", null);
        nullTypeParams.setChain(List.of("script1", "script2"));
        RunScriptAction nullTypeAction = new RunScriptAction(nullTypeParams);

        // When
        List<String> issues = nullTypeAction.verifyParameters(JOB_NAME, nullTypeParams, progress);

        // Then
        assertThat(progress.getErrors(), hasSize(1));
        assertThat(
                progress.getErrors(),
                contains(msg("scripts.automation.error.scriptTypeIsNull", JOB_NAME)));
        assertThat(issues, hasSize(1));
        assertThat(issues, hasItem(msg("scripts.automation.error.scriptTypeIsNull", JOB_NAME)));
    }
}
