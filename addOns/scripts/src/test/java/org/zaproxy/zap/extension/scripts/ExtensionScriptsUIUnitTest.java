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
package org.zaproxy.zap.extension.scripts;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import javax.script.ScriptException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.proxy.ProxyListener;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.scripts.internal.ProxyListenerScript;
import org.zaproxy.zap.extension.scripts.internal.TargetedScript;
import org.zaproxy.zap.network.HttpSenderListener;
import org.zaproxy.zap.testutils.TestUtils;

class ExtensionScriptsUIUnitTest extends TestUtils {

    private ExtensionLoader extensionLoader;
    private ExtensionScript extScript;
    private ExtensionScriptsUI extensionScriptsUI;

    @BeforeAll
    static void setUpAll() {
        mockMessages(new ExtensionScriptsUI());
    }

    @BeforeEach
    void setUp() {
        extScript = mock(ExtensionScript.class);
        extensionLoader = mock(ExtensionLoader.class);
        lenient().when(extensionLoader.getExtension(ExtensionScript.NAME)).thenReturn(extScript);
        Control.initSingletonForTesting(mock(Model.class), extensionLoader);
        extensionScriptsUI = new ExtensionScriptsUI();
    }

    @Test
    void shouldExtractMsgFrom1ScriptException() {
        // Given
        ScriptException e = new ScriptException("test");
        // When
        String msg = ExtensionScriptsUI.extractScriptExceptionMessage(e);
        // Then
        assertThat(msg, is(equalTo("test")));
    }

    @Test
    void shouldExtractMsgFromDeeperScriptException() {
        // Given
        ScriptException se = new ScriptException("test");
        RuntimeException re = new RuntimeException("runtime", se);
        Exception e = new RuntimeException("exception", re);
        // When
        String msg = ExtensionScriptsUI.extractScriptExceptionMessage(e);
        // Then
        assertThat(msg, is(equalTo("test")));
    }

    @Test
    void shouldExtractMsgWithNoScriptException() {
        // Given
        RuntimeException re = new RuntimeException("runtime");
        Exception e = new RuntimeException("exception", re);
        // When
        String msg = ExtensionScriptsUI.extractScriptExceptionMessage(e);
        // Then
        assertThat(msg, is(equalTo("java.lang.RuntimeException: exception")));
    }

    @Test
    @Disabled("Requires newer core.")
    void shouldRegisterTypeProxyOnHook() {
        // Given / When
        extensionScriptsUI.hook(mock());
        // Then
        ArgumentCaptor<ScriptType> captor = ArgumentCaptor.captor();
        verify(extScript, atLeastOnce()).registerScriptType(captor.capture());
        assertThat(
                captor.getAllValues().stream()
                        .anyMatch(t -> ExtensionScriptsUI.TYPE_PROXY.equals(t.getName())),
                is(true));
    }

    @Test
    @Disabled("Requires newer core.")
    void shouldRegisterTypeTargetedOnHook() {
        // Given / When
        extensionScriptsUI.hook(mock());
        // Then
        ArgumentCaptor<ScriptType> captor = ArgumentCaptor.captor();
        verify(extScript, atLeastOnce()).registerScriptType(captor.capture());
        assertThat(
                captor.getAllValues().stream()
                        .anyMatch(t -> ExtensionScriptsUI.TYPE_TARGETED.equals(t.getName())),
                is(true));
    }

    @Test
    @Disabled("Requires newer core.")
    void shouldRegisterTypeHttpSenderOnHook() {
        // Given / When
        extensionScriptsUI.hook(mock());
        // Then
        ArgumentCaptor<ScriptType> captor = ArgumentCaptor.captor();
        verify(extScript, atLeastOnce()).registerScriptType(captor.capture());
        assertThat(
                captor.getAllValues().stream()
                        .anyMatch(t -> ExtensionScriptsUI.TYPE_HTTP_SENDER.equals(t.getName())),
                is(true));
    }

    @Test
    @Disabled("Requires newer core.")
    void shouldAddProxyListenerOnHook() {
        // Given
        ExtensionHook extensionHook = mock();
        // When
        extensionScriptsUI.hook(extensionHook);
        // Then
        ArgumentCaptor<ProxyListener> captor = ArgumentCaptor.captor();
        verify(extensionHook).addProxyListener(captor.capture());
        assertThat(captor.getValue(), is(instanceOf(ProxyListenerScript.class)));
    }

    @Test
    @Disabled("Requires newer core.")
    void shouldAddHttpSenderListenerOnHook() {
        // Given
        ExtensionHook extensionHook = mock();
        // When
        extensionScriptsUI.hook(extensionHook);
        // Then
        ArgumentCaptor<HttpSenderListener> captor = ArgumentCaptor.captor();
        verify(extensionHook).addHttpSenderListener(captor.capture());
        assertThat(captor.getValue(), is(instanceOf(HttpSenderListener.class)));
    }

    @Test
    void shouldInvokeTargetedScript() throws Exception {
        // Given
        ScriptWrapper script = mock();
        HttpMessage msg = mock();
        TargetedScript targetedScript = mock();
        given(extScript.getInterface(eq(script), any())).willReturn(targetedScript);
        // When
        extensionScriptsUI.invokeTargetedScript(script, msg);
        // Then
        verify(targetedScript, times(1)).invokeWith(msg);
    }

    @Test
    void shouldHandleFailedTargetedScriptInterface() throws Exception {
        // Given
        ScriptWrapper script = mock();
        HttpMessage msg = mock();
        given(extScript.getInterface(eq(script), any())).willReturn(null);
        // When
        extensionScriptsUI.invokeTargetedScript(script, msg);
        // Then
        verify(extScript, times(1)).handleFailedScriptInterface(eq(script), any(String.class));
    }

    @Test
    void shouldHandleExceptionFromTargetedScript() throws Exception {
        // Given
        ScriptWrapper script = mock();
        HttpMessage msg = mock();
        TargetedScript targetedScript = mock();
        ScriptException exception = mock();
        given(extScript.getInterface(eq(script), any())).willReturn(targetedScript);
        doThrow(exception).when(targetedScript).invokeWith(msg);
        // When
        extensionScriptsUI.invokeTargetedScript(script, msg);
        // Then
        verify(extScript, times(1)).handleScriptException(script, exception);
    }
}
