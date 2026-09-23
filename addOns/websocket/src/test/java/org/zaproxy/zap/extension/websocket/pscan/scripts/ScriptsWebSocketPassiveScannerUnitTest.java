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
package org.zaproxy.zap.extension.websocket.pscan.scripts;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.script.ScriptsCache;
import org.zaproxy.zap.extension.script.ScriptsCache.Configuration;
import org.zaproxy.zap.extension.script.ScriptsCache.InterfaceProvider;

/**
 * Unit test for {@link ScriptsWebSocketPassiveScanner}, focused on the interface provider's
 * exclusion logic — verified directly against the {@link Configuration} passed to {@link
 * ExtensionScript#createScriptsCache(Configuration)}, without exercising the real {@link
 * ScriptsCache}.
 */
class ScriptsWebSocketPassiveScannerUnitTest {

    private ExtensionScript extensionScript;
    private WebSocketScriptSynchronizer scriptSynchronizer;
    private InterfaceProvider<WebSocketPassiveScript> interfaceProvider;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        extensionScript = mock(ExtensionScript.class);
        scriptSynchronizer = mock(WebSocketScriptSynchronizer.class);

        new ScriptsWebSocketPassiveScanner(extensionScript, scriptSynchronizer);

        ArgumentCaptor<Configuration<WebSocketPassiveScript>> configCaptor =
                ArgumentCaptor.forClass(Configuration.class);
        verify(extensionScript).createScriptsCache(configCaptor.capture());
        interfaceProvider = configCaptor.getValue().getInterfaceProvider();
    }

    @Test
    void shouldExcludeScriptWithSuccessfullySynchronizedRule() throws Exception {
        // Given
        ScriptWrapper script = mock(ScriptWrapper.class);
        given(scriptSynchronizer.isSynchronized(script)).willReturn(true);

        // When
        WebSocketPassiveScript result =
                interfaceProvider.getInterface(script, WebSocketPassiveScript.class);

        // Then
        assertThat(result, is(nullValue()));
        verify(extensionScript, never()).getInterface(any(), any());
    }

    @Test
    void shouldNotExcludeScriptThatFailedToSynchronize() throws Exception {
        // Given — e.g. the script declares metadata but its own rule failed to install (clashing
        // id); it must still run somewhere rather than being silently dropped.
        ScriptWrapper script = mock(ScriptWrapper.class);
        given(scriptSynchronizer.isSynchronized(script)).willReturn(false);
        WebSocketPassiveScript scriptInterface = mock(WebSocketPassiveScript.class);
        given(extensionScript.getInterface(script, WebSocketPassiveScript.class))
                .willReturn(scriptInterface);

        // When
        WebSocketPassiveScript result =
                interfaceProvider.getInterface(script, WebSocketPassiveScript.class);

        // Then
        assertThat(result, is(notNullValue()));
    }
}
