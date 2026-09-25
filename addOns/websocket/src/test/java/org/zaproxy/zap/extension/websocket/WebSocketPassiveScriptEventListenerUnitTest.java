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
package org.zaproxy.zap.extension.websocket;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.websocket.pscan.scripts.WebSocketScriptSynchronizer;

class WebSocketPassiveScriptEventListenerUnitTest {

    private WebSocketScriptSynchronizer synchronizer;
    private WebSocketPassiveScriptEventListener listener;
    private ScriptWrapper passiveScript;
    private ScriptWrapper otherScript;

    @BeforeEach
    void setUp() {
        synchronizer = mock(WebSocketScriptSynchronizer.class);
        listener = new WebSocketPassiveScriptEventListener(synchronizer);

        passiveScript = mock(ScriptWrapper.class);
        ScriptType passiveType = mock(ScriptType.class);
        when(passiveType.getName()).thenReturn(ExtensionWebSocket.SCRIPT_TYPE_WEBSOCKET_PASSIVE);
        when(passiveScript.getType()).thenReturn(passiveType);

        otherScript = mock(ScriptWrapper.class);
        ScriptType otherType = mock(ScriptType.class);
        when(otherType.getName()).thenReturn(ExtensionWebSocket.SCRIPT_TYPE_WEBSOCKET_SENDER);
        when(otherScript.getType()).thenReturn(otherType);
    }

    @Test
    void shouldSyncOnScriptAdded() {
        listener.scriptAdded(passiveScript, false);
        verify(synchronizer).scriptAdded(passiveScript);
    }

    @Test
    void shouldSyncOnScriptChanged() {
        listener.scriptChanged(passiveScript);
        verify(synchronizer).scriptAdded(passiveScript);
    }

    @Test
    void shouldSyncOnScriptRemoved() {
        listener.scriptRemoved(passiveScript);
        verify(synchronizer).scriptRemoved(passiveScript);
    }

    @Test
    void shouldRefreshMetadataOnScriptSaved() {
        // When
        listener.scriptSaved(passiveScript);

        // Then — saving is the event that content-editing (including metadata/ID changes) is
        // reported through, so it must trigger the same re-sync as scriptChanged
        verify(synchronizer).scriptAdded(passiveScript);
    }

    @Test
    void shouldIgnoreNonWebSocketPassiveScriptsOnSave() {
        listener.scriptSaved(otherScript);
        verify(synchronizer, never()).scriptAdded(otherScript);
    }

    @Test
    void shouldIgnoreNonWebSocketPassiveScriptsOnAdd() {
        listener.scriptAdded(otherScript, false);
        verify(synchronizer, never()).scriptAdded(otherScript);
    }

    @Test
    void shouldIgnoreNonWebSocketPassiveScriptsOnRemove() {
        listener.scriptRemoved(otherScript);
        verify(synchronizer, never()).scriptRemoved(otherScript);
    }
}
