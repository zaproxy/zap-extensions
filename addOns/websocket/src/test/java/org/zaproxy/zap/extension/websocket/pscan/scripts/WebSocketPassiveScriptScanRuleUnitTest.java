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

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.pscan.WebSocketScanHelper;
import org.zaproxy.zap.testutils.WebSocketTestUtils;
import org.zaproxy.zap.utils.I18N;

class WebSocketPassiveScriptScanRuleUnitTest extends WebSocketTestUtils {

    @Override
    protected void setUpMessages() {
        I18N i18n = mock(I18N.class, withSettings().strictness(Strictness.LENIENT));
        lenient().when(i18n.getString(anyString())).thenReturn("");
        lenient().when(i18n.getString(anyString(), any())).thenReturn("");
        Constant.messages = i18n;
    }

    private ExtensionScript extensionScript;
    private ScriptWrapper script;
    private WebSocketPassiveScript scriptInterface;
    private WebSocketPassiveScriptScanRule rule;
    private WebSocketScanHelper helper;
    private WebSocketMessageDTO message;

    @BeforeEach
    void setUp() throws Exception {
        super.setUpZap();
        ExtensionLoader loader = mock(ExtensionLoader.class);
        Control.initSingletonForTesting(Model.getSingleton(), loader);
        extensionScript = mock(ExtensionScript.class);
        lenient().when(loader.getExtension(ExtensionScript.class)).thenReturn(extensionScript);

        script = mock(ScriptWrapper.class);
        scriptInterface = mock(WebSocketPassiveScript.class);

        rule = new WebSocketPassiveScriptScanRule(script, new ScanRuleMetadata(1, "Test Rule"));
        helper = mock(WebSocketScanHelper.class);
        message = mock(WebSocketMessageDTO.class);
    }

    @Test
    void shouldSkipScanWhenScriptDisabled() throws Exception {
        // Given
        when(script.isEnabled()).thenReturn(false);

        // When
        rule.scanMessage(helper, message);

        // Then — the script tree's own enabled flag is honoured, independent of any GSPM/manager
        // level enabled state (which is checked separately, before scanMessage is even called)
        verify(scriptInterface, never()).scan(any(), any());
    }

    @Test
    void shouldRunScanWhenScriptEnabled() throws Exception {
        // Given
        when(script.isEnabled()).thenReturn(true);
        when(extensionScript.getInterface(script, WebSocketPassiveScript.class))
                .thenReturn(scriptInterface);

        // When
        rule.scanMessage(helper, message);

        // Then
        verify(scriptInterface).scan(eq(helper), eq(message));
        verify(extensionScript, never()).handleScriptException(any(), any());
    }
}
