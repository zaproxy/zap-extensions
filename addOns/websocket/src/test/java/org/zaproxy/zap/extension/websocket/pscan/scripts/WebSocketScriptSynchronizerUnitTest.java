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
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import java.lang.reflect.UndeclaredThrowableException;
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata;
import org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadataProvider;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.websocket.pscan.WebSocketPassiveScanner;
import org.zaproxy.zap.extension.websocket.pscan.WebSocketPassiveScannerManager;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.I18N;

class WebSocketScriptSynchronizerUnitTest extends TestUtils {

    private ExtensionScript extensionScript;
    private WebSocketPassiveScannerManager scannerManager;
    private WebSocketScriptSynchronizer synchronizer;

    @BeforeEach
    void setUp() {
        I18N i18n = mock(I18N.class, withSettings().strictness(Strictness.LENIENT));
        given(i18n.getString(anyString(), any())).willReturn("");
        Constant.messages = i18n;
        extensionScript = mock(ExtensionScript.class);
        scannerManager = mock(WebSocketPassiveScannerManager.class);
        synchronizer = new WebSocketScriptSynchronizer(extensionScript, scannerManager);
    }

    @AfterAll
    static void cleanUp() {
        Constant.messages = null;
    }

    @Test
    void shouldLoadScanRuleForScript() throws Exception {
        // Given
        var metadata = new ScanRuleMetadata(12345, "Test Scan Rule");
        ScriptWrapper script = createScriptWrapper(metadata);
        given(scannerManager.add(any())).willReturn(true);

        // When
        synchronizer.scriptAdded(script);

        // Then
        var scanRuleCaptor = ArgumentCaptor.forClass(WebSocketPassiveScriptScanRule.class);
        verify(scannerManager, times(1)).add(scanRuleCaptor.capture());
        WebSocketPassiveScriptScanRule scanRule = scanRuleCaptor.getValue();
        assertThat(scanRule, is(notNullValue()));
        assertThat(scanRule.getId(), is(equalTo(metadata.getId())));
        assertThat(scanRule.getName(), is(equalTo(metadata.getName())));
    }

    @Test
    void shouldNotLoadSameScriptTwice() throws Exception {
        // Given
        var metadata = new ScanRuleMetadata(12345, "Test Scan Rule");
        ScriptWrapper script = createScriptWrapper(metadata);
        given(scannerManager.add(any())).willReturn(true);

        // When
        synchronizer.scriptAdded(script);
        synchronizer.scriptAdded(script);

        // Then
        verify(scannerManager, times(1)).add(any());
    }

    @Test
    void shouldUnloadScanRuleForScript() throws Exception {
        // Given
        var metadata = new ScanRuleMetadata(12345, "Test Scan Rule");
        ScriptWrapper script = createScriptWrapper(metadata);
        given(scannerManager.add(any())).willReturn(true);
        given(scannerManager.removeScanner(any())).willReturn(true);

        // When
        synchronizer.scriptAdded(script);
        synchronizer.scriptRemoved(script);

        // Then
        var scanRuleCaptor = ArgumentCaptor.forClass(WebSocketPassiveScriptScanRule.class);
        verify(scannerManager, times(1)).removeScanner(scanRuleCaptor.capture());
        assertThat(scanRuleCaptor.getValue().getId(), is(equalTo(metadata.getId())));
    }

    @Test
    void shouldUnloadAllScanRulesOnUnload() throws Exception {
        // Given
        var metadata = new ScanRuleMetadata(12345, "Test Scan Rule");
        ScriptWrapper script = createScriptWrapper(metadata);
        given(scannerManager.add(any())).willReturn(true);
        given(scannerManager.removeScanner(any())).willReturn(true);
        synchronizer.scriptAdded(script);

        // When
        synchronizer.unload();

        // Then
        verify(scannerManager, times(1)).removeScanner(any());
    }

    @Test
    void shouldSkipScriptsWithNoMetadata() throws Exception {
        // Given
        var script = mock(ScriptWrapper.class);
        given(extensionScript.getInterface(script, ScanRuleMetadataProvider.class))
                .willReturn(null);

        // When
        synchronizer.scriptAdded(script);

        // Then
        verify(scannerManager, never()).add(any());
    }

    @Test
    void shouldNotLoadScriptWithClashingId() throws Exception {
        // Given
        var metadata = new ScanRuleMetadata(12345, "Test Scan Rule");
        ScriptWrapper script = createScriptWrapper(metadata);
        WebSocketPassiveScanner existing = mock(WebSocketPassiveScanner.class);
        given(existing.getId()).willReturn(12345);
        given(existing.getName()).willReturn("Existing Rule");
        given(scannerManager.getScanners()).willReturn(List.of(existing));

        // When
        synchronizer.scriptAdded(script);

        // Then
        verify(scannerManager, never()).add(any());
        verify(extensionScript).setEnabled(script, false);
    }

    @Test
    void shouldNotLogErrorOnUndeclaredMethodInPythonScripts() throws Exception {
        // Given
        var metadataProvider =
                new ScanRuleMetadataProvider() {
                    @Override
                    public ScanRuleMetadata getMetadata() {
                        throw new UndeclaredThrowableException(null, "getMetadata");
                    }
                };
        var script = mock(ScriptWrapper.class);
        given(extensionScript.getInterface(script, ScanRuleMetadataProvider.class))
                .willReturn(metadataProvider);

        // When
        synchronizer.scriptAdded(script);

        // Then
        verify(extensionScript, times(0)).handleScriptException(eq(script), any());
        verify(scannerManager, never()).add(any());
    }

    private ScriptWrapper createScriptWrapper(ScanRuleMetadata metadata) throws Exception {
        var script = mock(ScriptWrapper.class);
        var metadataProvider =
                new ScanRuleMetadataProvider() {
                    @Override
                    public ScanRuleMetadata getMetadata() {
                        return metadata;
                    }
                };
        given(extensionScript.getInterface(script, ScanRuleMetadataProvider.class))
                .willReturn(metadataProvider);
        return script;
    }
}
