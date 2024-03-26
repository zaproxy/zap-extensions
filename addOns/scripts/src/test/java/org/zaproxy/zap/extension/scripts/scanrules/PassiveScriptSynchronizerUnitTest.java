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
package org.zaproxy.zap.extension.scripts.scanrules;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.lang.reflect.UndeclaredThrowableException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.PluginFactory;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata;
import org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadataProvider;
import org.zaproxy.zap.extension.pscan.ExtensionPassiveScan;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.testutils.TestUtils;

public class PassiveScriptSynchronizerUnitTest extends TestUtils {

    private ExtensionPassiveScan extensionPassiveScan;
    private ExtensionScript extensionScript;
    private ExtensionLoader extensionLoader;
    private Model model;

    @BeforeEach
    void setUp() throws Exception {
        setUpZap();
        extensionPassiveScan = mock(ExtensionPassiveScan.class);
        extensionScript = mock(ExtensionScript.class);
        extensionLoader = mock(ExtensionLoader.class);
        model = mock(Model.class);
        Model.setSingletonForTesting(model);
        Control.initSingletonForTesting(model, extensionLoader);
    }

    @Test
    @SuppressWarnings("try")
    void shouldLoadPassiveScanRuleForScript() throws Exception {
        // Given
        var synchronizer = new PassiveScriptSynchronizer();
        var metadata = new ScanRuleMetadata(12345, "Test Scan Rule");
        var metadataProvider =
                new ScanRuleMetadataProvider() {
                    @Override
                    public ScanRuleMetadata getMetadata() {
                        return metadata;
                    }
                };
        ScriptWrapper script =
                createScriptWrapper(metadataProvider, ScanRuleMetadataProvider.class);
        var scanRuleCaptor = ArgumentCaptor.forClass(PassiveScriptScanRule.class);
        given(extensionPassiveScan.addPluginPassiveScanner(any())).willReturn(true);
        // When
        try (var ignored = mockStatic(PluginFactory.class)) {
            synchronizer.scriptAdded(script);
        }
        // Then
        verify(extensionPassiveScan, times(1)).addPluginPassiveScanner(scanRuleCaptor.capture());
        PassiveScriptScanRule scanRule = scanRuleCaptor.getValue();
        assertThat(scanRule, is(notNullValue()));
        assertThat(scanRule.getPluginId(), is(equalTo(metadata.getId())));
        assertThat(scanRule.getName(), is(equalTo(metadata.getName())));
    }

    @Test
    @SuppressWarnings("try")
    void shouldNotLoadSameScriptTwice() throws Exception {
        // Given
        var synchronizer = new PassiveScriptSynchronizer();
        var metadata = new ScanRuleMetadata(12345, "Test Scan Rule");
        var metadataProvider =
                new ScanRuleMetadataProvider() {
                    @Override
                    public ScanRuleMetadata getMetadata() {
                        return metadata;
                    }
                };
        ScriptWrapper script =
                createScriptWrapper(metadataProvider, ScanRuleMetadataProvider.class);
        given(extensionPassiveScan.addPluginPassiveScanner(any())).willReturn(true);
        // When
        try (var ignored = mockStatic(PluginFactory.class)) {
            synchronizer.scriptAdded(script);
            synchronizer.scriptAdded(script);
        }
        // Then
        var scanRuleCaptor = ArgumentCaptor.forClass(PassiveScriptScanRule.class);
        verify(extensionPassiveScan, times(1)).addPluginPassiveScanner(scanRuleCaptor.capture());
        PassiveScriptScanRule scanRule = scanRuleCaptor.getValue();
        assertThat(scanRule, is(notNullValue()));
        assertThat(scanRule.getPluginId(), is(equalTo(metadata.getId())));
        assertThat(scanRule.getName(), is(equalTo(metadata.getName())));
    }

    @Test
    @SuppressWarnings("try")
    void shouldUnloadPassiveScanRuleForScript() throws Exception {
        // Given
        var synchronizer = new PassiveScriptSynchronizer();
        var metadata = new ScanRuleMetadata(12345, "Test Scan Rule");
        var metadataProvider =
                new ScanRuleMetadataProvider() {
                    @Override
                    public ScanRuleMetadata getMetadata() {
                        return metadata;
                    }
                };
        given(extensionPassiveScan.addPluginPassiveScanner(any())).willReturn(true);
        ScriptWrapper script =
                createScriptWrapper(metadataProvider, ScanRuleMetadataProvider.class);
        // When
        try (var ignored = mockStatic(PluginFactory.class)) {
            synchronizer.scriptAdded(script);
            synchronizer.scriptRemoved(script);
        }
        // Then
        var scanRuleCaptor = ArgumentCaptor.forClass(PassiveScriptScanRule.class);
        verify(extensionPassiveScan, times(1)).removePluginPassiveScanner(scanRuleCaptor.capture());
        PassiveScriptScanRule scanRule = scanRuleCaptor.getValue();
        assertThat(scanRule, is(notNullValue()));
        assertThat(scanRule.getPluginId(), is(equalTo(metadata.getId())));
        assertThat(scanRule.getName(), is(equalTo(metadata.getName())));
    }

    @Test
    void shouldNotLogErrorOnUndeclaredMethodInPythonScripts() throws Exception {
        // Given
        var synchronizer = new PassiveScriptSynchronizer();
        var metadataProvider =
                new ScanRuleMetadataProvider() {
                    @Override
                    public ScanRuleMetadata getMetadata() {
                        throw new UndeclaredThrowableException(null, "getMetadata");
                    }
                };
        var script = mock(ScriptWrapper.class);
        given(extensionLoader.getExtension(ExtensionScript.class)).willReturn(extensionScript);
        given(extensionScript.getInterface(script, ScanRuleMetadataProvider.class))
                .willReturn(metadataProvider);
        // When
        synchronizer.scriptAdded(script);
        // Then
        verify(extensionScript, times(0)).handleScriptException(eq(script), any());
    }

    private <T> ScriptWrapper createScriptWrapper(T scriptInterface, Class<T> scriptClass)
            throws Exception {
        var script = mock(ScriptWrapper.class);
        given(extensionLoader.getExtension(ExtensionScript.class)).willReturn(extensionScript);
        given(extensionLoader.getExtension(ExtensionPassiveScan.class))
                .willReturn(extensionPassiveScan);
        given(extensionScript.getInterface(script, scriptClass)).willReturn(scriptInterface);
        return script;
    }
}
