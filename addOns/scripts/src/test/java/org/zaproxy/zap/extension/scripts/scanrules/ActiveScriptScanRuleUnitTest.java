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

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.util.List;
import org.apache.commons.configuration.BaseConfiguration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.HostProcess;
import org.parosproxy.paros.core.scanner.NameValuePair;
import org.parosproxy.paros.core.scanner.ScannerParam;
import org.parosproxy.paros.core.scanner.Variant;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata;
import org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadataProvider;
import org.zaproxy.zap.extension.ascan.VariantFactory;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.testutils.TestUtils;

public class ActiveScriptScanRuleUnitTest extends TestUtils {

    private ExtensionScript extensionScript;
    private ExtensionLoader extensionLoader;
    private Model model;
    private HostProcess parent;
    private HttpMessage message;

    @BeforeEach
    void setUp() throws Exception {
        setUpZap();
        extensionScript = mock(ExtensionScript.class);
        extensionLoader = mock(ExtensionLoader.class);
        parent = mock(HostProcess.class);
        message = new HttpMessage(new HttpRequestHeader("GET / HTTP/1.1"));
        model = mock(Model.class);
        Model.setSingletonForTesting(model);
        Control.initSingletonForTesting(model, extensionLoader);
    }

    @Test
    void shouldScanNodesWithActiveScript2() throws Exception {
        // Given
        ActiveScript2 scriptActiveInterface = mock(ActiveScript2.class);
        ScriptWrapper script = createScriptWrapper(scriptActiveInterface, ActiveScript2.class);
        VariantFactory variantFactory = mock(VariantFactory.class);
        given(variantFactory.createVariants(any(), any())).willReturn(List.of(mock(Variant.class)));
        given(model.getVariantFactory()).willReturn(variantFactory);
        var metadata = new ScanRuleMetadata(12345, "Test Scan Rule");
        var scanRule = new ActiveScriptScanRule(script, metadata);
        scanRule.init(message, parent);
        // When
        scanRule.scan();
        // Then
        verify(scriptActiveInterface, times(1)).scanNode(scanRule, message);
    }

    @Test
    void shouldScanParamsWithActiveScript() throws Exception {
        // Given
        ActiveScript scriptActiveInterface = mock(ActiveScript.class);
        ScriptWrapper script = createScriptWrapper(scriptActiveInterface, ActiveScript.class);
        given(parent.getScannerParam()).willReturn(mock(ScannerParam.class));
        String name1 = "Name1";
        String value1 = "Value1";
        NameValuePair param1 = param(name1, value1);
        String name2 = "Name2";
        String value2 = "Value2";
        NameValuePair param2 = param(name2, value2);
        Variant variant = mock(Variant.class);
        given(variant.getParamList()).willReturn(List.of(param1, param2));
        VariantFactory variantFactory = mock(VariantFactory.class);
        given(variantFactory.createVariants(any(), any())).willReturn(List.of(variant));
        given(model.getVariantFactory()).willReturn(variantFactory);
        var metadata = new ScanRuleMetadata(12345, "Test Scan Rule");
        var scanRule = new ActiveScriptScanRule(script, metadata);
        scanRule.init(message, parent);
        // When
        scanRule.scan();
        // Then
        verify(scriptActiveInterface, times(1)).scan(scanRule, message, name1, value1);
        verify(scriptActiveInterface, times(1)).scan(scanRule, message, name2, value2);
    }

    @Test
    void shouldScanWithCopyCreatedWithReflectionAndConfig() throws Exception {
        // Given
        ActiveScript2 scriptActiveInterface = mock(ActiveScript2.class);
        var script = mock(ScriptWrapper.class);
        var metadata = new ScanRuleMetadata(12345, "Test Scan Rule");
        var metadataProvider =
                new ScanRuleMetadataProvider() {
                    @Override
                    public ScanRuleMetadata getMetadata() {
                        return metadata;
                    }
                };
        String scriptName = "testScript.js";
        given(script.getName()).willReturn("testScript.js");
        given(script.isEnabled()).willReturn(true);
        given(extensionLoader.getExtension(ExtensionScript.class)).willReturn(extensionScript);
        given(extensionScript.getInterface(script, ActiveScript2.class))
                .willReturn(scriptActiveInterface);
        given(extensionScript.getInterface(script, ScanRuleMetadataProvider.class))
                .willReturn(metadataProvider);
        given(extensionScript.getScript(scriptName)).willReturn(script);
        VariantFactory variantFactory = mock(VariantFactory.class);
        given(variantFactory.createVariants(any(), any())).willReturn(List.of(mock(Variant.class)));
        given(model.getVariantFactory()).willReturn(variantFactory);
        var scanRule = new ActiveScriptScanRule(script, metadata);
        scanRule.setConfig(new BaseConfiguration());
        var scanRuleCopy = scanRule.getClass().getDeclaredConstructor().newInstance();
        scanRuleCopy.setConfig(scanRule.getConfig());
        scanRuleCopy.init(message, parent);
        // When
        scanRuleCopy.scan();
        // Then
        verify(scriptActiveInterface, times(1)).scanNode(scanRule, message);
    }

    private <T> ScriptWrapper createScriptWrapper(T scriptInterface, Class<T> scriptClass)
            throws Exception {
        var script = mock(ScriptWrapper.class);
        given(extensionLoader.getExtension(ExtensionScript.class)).willReturn(extensionScript);
        given(extensionScript.getInterface(script, scriptClass)).willReturn(scriptInterface);
        given(script.isEnabled()).willReturn(true);
        return script;
    }

    private static NameValuePair param(String name, String value) {
        NameValuePair nvp = mock(NameValuePair.class);
        given(nvp.getName()).willReturn(name);
        given(nvp.getValue()).willReturn(value);
        return nvp;
    }
}
