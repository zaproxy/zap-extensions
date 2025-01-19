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
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import net.htmlparser.jericho.Source;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.commonlib.scanrules.Confidence;
import org.zaproxy.addon.commonlib.scanrules.Risk;
import org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata;
import org.zaproxy.zap.extension.pscan.PassiveScanData;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptEngineWrapper;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.testutils.TestUtils;

public class PassiveScriptScanRuleUnitTest extends TestUtils {

    private ExtensionScript extensionScript;
    private ExtensionLoader extensionLoader;
    private HttpMessage message;
    private int id;
    private Source source;

    @BeforeEach
    void setUp() throws Exception {
        setUpZap();
        extensionScript = mock(ExtensionScript.class);
        extensionLoader = mock(ExtensionLoader.class);
        message = new HttpMessage(new HttpRequestHeader("GET / HTTP/1.1"));
        id = 1;
        source = new Source("");
        var model = mock(Model.class);
        Model.setSingletonForTesting(model);
        Control.initSingletonForTesting(model, extensionLoader);
    }

    @Test
    void shouldScan() throws Exception {
        // Given
        PassiveScript scriptInterface = mock(PassiveScript.class);
        ScriptWrapper script = createScriptWrapper(scriptInterface, PassiveScript.class);
        var metadata = new ScanRuleMetadata(12345, "Test Scan Rule");
        var scanRule = new PassiveScriptScanRule(script, metadata);
        // When
        scanRule.scanHttpResponseReceive(message, id, source);
        // Then
        verify(scriptInterface, times(1)).scan(scanRule, message, source);
    }

    @Test
    void shouldScanWithCopy() throws Exception {
        // Given
        PassiveScript scriptInterface = mock(PassiveScript.class);
        ScriptWrapper script = createScriptWrapper(scriptInterface, PassiveScript.class);
        var metadata = new ScanRuleMetadata(12345, "Test Scan Rule");
        var scanRule = new PassiveScriptScanRule(script, metadata);
        // When
        scanRule.copy().scanHttpResponseReceive(message, id, source);
        // Then
        verify(scriptInterface, times(1)).scan(scanRule, message, source);
    }

    @Test
    void shouldHandleNullReferences() throws Exception {
        // Given
        ScriptWrapper script = mock(ScriptWrapper.class);
        var metadata = new ScanRuleMetadata(12345, "Test Scan Rule");
        metadata.setRisk(Risk.HIGH);
        metadata.setConfidence(Confidence.HIGH);
        metadata.setReferences(null);
        var scanRule = new PassiveScriptScanRule(script, metadata);
        scanRule.setHelper(mock(PassiveScanData.class));
        // When
        Alert alert = scanRule.newAlert().build();
        // Then
        assertThat(alert.getReference(), is(equalTo("")));
    }

    @Test
    void shouldHonourScriptEngineThreadedPropertyOnAppliesToHistoryType() throws Exception {
        // Given
        PassiveScript scriptInterface = mock(PassiveScript.class);
        ScriptWrapper script = createScriptWrapper(scriptInterface, PassiveScript.class);
        var engine = mock(ScriptEngineWrapper.class);
        given(engine.isSingleThreaded()).willReturn(true);
        given(script.getEngine()).willReturn(engine);
        int historyType = 1;
        var scanRule = new PassiveScriptScanRule(script, null);
        // When
        scanRule.appliesToHistoryType(historyType);
        scanRule.appliesToHistoryType(historyType);
        // Then
        verify(engine, times(2)).isSingleThreaded();
        verify(scriptInterface, times(2)).appliesToHistoryType(historyType);
    }

    private <T> ScriptWrapper createScriptWrapper(T scriptInterface, Class<T> scriptClass)
            throws Exception {
        var script = mock(ScriptWrapper.class);
        given(extensionLoader.getExtension(ExtensionScript.class)).willReturn(extensionScript);
        given(extensionScript.getInterface(script, scriptClass)).willReturn(scriptInterface);
        return script;
    }
}
