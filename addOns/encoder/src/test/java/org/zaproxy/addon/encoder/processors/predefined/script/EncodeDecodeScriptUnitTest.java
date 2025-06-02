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
package org.zaproxy.addon.encoder.processors.predefined.script;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import java.io.IOException;
import java.util.List;
import javax.script.ScriptException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.encoder.ExtensionEncoder;
import org.zaproxy.addon.encoder.processors.EncodeDecodeResult;
import org.zaproxy.addon.encoder.processors.script.EncodeDecodeScript;
import org.zaproxy.addon.encoder.processors.script.EncodeDecodeScriptHelper;
import org.zaproxy.addon.encoder.processors.script.ScriptBasedEncodeDecodeProcessor;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;

class EncodeDecodeScriptUnitTest {

    private EncodeDecodeScript script;
    private ScriptBasedEncodeDecodeProcessor processor;

    @BeforeEach
    void setup() throws ScriptException, IOException {
        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
        ExtensionLoader extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        ExtensionScript extScript =
                mock(ExtensionScript.class, withSettings().strictness(Strictness.LENIENT));
        given(extensionLoader.getExtension(ExtensionScript.class)).willReturn(extScript);
        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
        ScriptWrapper scriptWrapper = mock(ScriptWrapper.class);
        given(scriptWrapper.isEnabled()).willReturn(true);
        given(extScript.getScripts(ExtensionEncoder.SCRIPT_TYPE_ENCODE_DECODE))
                .willReturn(List.of(scriptWrapper));
        script = mock(EncodeDecodeScript.class);
        given(extScript.getInterface(scriptWrapper, EncodeDecodeScript.class)).willReturn(script);
        processor = new ScriptBasedEncodeDecodeProcessor("testScript");
        given(scriptWrapper.getName()).willReturn("testScript");
    }

    @Test
    void shouldHandleExpectedResultObject() throws Exception {
        // Given
        String admin = "admin";
        EncodeDecodeResult expected = new EncodeDecodeResult(admin);
        given(script.process(any(), eq(admin))).willReturn(expected);
        // When
        EncodeDecodeResult result = processor.process(admin);
        // Then
        assertThat(result, is(equalTo(expected)));
    }

    @Test
    void shouldHandleStringResultObject() throws Exception {
        // Given
        String admin = "admin";
        given(script.process(any(), eq(admin))).willReturn(admin);
        // When
        EncodeDecodeResult result = processor.process(admin);
        // Then
        assertThat(result.getResult(), is(equalTo(admin)));
    }

    @Test
    void shouldHandleUnexpectedReturnType() throws Exception {
        // Given
        String admin = "admin";
        given(script.process(any(), eq(admin))).willReturn(6667);
        // When
        EncodeDecodeResult result = processor.process(admin);
        // Then
        assertThat(result.getResult(), is(equalTo("6667")));
    }

    @Test
    void shouldHandleNullReturnType() throws Exception {
        // Given
        String admin = "admin";
        given(script.process(any(), eq(admin))).willReturn(null);
        // When
        EncodeDecodeResult result = processor.process(admin);
        // Then
        assertThat(result.getResult(), is(equalTo(null)));
    }

    @Test
    void helperShouldNotBeNull() throws Exception {
        // Given
        String admin = "admin";
        EncodeDecodeResult expected = new EncodeDecodeResult(admin);
        given(script.process(any(), eq(admin))).willReturn(expected);
        ArgumentCaptor<EncodeDecodeScriptHelper> helperCaptor =
                ArgumentCaptor.forClass(EncodeDecodeScriptHelper.class);
        // When
        processor.process(admin);
        // Then
        verify(script).process(helperCaptor.capture(), any());
        assertThat(helperCaptor.getValue(), is(notNullValue()));
    }
}
