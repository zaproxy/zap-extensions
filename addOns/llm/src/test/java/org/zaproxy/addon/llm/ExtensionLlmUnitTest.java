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
package org.zaproxy.addon.llm;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.OptionsChangedListener;
import org.zaproxy.addon.llm.services.LlmCommunicationService;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.I18N;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

public class ExtensionLlmUnitTest extends TestUtils {

    private static ExtensionLlm ext;
    private static ExtensionHook hook;

    @BeforeAll
    static void beforeAll() {
        Control.initSingletonForTesting();
        hook = mock(ExtensionHook.class);
        ext = new ExtensionLlm();
        ext.hook(hook);
        ext.getOptions().load(new ZapXmlConfiguration());
        Constant.messages = mock(I18N.class);
    }

    @Test
    void shouldReturnDifferentCommsForDifferentKeys() {
        // Given
        ext.getOptions().setModelProvider(LlmProvider.OLLAMA);
        ext.getOptions().setEndpoint("http://localhost");

        // When
        LlmCommunicationService comms1 = ext.getCommunicationService("KEY1");
        LlmCommunicationService comms2 = ext.getCommunicationService("KEY2");
        LlmCommunicationService comms3 = ext.getCommunicationService("KEY3");

        // Then
        assertThat(comms1, is(not(equalTo(comms2))));
        assertThat(comms1, is(not(equalTo(comms3))));
        assertThat(comms2, is(not(equalTo(comms3))));
    }

    @Test
    void shouldReturnSameCommsForSameKey() {
        // Given
        ext.getOptions().setModelProvider(LlmProvider.OLLAMA);
        ext.getOptions().setEndpoint("http://localhost");

        // When
        LlmCommunicationService comms1 = ext.getCommunicationService("KEY1");
        LlmCommunicationService comms2 = ext.getCommunicationService("KEY1");
        LlmCommunicationService comms3 = ext.getCommunicationService("KEY1");

        // Then
        assertThat(comms1, is(equalTo(comms2)));
        assertThat(comms1, is(equalTo(comms3)));
    }

    @Test
    void shouldReturnDifferemtCommsForSameKeyIfChanged() {
        // Given
        ext.getOptions().setModelProvider(LlmProvider.OLLAMA);
        ext.getOptions().setEndpoint("http://localhost");

        // When
        LlmCommunicationService comms1 = ext.getCommunicationService("KEY1");
        ext.getOptions().setEndpoint("http://localhost:1234");

        ArgumentCaptor<OptionsChangedListener> argument =
                ArgumentCaptor.forClass(OptionsChangedListener.class);
        verify(hook).addOptionsChangedListener(argument.capture());
        argument.getValue().optionsChanged(null);

        LlmCommunicationService comms2 = ext.getCommunicationService("KEY1");

        // Then
        assertThat(comms1, is(not(equalTo(comms2))));
    }
}
