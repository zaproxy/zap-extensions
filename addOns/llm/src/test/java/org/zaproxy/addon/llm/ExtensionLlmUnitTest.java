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
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.OptionsChangedListener;
import org.zaproxy.addon.llm.services.LlmCommunicationService;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

public class ExtensionLlmUnitTest extends TestUtils {

    private static ExtensionLlm ext;
    private static ExtensionHook hook;

    @BeforeAll
    static void beforeAll() {
        mockMessages(new ExtensionLlm());
        Control.initSingletonForTesting();
        hook = mock(ExtensionHook.class);
        ext = new ExtensionLlm();
        ext.hook(hook);
        ext.getOptions().load(new ZapXmlConfiguration());
    }

    @Test
    void shouldReturnDifferentCommsForDifferentKeys() {
        // Given
        ext.getOptions()
                .setProviderConfigs(
                        List.of(
                                new LlmProviderConfig(
                                        "default",
                                        LlmProvider.OLLAMA,
                                        null,
                                        "http://localhost",
                                        List.of("model1"))));
        ext.getOptions().setDefaultProviderName("default");

        // When
        LlmCommunicationService comms1 = ext.getCommunicationService("KEY1", null);
        LlmCommunicationService comms2 = ext.getCommunicationService("KEY2", null);
        LlmCommunicationService comms3 = ext.getCommunicationService("KEY3", null);

        // Then
        assertThat(comms1, is(not(equalTo(comms2))));
        assertThat(comms1, is(not(equalTo(comms3))));
        assertThat(comms2, is(not(equalTo(comms3))));
    }

    @Test
    void shouldReturnSameCommsForSameKey() {
        // Given
        ext.getOptions()
                .setProviderConfigs(
                        List.of(
                                new LlmProviderConfig(
                                        "default",
                                        LlmProvider.OLLAMA,
                                        null,
                                        "http://localhost",
                                        List.of("model1"))));
        ext.getOptions().setDefaultProviderName("default");

        // When
        LlmCommunicationService comms1 = ext.getCommunicationService("KEY1", null);
        LlmCommunicationService comms2 = ext.getCommunicationService("KEY1", null);
        LlmCommunicationService comms3 = ext.getCommunicationService("KEY1", null);

        // Then
        assertThat(comms1, is(equalTo(comms2)));
        assertThat(comms1, is(equalTo(comms3)));
    }

    @Test
    void shouldReturnDifferentCommsForSameKeyIfChanged() {
        // Given
        ext.getOptions()
                .setProviderConfigs(
                        List.of(
                                new LlmProviderConfig(
                                        "default",
                                        LlmProvider.OLLAMA,
                                        null,
                                        "http://localhost",
                                        List.of("model1"))));
        ext.getOptions().setDefaultProviderName("default");

        // When
        LlmCommunicationService comms1 = ext.getCommunicationService("KEY1", null);
        ext.getOptions()
                .setProviderConfigs(
                        List.of(
                                new LlmProviderConfig(
                                        "default",
                                        LlmProvider.OLLAMA,
                                        null,
                                        "http://localhost:1234",
                                        List.of("model1"))));

        ArgumentCaptor<OptionsChangedListener> argument =
                ArgumentCaptor.forClass(OptionsChangedListener.class);
        verify(hook).addOptionsChangedListener(argument.capture());
        argument.getValue().optionsChanged(null);

        LlmCommunicationService comms2 = ext.getCommunicationService("KEY1", null);

        // Then
        assertThat(comms1, is(not(equalTo(comms2))));
    }

    @Test
    void shouldReturnNoCommsIfNoDefault() {
        // Given
        ext.getOptions()
                .setProviderConfigs(
                        List.of(
                                new LlmProviderConfig(
                                        "p1",
                                        LlmProvider.OLLAMA,
                                        null,
                                        "http://localhost",
                                        List.of("model1"))));
        ext.getOptions().setDefaultProviderName("");

        // When
        LlmCommunicationService comms1 = ext.getCommunicationService("KEY1", null);

        // Then
        assertThat(comms1, is(nullValue()));
    }

    @Test
    void shouldReturnDefaultProvider() {
        // Given
        ext.getOptions()
                .setProviderConfigs(
                        List.of(
                                new LlmProviderConfig(
                                        "p1",
                                        LlmProvider.OLLAMA,
                                        null,
                                        "http://localhost",
                                        List.of("model1")),
                                new LlmProviderConfig(
                                        "p2",
                                        LlmProvider.AZURE_OPENAI,
                                        "12345",
                                        "http://localhost",
                                        List.of("model1"))));

        // When
        ext.getOptions().setDefaultProviderName("p1");
        LlmCommunicationService comms1 = ext.getCommunicationService("KEY1", null);
        ext.getOptions().setDefaultProviderName("p2");
        LlmCommunicationService comms2 = ext.getCommunicationService("KEY2", null);

        // Then
        assertThat(comms1.getPconf().getProvider(), is(LlmProvider.OLLAMA));
        assertThat(comms2.getPconf().getProvider(), is(LlmProvider.AZURE_OPENAI));
    }
}
