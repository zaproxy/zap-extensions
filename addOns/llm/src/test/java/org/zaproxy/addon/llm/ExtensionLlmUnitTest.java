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
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.sameInstance;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import dev.langchain4j.service.tool.ToolProvider;
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
    void shouldReturnNewCommsAfterRemoval() {
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
        ext.removeCommunicationService("KEY1");
        LlmCommunicationService comms2 = ext.getCommunicationService("KEY1", null);

        // Then
        assertThat(comms1, is(not(equalTo(comms2))));
    }

    @Test
    void shouldBumpToolProvidersVersionWhenToolsChange() {
        // Given
        int before = ext.getToolProvidersVersion();
        ToolProvider provider = mock(ToolProvider.class);

        // When
        ext.addToolProvider(provider);
        int afterAdd = ext.getToolProvidersVersion();
        ext.removeToolProvider(provider);
        int afterRemove = ext.getToolProvidersVersion();

        // Then
        assertThat(afterAdd, is(not(equalTo(before))));
        assertThat(afterRemove, is(not(equalTo(afterAdd))));
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
    void shouldClearCachedServicesWhenToolProviderAdded() {
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
        LlmCommunicationService before = ext.getCommunicationService("MCP_KEY1", null);
        ToolProvider provider = mock(ToolProvider.class);

        // When
        ext.addToolProvider(provider);
        LlmCommunicationService after = ext.getCommunicationService("MCP_KEY1", null);

        // Then
        assertThat(before, is(not(equalTo(after))));
    }

    @Test
    void shouldClearCachedServicesWhenToolProviderRemoved() {
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
        ToolProvider provider = mock(ToolProvider.class);
        ext.addToolProvider(provider);
        LlmCommunicationService before = ext.getCommunicationService("MCP_KEY2", null);

        // When
        ext.removeToolProvider(provider);
        LlmCommunicationService after = ext.getCommunicationService("MCP_KEY2", null);

        // Then
        assertThat(before, is(not(equalTo(after))));
    }

    @Test
    void shouldReturnNoCommsIfProviderHasNoModels() {
        // Given
        ext.getOptions()
                .setProviderConfigs(
                        List.of(
                                new LlmProviderConfig(
                                        "claude", LlmProvider.CLAUDE, "key", "", List.of())));
        ext.getOptions().setDefaultProviderName("claude");

        // When
        LlmCommunicationService comms = ext.getCommunicationService("KEY1", null);

        // Then
        assertThat(comms, is(nullValue()));
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

    @Test
    void shouldIncludeToolProvidersWhenBuildingServiceWithToolsEnabled() {
        // Given
        LlmProviderConfig config =
                new LlmProviderConfig(
                        "ollama", LlmProvider.OLLAMA, null, "http://localhost", List.of("model1"));
        ToolProvider provider = mock(ToolProvider.class);
        ext.addToolProvider(provider);

        // When
        LlmCommunicationService service =
                ext.buildCommunicationService(config, "model1", null, true, null);

        // Then
        assertThat(service, is(not(nullValue())));
        assertThat(service.getToolProviders(), contains(provider));
    }

    @Test
    void shouldOmitToolProvidersWhenBuildingServiceWithToolsDisabled() {
        // Given
        LlmProviderConfig config =
                new LlmProviderConfig(
                        "ollama", LlmProvider.OLLAMA, null, "http://localhost", List.of("model1"));
        ToolProvider provider = mock(ToolProvider.class);
        ext.addToolProvider(provider);

        // When
        LlmCommunicationService service =
                ext.buildCommunicationService(config, "model1", null, false, null);

        // Then
        assertThat(service, is(not(nullValue())));
        assertThat(service.getToolProviders(), is(empty()));
    }

    @Test
    void shouldOmitToolProvidersWhenProviderIsUntrustedEvenIfToolsRequested() {
        // Given
        LlmProviderConfig config =
                new LlmProviderConfig(
                        "claude",
                        LlmProvider.CLAUDE,
                        "key",
                        "",
                        List.of("claude-sonnet-4-6"),
                        false);
        ToolProvider provider = mock(ToolProvider.class);
        ext.addToolProvider(provider);

        // When
        LlmCommunicationService service =
                ext.buildCommunicationService(config, "claude-sonnet-4-6", null, true, null);

        // Then
        assertThat(service, is(not(nullValue())));
        assertThat(service.getToolProviders(), is(empty()));
    }

    @Test
    void shouldDefaultNewConfigsTrustedBasedOnProviderType() {
        assertThat(
                new LlmProviderConfig(
                                "ollama",
                                LlmProvider.OLLAMA,
                                null,
                                "http://localhost",
                                List.of("m1"))
                        .isTrusted(),
                is(true));
        assertThat(
                new LlmProviderConfig("jlama", LlmProvider.JLAMA, "", "", List.of("/models/tiny"))
                        .isTrusted(),
                is(true));
        assertThat(
                new LlmProviderConfig(
                                "claude",
                                LlmProvider.CLAUDE,
                                "key",
                                "",
                                List.of("claude-sonnet-4-6"))
                        .isTrusted(),
                is(false));
    }

    @Test
    void shouldRegisterAndUnregisterChatModelFactory() {
        // Given
        LlmChatModelFactory factory = mock(LlmChatModelFactory.class);
        when(factory.getProvider()).thenReturn(LlmProvider.JLAMA);

        // When
        ext.registerChatModelFactory(factory);

        // Then
        assertThat(ext.hasChatModelFactory(LlmProvider.JLAMA), is(true));
        assertThat(ext.getChatModelFactory(LlmProvider.JLAMA), is(factory));

        // When
        ext.unregisterChatModelFactory(factory);

        // Then
        assertThat(ext.hasChatModelFactory(LlmProvider.JLAMA), is(false));
        assertThat(ext.getChatModelFactory(LlmProvider.JLAMA), is(nullValue()));
    }

    @Test
    void shouldConfigureProviderAsDefault() {
        // Given
        ext.getOptions().setProviderConfigs(List.of());
        LlmProviderConfig config =
                new LlmProviderConfig("Local", LlmProvider.JLAMA, "", "", List.of("/models/tiny"));

        // When
        ext.configureProvider(config, true);

        // Then
        assertThat(ext.getProviderConfigs(), hasSize(1));
        assertThat(ext.getDefaultProviderConfig().getName(), is("Local"));
        assertThat(ext.getDefaultProviderConfig().getProvider(), is(LlmProvider.JLAMA));
        assertThat(ext.getDefaultModelName(), is("/models/tiny"));
    }

    @Test
    void configureProviderShouldKeepCommsWhenOnlyAddingModel() {
        // Given
        ext.removeCommunicationService("CFG_KEEP");
        ext.getOptions()
                .setProviderConfigs(
                        List.of(
                                new LlmProviderConfig(
                                        "ollama",
                                        LlmProvider.OLLAMA,
                                        null,
                                        "http://localhost:11434",
                                        List.of("model1"))));
        ext.getOptions().setDefaultProviderName("ollama");
        ext.getOptions().setDefaultModelName("model1");
        LlmCommunicationService before = ext.getCommunicationService("CFG_KEEP", null);
        assertThat(before, is(not(nullValue())));

        // When — add another model without changing the selected one
        ext.configureProvider(
                new LlmProviderConfig(
                        "ollama",
                        LlmProvider.OLLAMA,
                        null,
                        "http://localhost:11434",
                        List.of("model1", "model2")),
                false);

        // Then
        assertThat(ext.getCommunicationService("CFG_KEEP", null), is(sameInstance(before)));
        assertThat(ext.getDefaultModelName(), is("model1"));
        assertThat(ext.getProviderConfigs().get(0).getModels(), hasSize(2));
    }

    @Test
    void configureProviderShouldDropCommsWhenModelRemoved() {
        // Given
        ext.removeCommunicationService("CFG_DROP_MODEL");
        ext.getOptions()
                .setProviderConfigs(
                        List.of(
                                new LlmProviderConfig(
                                        "ollama",
                                        LlmProvider.OLLAMA,
                                        null,
                                        "http://localhost:11434",
                                        List.of("model1", "model2"))));
        ext.getOptions().setDefaultProviderName("ollama");
        ext.getOptions().setDefaultModelName("model1");
        LlmCommunicationService before = ext.getCommunicationService("CFG_DROP_MODEL", null);
        assertThat(before, is(not(nullValue())));
        assertThat(before.getModelName(), is("model1"));

        // When — remove the model the cached service is using
        ext.configureProvider(
                new LlmProviderConfig(
                        "ollama",
                        LlmProvider.OLLAMA,
                        null,
                        "http://localhost:11434",
                        List.of("model2")),
                false);

        // Then
        assertThat(
                ext.getCommunicationService("CFG_DROP_MODEL", null), is(not(sameInstance(before))));
        assertThat(ext.getDefaultModelName(), is("model2"));
    }

    @Test
    void configureProviderShouldDropCommsWhenConnectionChanges() {
        // Given
        ext.removeCommunicationService("CFG_DROP_CONN");
        ext.getOptions()
                .setProviderConfigs(
                        List.of(
                                new LlmProviderConfig(
                                        "ollama",
                                        LlmProvider.OLLAMA,
                                        null,
                                        "http://localhost:11434",
                                        List.of("model1"))));
        ext.getOptions().setDefaultProviderName("ollama");
        ext.getOptions().setDefaultModelName("model1");
        LlmCommunicationService before = ext.getCommunicationService("CFG_DROP_CONN", null);
        assertThat(before, is(not(nullValue())));

        // When
        ext.configureProvider(
                new LlmProviderConfig(
                        "ollama",
                        LlmProvider.OLLAMA,
                        null,
                        "http://localhost:11435",
                        List.of("model1")),
                false);

        // Then
        assertThat(
                ext.getCommunicationService("CFG_DROP_CONN", null), is(not(sameInstance(before))));
    }
}
