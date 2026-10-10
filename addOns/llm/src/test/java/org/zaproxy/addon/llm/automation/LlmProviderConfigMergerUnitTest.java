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
package org.zaproxy.addon.llm.automation;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.llm.ExtensionLlm;
import org.zaproxy.addon.llm.LlmOptions;
import org.zaproxy.addon.llm.LlmProvider;
import org.zaproxy.addon.llm.LlmProviderConfig;
import org.zaproxy.addon.llm.automation.LlmConfigJob.Parameters;
import org.zaproxy.addon.llm.automation.LlmConfigJob.Provider;
import org.zaproxy.addon.llm.automation.LlmProviderConfigMerger.Result;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit tests for {@link LlmProviderConfigMerger}. */
class LlmProviderConfigMergerUnitTest extends TestUtils {

    private LlmOptions options;
    private Parameters parameters;

    @BeforeEach
    void setUp() {
        mockMessages(new ExtensionLlm());
        options = new LlmOptions();
        options.load(new ZapXmlConfiguration());
        parameters = new Parameters();
    }

    @Test
    void shouldAddNewProviderWithDefaults() {
        // Given
        Provider provider = provider("local", LlmProvider.OLLAMA);
        provider.setEndpoint("http://localhost:11434/");
        provider.setModels(List.of("llama"));

        // When
        Result result = LlmProviderConfigMerger.merge(options, parameters, List.of(provider));

        // Then
        assertThat(result.errors(), is(empty()));
        LlmProviderConfig config = result.providers().get(0);
        assertThat(config.getName(), is(equalTo("local")));
        assertThat(config.isTrusted(), is(true));
        assertThat(config.getTimeoutSeconds(), is(LlmProviderConfig.DEFAULT_TIMEOUT_SECONDS));
        assertThat(result.defaultProvider(), is(equalTo("local")));
        assertThat(result.defaultModel(), is(equalTo("llama")));
    }

    @Test
    void shouldNotTrustCloudProviderByDefault() {
        // Given
        Provider provider = provider("cloud", LlmProvider.CLAUDE);
        provider.setModels(List.of("model"));

        // When
        Result result = LlmProviderConfigMerger.merge(options, parameters, List.of(provider));

        // Then
        assertThat(result.errors(), is(empty()));
        assertThat(result.providers().get(0).isTrusted(), is(false));
    }

    @Test
    void shouldUpdateOnlySpecifiedFieldsOfExistingProvider() {
        // Given
        existing("a", LlmProvider.OLLAMA, "http://a", "m1");
        existing("b", LlmProvider.OLLAMA, "http://b", "m2");
        Provider update = new Provider();
        update.setName("a");
        update.setTimeout(5);

        // When
        Result result = LlmProviderConfigMerger.merge(options, parameters, List.of(update));

        // Then
        assertThat(result.errors(), is(empty()));
        assertThat(names(result), contains("a", "b"));
        LlmProviderConfig a = result.providers().get(0);
        assertThat(a.getEndpoint(), is(equalTo("http://a")));
        assertThat(a.getModels(), contains("m1"));
        assertThat(a.getTimeoutSeconds(), is(5));
    }

    @Test
    void shouldDeleteExistingWhenRequested() {
        // Given
        existing("old", LlmProvider.OLLAMA, "http://old", "m1");
        parameters.setDeleteExisting(true);
        Provider provider = provider("new", LlmProvider.CLAUDE);
        provider.setModels(List.of("m"));

        // When
        Result result = LlmProviderConfigMerger.merge(options, parameters, List.of(provider));

        // Then
        assertThat(names(result), contains("new"));
        assertThat(result.defaultProvider(), is(equalTo("new")));
    }

    @Test
    void shouldKeepExistingDefaultsWhenStillValid() {
        // Given
        existing("a", LlmProvider.OLLAMA, "http://a", "m1", "m2");
        options.setDefaultProviderName("a");
        options.setDefaultModelName("m2");

        // When
        Result result = LlmProviderConfigMerger.merge(options, parameters, List.of());

        // Then
        assertThat(result.defaultProvider(), is(equalTo("a")));
        assertThat(result.defaultModel(), is(equalTo("m2")));
    }

    @Test
    void shouldUseRequestedDefaults() {
        // Given
        existing("a", LlmProvider.OLLAMA, "http://a", "m1");
        Provider provider = provider("b", LlmProvider.CLAUDE);
        provider.setModels(List.of("x", "y"));
        parameters.setDefaultProvider("b");
        parameters.setDefaultModel("y");

        // When
        Result result = LlmProviderConfigMerger.merge(options, parameters, List.of(provider));

        // Then
        assertThat(result.errors(), is(empty()));
        assertThat(result.defaultProvider(), is(equalTo("b")));
        assertThat(result.defaultModel(), is(equalTo("y")));
    }

    @Test
    void shouldUseFirstModelWhenExistingDefaultModelNotInNewDefaultProvider() {
        // Given
        existing("a", LlmProvider.OLLAMA, "http://a", "m1");
        options.setDefaultProviderName("a");
        options.setDefaultModelName("m1");
        Provider provider = provider("b", LlmProvider.CLAUDE);
        provider.setModels(List.of("x", "y"));
        parameters.setDefaultProvider("b");

        // When
        Result result = LlmProviderConfigMerger.merge(options, parameters, List.of(provider));

        // Then
        assertThat(result.defaultModel(), is(equalTo("x")));
    }

    @Test
    void shouldErrorOnUnknownDefaultProvider() {
        // Given
        parameters.setDefaultProvider("missing");

        // When
        Result result = LlmProviderConfigMerger.merge(options, parameters, List.of());

        // Then
        assertThat(
                result.errors(),
                contains("The default provider 'missing' is not a configured provider"));
    }

    @Test
    void shouldErrorOnDefaultModelNotInProvider() {
        // Given
        Provider provider = provider("a", LlmProvider.CLAUDE);
        provider.setModels(List.of("m1"));
        parameters.setDefaultModel("other");

        // When
        Result result = LlmProviderConfigMerger.merge(options, parameters, List.of(provider));

        // Then
        assertThat(
                result.errors(),
                contains("The default model 'other' is not one of the models of provider 'a'"));
    }

    @Test
    void shouldErrorOnBlankName() {
        // When
        Result result =
                LlmProviderConfigMerger.merge(
                        options, parameters, List.of(provider(" ", LlmProvider.CLAUDE)));

        // Then
        assertThat(result.errors(), contains("Every provider requires a name"));
    }

    @Test
    void shouldErrorOnDuplicateName() {
        // Given
        Provider first = provider("a", LlmProvider.CLAUDE);
        first.setModels(List.of("m"));
        Provider second = provider("a", LlmProvider.CLAUDE);
        second.setModels(List.of("m"));

        // When
        Result result = LlmProviderConfigMerger.merge(options, parameters, List.of(first, second));

        // Then
        assertThat(result.errors(), contains("The provider name 'a' is used more than once"));
    }

    @Test
    void shouldErrorOnMissingOrNoneType() {
        // Given
        Provider noType = provider("a", null);
        Provider none = provider("b", LlmProvider.NONE);

        // When
        Result result = LlmProviderConfigMerger.merge(options, parameters, List.of(noType, none));

        // Then
        assertThat(
                result.errors(),
                contains(
                        "The provider 'a' requires a valid type",
                        "The provider 'b' requires a valid type"));
    }

    @Test
    void shouldErrorOnMissingEndpointAndModels() {
        // When
        Result result =
                LlmProviderConfigMerger.merge(
                        options, parameters, List.of(provider("a", LlmProvider.OPENAI_COMPATIBLE)));

        // Then
        assertThat(
                result.errors(),
                contains(
                        "The provider 'a' requires an endpoint",
                        "The provider 'a' requires at least one model"));
    }

    @Test
    void shouldValidateProviderAgainstExistingOne() {
        // Given
        existing("a", LlmProvider.OLLAMA, "http://a", "m1");
        Provider partial = new Provider();
        partial.setName("a");

        // When
        List<String> errors = LlmProviderConfigMerger.validate(options, partial, false);

        // Then
        assertThat(errors, is(empty()));
    }

    @Test
    void shouldValidateProviderWithoutExistingOnesWhenDeleting() {
        // Given
        existing("a", LlmProvider.OLLAMA, "http://a", "m1");
        Provider partial = new Provider();
        partial.setName("a");

        // When
        List<String> errors = LlmProviderConfigMerger.validate(options, partial, true);

        // Then
        assertThat(errors, contains("The provider 'a' requires a valid type"));
    }

    @Test
    void shouldValidateProviderName() {
        // When
        List<String> errors = LlmProviderConfigMerger.validate(options, new Provider(), false);

        // Then
        assertThat(errors, contains("Every provider requires a name"));
    }

    private void existing(String name, LlmProvider type, String endpoint, String... models) {
        List<LlmProviderConfig> configs = options.getProviderConfigs();
        configs.add(new LlmProviderConfig(name, type, "", endpoint, List.of(models)));
        options.setProviderConfigs(configs);
    }

    private static Provider provider(String name, LlmProvider type) {
        Provider provider = new Provider();
        provider.setName(name);
        provider.setType(type);
        return provider;
    }

    private static List<String> names(Result result) {
        return result.providers().stream().map(LlmProviderConfig::getName).toList();
    }
}
