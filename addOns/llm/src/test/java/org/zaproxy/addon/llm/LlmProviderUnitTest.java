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
package org.zaproxy.addon.llm;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.EnumSource.Mode;
import org.zaproxy.zap.testutils.TestUtils;

class LlmProviderUnitTest extends TestUtils {

    @BeforeAll
    static void setupAll() {
        mockMessages(new ExtensionLlm());
    }

    @Test
    void shouldNotRequireModelForNoneProvider() {
        assertThat(LlmProvider.NONE.isModelRequired(), is(false));
    }

    @ParameterizedTest
    @EnumSource(value = LlmProvider.class, mode = Mode.EXCLUDE, names = "NONE")
    void allActiveProvidersShouldRequireModel(LlmProvider provider) {
        assertThat(provider.isModelRequired(), is(true));
    }

    @ParameterizedTest
    @EnumSource(
            value = LlmProvider.class,
            mode = Mode.INCLUDE,
            names = {"OLLAMA", "AZURE_OPENAI", "OPENAI_COMPATIBLE"})
    void shouldReportEndpointRequired(LlmProvider provider) {
        assertThat(provider.isEndpointRequired(), is(true));
    }

    @ParameterizedTest
    @EnumSource(
            value = LlmProvider.class,
            mode = Mode.EXCLUDE,
            names = {"OLLAMA", "AZURE_OPENAI", "OPENAI_COMPATIBLE"})
    void shouldReportEndpointNotRequired(LlmProvider provider) {
        assertThat(provider.isEndpointRequired(), is(false));
    }

    @ParameterizedTest
    @EnumSource(
            value = LlmProvider.class,
            mode = Mode.INCLUDE,
            names = {"OLLAMA", "AZURE_OPENAI", "OPENAI_COMPATIBLE"})
    void shouldReportEndpointSupported(LlmProvider provider) {
        assertThat(provider.supportsEndpoint(), is(true));
    }

    @ParameterizedTest
    @EnumSource(
            value = LlmProvider.class,
            mode = Mode.EXCLUDE,
            names = {"OLLAMA", "AZURE_OPENAI", "OPENAI_COMPATIBLE"})
    void shouldReportEndpointNotSupported(LlmProvider provider) {
        assertThat(provider.supportsEndpoint(), is(false));
    }

    @Test
    void shouldTrustLocalProvidersByDefault() {
        assertThat(LlmProvider.OLLAMA.isTrustedByDefault(), is(true));
        assertThat(LlmProvider.JLAMA.isTrustedByDefault(), is(true));
    }

    @ParameterizedTest
    @EnumSource(
            value = LlmProvider.class,
            mode = Mode.EXCLUDE,
            names = {"OLLAMA", "JLAMA"})
    void shouldNotTrustNonLocalProvidersByDefault(LlmProvider provider) {
        assertThat(provider.isTrustedByDefault(), is(false));
    }

    @Test
    void shouldSuggestOpenAiCompatibleEndpoints() {
        assertThat(
                LlmProvider.OPENAI_COMPATIBLE.getSuggestedEndpoints().stream()
                        .map(LlmProvider.SuggestedEndpoint::url)
                        .toList(),
                contains(
                        "https://openrouter.ai/api/v1",
                        "https://api.openai.com/v1",
                        "http://localhost:1234/v1",
                        "http://localhost:8080/v1"));
        assertThat(
                LlmProvider.OPENAI_COMPATIBLE.getSuggestedEndpoints().get(2).getLabel(),
                is("http://localhost:1234/v1 (LM Studio)"));
        assertThat(
                LlmProvider.OPENAI_COMPATIBLE.getSuggestedEndpoints().get(2).toString(),
                is("http://localhost:1234/v1"));
    }

    @Test
    void shouldSuggestOllamaEndpoint() {
        assertThat(
                LlmProvider.OLLAMA.getSuggestedEndpoints().stream()
                        .map(LlmProvider.SuggestedEndpoint::url)
                        .toList(),
                contains("http://localhost:11434/"));
        assertThat(
                LlmProvider.OLLAMA.getSuggestedEndpoints().get(0).getLabel(),
                is("http://localhost:11434/"));
    }

    @ParameterizedTest
    @EnumSource(
            value = LlmProvider.class,
            mode = Mode.EXCLUDE,
            names = {"OPENAI_COMPATIBLE", "OLLAMA"})
    void shouldNotSuggestEndpointsForOtherProviders(LlmProvider provider) {
        assertThat(provider.getSuggestedEndpoints(), empty());
    }

    @Test
    void jlamaShouldUseLocalModelPathAndExternalFactory() {
        assertThat(LlmProvider.JLAMA.isLocalModelPath(), is(true));
        assertThat(LlmProvider.JLAMA.requiresExternalFactory(), is(true));
        assertThat(LlmProvider.JLAMA.supportsApiKey(), is(false));
        assertThat(LlmProvider.JLAMA.supportsEndpoint(), is(false));
    }

    @Test
    void jlamaDisplayModelNameShouldBeDirectoryName() {
        assertThat(
                LlmProvider.JLAMA.toDisplayModelName("/home/user/.ZAP/llm-models/TinyLlama-Q4"),
                is("TinyLlama-Q4"));
        assertThat(LlmProvider.JLAMA.toDisplayModelName("TinyLlama-Q4"), is("TinyLlama-Q4"));
    }

    @ParameterizedTest
    @EnumSource(
            value = LlmProvider.class,
            mode = Mode.EXCLUDE,
            names = {"NONE", "OLLAMA", "JLAMA"})
    void shouldSupportApiKey(LlmProvider provider) {
        assertThat(provider.supportsApiKey(), is(true));
    }
}
