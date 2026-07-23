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
package org.zaproxy.addon.llm.ui;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.io.IOException;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.EnumSource.Mode;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.llm.ExtensionLlm;
import org.zaproxy.addon.llm.LlmProvider;
import org.zaproxy.zap.testutils.TestUtils;

class AddLlmProviderDialogUnitTest extends TestUtils {

    @BeforeAll
    static void setupAll() {
        mockMessages(new ExtensionLlm());
    }

    @Test
    void shouldApplyDefaultForOpenRouter() {
        // Given / When
        String endpoint = AddLlmProviderDialog.endpointValueOnSelect(LlmProvider.OPENROUTER);

        // Then
        assertThat(endpoint, is("https://openrouter.ai/api/v1"));
    }

    @ParameterizedTest
    @NullSource
    @EnumSource(
            value = LlmProvider.class,
            mode = Mode.EXCLUDE,
            names = {"OPENROUTER"})
    void shouldClearValueForProvidersWithoutDefaultEndpoint(LlmProvider provider) {
        // Given / When
        String endpoint = AddLlmProviderDialog.endpointValueOnSelect(provider);
        // Then
        assertThat(endpoint, is(""));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "http://localhost:11434/",
                "http://localhost:11434",
                "https://openrouter.ai/api/v1",
                "https://docs-test-001.openai.azure.com/",
                "http://127.0.0.1:11434",
                "http://192.168.0.232:11434",
                "http://host.docker.internal:11434"
            })
    void shouldAcceptValidHttpEndpoints(String endpoint) {
        assertThat(AddLlmProviderDialog.isValidHttpEndpoint(endpoint), is(true));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(
            strings = {
                " ",
                "localhost:11434",
                "127.0.0.1:11434",
                "example.com",
                "http://",
                "https://",
                "ftp://example.com/",
                "http:///path"
            })
    void shouldRejectInvalidHttpEndpoints(String endpoint) {
        assertThat(AddLlmProviderDialog.isValidHttpEndpoint(endpoint), is(false));
    }

    @Test
    void shouldEnsurePathWhenBuildingRequestUri() throws Exception {
        URI uri = AddLlmProviderDialog.toRequestUri("http://192.168.0.232:11434");

        assertThat(uri.getHost(), is("192.168.0.232"));
        assertThat(uri.getPort(), is(11434));
        assertThat(uri.getPath(), is("/"));
    }

    @Test
    void shouldTreatSuccessfulHttpSenderProbeAsReachable() throws Exception {
        HttpSender sender = mock(HttpSender.class);

        assertThat(
                AddLlmProviderDialog.isEndpointReachable("http://192.168.0.232:11434", sender),
                is(true));
        verify(sender).sendAndReceive(any(HttpMessage.class));
    }

    @Test
    void shouldTreatHttpSenderFailureAsUnreachable() throws Exception {
        HttpSender sender = mock(HttpSender.class);
        doThrow(new IOException("connection refused"))
                .when(sender)
                .sendAndReceive(any(HttpMessage.class));

        assertThat(
                AddLlmProviderDialog.isEndpointReachable("http://192.168.0.232:11434", sender),
                is(false));
    }
}
