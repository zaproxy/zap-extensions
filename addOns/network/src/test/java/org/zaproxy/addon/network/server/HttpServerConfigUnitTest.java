/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.network.server;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.network.HttpSender;

/** Unit test for {@link HttpServerConfig}. */
class HttpServerConfigUnitTest {

    private HttpMessageHandler handler = mock(HttpMessageHandler.class);
    private HttpSender httpSender = mock(HttpSender.class);

    private HttpServerConfig config;

    private HttpServerConfig.Builder builderWithRequiredProperties() {
        return HttpServerConfig.builder().setHttpMessageHandler(handler);
    }

    @Test
    void shouldThrowExceptionWhenBuildingAConfigWithoutHttpMessageHandler() {
        // Given
        HttpServerConfig.Builder builder = HttpServerConfig.builder();
        // When
        IllegalStateException e = assertThrows(IllegalStateException.class, builder::build);
        // Then
        assertThat(e.getMessage(), containsString("httpMessageHandler"));
    }

    @Test
    void shouldThrowExceptionWhenSettingANullHttpMessageHandler() {
        // Given
        HttpServerConfig.Builder builder = HttpServerConfig.builder();
        HttpMessageHandler handler = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> builder.setHttpMessageHandler(handler));
    }

    @Test
    void shouldSetNullHttpSender() {
        // Given
        HttpServerConfig.Builder builder = HttpServerConfig.builder();
        HttpSender httpSender = null;
        // When / Then
        assertDoesNotThrow(() -> builder.setHttpSender(httpSender));
    }

    @Test
    void shouldCreateConfigWithAllProperties() {
        // Given
        HttpServerConfig.Builder builder = HttpServerConfig.builder();
        // When / Then
        assertDoesNotThrow(
                () ->
                        builder.setHttpMessageHandler(handler)
                                .setHttpSender(httpSender)
                                .setServeZapApi(true)
                                .build());
    }

    @Test
    void shouldRetrieveHttpMessageHandlerSet() {
        // Given
        config = builderWithRequiredProperties().build();
        // When
        HttpMessageHandler retrievedHttpMessageHandler = config.getHttpMessageHandler();
        // Then
        assertThat(retrievedHttpMessageHandler, is(equalTo(handler)));
    }

    @Test
    void shouldRetrieveHttpSenderSet() {
        // Given
        config = builderWithRequiredProperties().setHttpSender(httpSender).build();
        // When
        HttpSender retrievedHttpSender = config.getHttpSender();
        // Then
        assertThat(retrievedHttpSender, is(equalTo(httpSender)));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldRetrieveServeZapApiSet(boolean serve) {
        // Given
        config = builderWithRequiredProperties().setServeZapApi(serve).build();
        // When
        boolean retrievedServeZapApi = config.isServeZapApi();
        // Then
        assertThat(retrievedServeZapApi, is(equalTo(serve)));
    }
}
