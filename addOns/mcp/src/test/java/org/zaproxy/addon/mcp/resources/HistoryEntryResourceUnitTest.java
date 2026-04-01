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
package org.zaproxy.addon.mcp.resources;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Locale;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.utils.I18N;

/** Unit tests for {@link HistoryEntryResource}. */
class HistoryEntryResourceUnitTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private ExtensionLoader extensionLoader;
    private ExtensionHistory extHistory;
    private HistoryEntryResource resource;

    @BeforeEach
    void setUp() {
        Constant.messages = new I18N(Locale.ROOT);
        extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        extHistory = mock(ExtensionHistory.class, withSettings().strictness(Strictness.LENIENT));
        given(extensionLoader.getExtension(ExtensionHistory.class)).willReturn(extHistory);
        Control.initSingletonForTesting(mock(Model.class), extensionLoader);
        resource = new HistoryEntryResource();
    }

    @Test
    void shouldReturnErrorForInvalidUri() {
        // Given / When
        String content = resource.readContent("zap://other/123");

        // Then
        assertThat(
                content, equalTo("{\"error\":\"!mcp.resource.historyentry.error.invaliduri!\"}"));
    }

    @Test
    void shouldReturnErrorForMissingId() {
        // Given / When
        String content = resource.readContent("zap://history/");

        // Then
        assertThat(content, equalTo("{\"error\":\"!mcp.resource.historyentry.error.missingid!\"}"));
    }

    @Test
    void shouldReturnErrorForInvalidId() {
        // Given / When
        String content = resource.readContent("zap://history/abc");

        // Then
        assertThat(content, equalTo("{\"error\":\"!mcp.resource.historyentry.error.invalidid!\"}"));
    }

    @Test
    void shouldHaveCorrectUriAndName() {
        // Given / When / Then
        assertThat(resource.getUri(), equalTo("zap://history/"));
        assertThat(resource.getName(), equalTo("history-entry"));
    }

    @Test
    void shouldReturnRequestAndResponseWhenHistoryEntryExists() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET /test HTTP/1.1\r\nHost: example.com\r\n");
        msg.setRequestBody("request body");
        msg.setResponseHeader("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n");
        msg.setResponseBody("response body");

        HistoryReference href =
                mock(HistoryReference.class, withSettings().strictness(Strictness.LENIENT));
        given(href.getHttpMessage()).willReturn(msg);
        given(extHistory.getHistoryReference(123)).willReturn(href);

        // When
        String content = resource.readContent("zap://history/123");

        // Then
        assertThat(
                content,
                equalTo(
                        "{"
                                + "\"requestHeader\":\"GET http://example.com/test HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n\","
                                + "\"requestBody\":\"request body\","
                                + "\"responseHeader\":\"HTTP/1.1 200 OK\\r\\nContent-Type: text/html\\r\\n\\r\\n\","
                                + "\"responseBody\":\"response body\"}"));
    }

    @Test
    void shouldReturnErrorWhenHistoryEntryNotFound() {
        // Given / When
        given(extHistory.getHistoryReference(999)).willReturn(null);

        String content = resource.readContent("zap://history/999");

        // Then
        assertThat(content, equalTo("{\"error\":\"!mcp.resource.historyentry.error.notfound!\"}"));
    }
}
