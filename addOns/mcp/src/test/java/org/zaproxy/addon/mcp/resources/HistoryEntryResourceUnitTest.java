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
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import com.fasterxml.jackson.databind.JsonNode;
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
        String content = resource.readContent("zap://other/123");

        JsonNode json = parseJson(content);
        assertThat(json.has("error"), equalTo(true));
        assertThat(json.get("error").asText(), containsString("invalid"));
    }

    @Test
    void shouldReturnErrorForMissingId() {
        String content = resource.readContent("zap://history/");

        JsonNode json = parseJson(content);
        assertThat(json.has("error"), equalTo(true));
        assertThat(json.get("error").asText(), containsString("id"));
    }

    @Test
    void shouldReturnErrorForInvalidId() {
        String content = resource.readContent("zap://history/abc");

        JsonNode json = parseJson(content);
        assertThat(json.has("error"), equalTo(true));
        assertThat(json.get("error").asText(), containsString("invalid"));
    }

    @Test
    void shouldHaveCorrectUriAndName() {
        assertThat(resource.getUri(), equalTo("zap://history/"));
        assertThat(resource.getName(), equalTo("history-entry"));
    }

    @Test
    void shouldReturnRequestAndResponseWhenHistoryEntryExists() throws Exception {
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET /test HTTP/1.1\r\nHost: example.com\r\n");
        msg.setRequestBody("request body");
        msg.setResponseHeader("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n");
        msg.setResponseBody("response body");

        HistoryReference href =
                mock(HistoryReference.class, withSettings().strictness(Strictness.LENIENT));
        given(href.getHttpMessage()).willReturn(msg);
        given(extHistory.getHistoryReference(123)).willReturn(href);

        String content = resource.readContent("zap://history/123");
        JsonNode json = parseJson(content);

        assertThat(json.has("error"), equalTo(false));
        assertThat(json.get("requestHeader").asText(), containsString("GET"));
        assertThat(json.get("requestBody").asText(), equalTo("request body"));
        assertThat(json.get("responseHeader").asText(), containsString("HTTP/1.1 200"));
        assertThat(json.get("responseBody").asText(), equalTo("response body"));
    }

    @Test
    void shouldReturnErrorWhenHistoryEntryNotFound() {
        given(extHistory.getHistoryReference(999)).willReturn(null);

        String content = resource.readContent("zap://history/999");
        JsonNode json = parseJson(content);

        assertThat(json.has("error"), equalTo(true));
        // Matches resolved message ("History ID 999 not found") and unresolved key
        assertThat(json.get("error").asText().toLowerCase(), containsString("notfound"));
    }

    @Test
    void shouldReturnErrorWhenHistoryReferenceHasNoHttpMessage() throws Exception {
        HistoryReference href =
                mock(HistoryReference.class, withSettings().strictness(Strictness.LENIENT));
        given(href.getHttpMessage()).willReturn(null);
        given(extHistory.getHistoryReference(123)).willReturn(href);

        String content = resource.readContent("zap://history/123");
        JsonNode json = parseJson(content);

        assertThat(json.has("error"), equalTo(true));
        // Matches resolved message ("History ID 123 not found") and unresolved key
        assertThat(json.get("error").asText().toLowerCase(), containsString("notfound"));
    }

    private static JsonNode parseJson(String json) {
        try {
            return OBJECT_MAPPER.readTree(json);
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse JSON: " + json, e);
        }
    }
}
