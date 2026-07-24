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
package org.zaproxy.addon.mcp.tools;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.mcp.ExtensionMcp;
import org.zaproxy.addon.mcp.McpTool;
import org.zaproxy.addon.mcp.McpToolException;
import org.zaproxy.addon.mcp.McpToolResult;
import org.zaproxy.addon.mcp.tools.ZapGetHistoryTool.BodyWindow;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit tests for {@link ZapGetHistoryTool}. */
class ZapGetHistoryToolUnitTest extends TestUtils {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private ExtensionHistory extHistory;
    private ZapGetHistoryTool tool;

    @BeforeEach
    void setUp() {
        mockMessages(new ExtensionMcp());
        ExtensionLoader extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        extHistory = mock(ExtensionHistory.class, withSettings().strictness(Strictness.LENIENT));
        given(extensionLoader.getExtension(ExtensionHistory.class)).willReturn(extHistory);
        Control.initSingletonForTesting(mock(Model.class), extensionLoader);
        tool = new ZapGetHistoryTool();
    }

    @Test
    void shouldHaveExpectedNameAndRequiredId() {
        assertThat(tool.getName(), is(equalTo("zap_get_history")));
        assertThat(tool.getInputSchema().required(), is(equalTo(List.of("id"))));
        assertThat(tool.getInputSchema().properties().containsKey("fields"), is(true));
        assertThat(tool.getInputSchema().properties().containsKey("body_offset"), is(true));
        assertThat(tool.getInputSchema().properties().containsKey("max_body_chars"), is(true));
    }

    @Test
    void shouldDefaultToHeadersOnly() throws Exception {
        givenHistory(123, "req-body", "resp-body-content");

        McpToolResult result = tool.execute(args(Map.of("id", "123"), Map.of()));
        JsonNode json = MAPPER.readTree(result.text());

        assertThat(json.get("id").asInt(), is(equalTo(123)));
        assertThat(json.has("requestHeader"), is(true));
        assertThat(json.has("responseHeader"), is(true));
        assertThat(json.has("requestBody"), is(false));
        assertThat(json.has("responseBody"), is(false));
    }

    @Test
    void shouldReturnWindowedBodiesWithMetadata() throws Exception {
        givenHistory(7, "ABCDEFGHIJ", "0123456789");

        McpToolResult result =
                tool.execute(
                        args(
                                Map.of("id", "7", "body_offset", "2", "max_body_chars", "4"),
                                Map.of("fields", List.of("requestBody", "responseBody"))));
        JsonNode json = MAPPER.readTree(result.text());

        assertThat(json.get("requestBody").asText(), is(equalTo("CDEF")));
        assertThat(json.get("requestBodyLength").asInt(), is(equalTo(10)));
        assertThat(json.get("requestBodyOffset").asInt(), is(equalTo(2)));
        assertThat(json.get("requestBodyReturned").asInt(), is(equalTo(4)));
        assertThat(json.get("requestBodyTruncated").asBoolean(), is(true));

        assertThat(json.get("responseBody").asText(), is(equalTo("2345")));
        assertThat(json.get("responseBodyLength").asInt(), is(equalTo(10)));
        assertThat(json.get("responseBodyOffset").asInt(), is(equalTo(2)));
        assertThat(json.get("responseBodyReturned").asInt(), is(equalTo(4)));
        assertThat(json.get("responseBodyTruncated").asBoolean(), is(true));
    }

    @Test
    void shouldSupportNegativeBodyOffsetFromEnd() throws Exception {
        givenHistory(1, "ABCDEFGHIJ", "0123456789");

        McpToolResult result =
                tool.execute(
                        args(
                                Map.of("id", "1", "body_offset", "-3", "max_body_chars", "10"),
                                Map.of("fields", List.of("responseBody"))));
        JsonNode json = MAPPER.readTree(result.text());

        assertThat(json.get("responseBody").asText(), is(equalTo("789")));
        assertThat(json.get("responseBodyOffset").asInt(), is(equalTo(7)));
        assertThat(json.get("responseBodyReturned").asInt(), is(equalTo(3)));
        assertThat(json.get("responseBodyTruncated").asBoolean(), is(true));
    }

    @Test
    void shouldMarkBodiesNotTruncatedWhenFullyReturned() throws Exception {
        givenHistory(1, "abc", "xyz");

        McpToolResult result =
                tool.execute(
                        args(
                                Map.of("id", "1", "max_body_chars", "100"),
                                Map.of("fields", List.of("requestBody", "responseBody"))));
        JsonNode json = MAPPER.readTree(result.text());

        assertThat(json.get("requestBody").asText(), is(equalTo("abc")));
        assertThat(json.get("requestBodyTruncated").asBoolean(), is(false));
        assertThat(json.get("responseBody").asText(), is(equalTo("xyz")));
        assertThat(json.get("responseBodyTruncated").asBoolean(), is(false));
    }

    @Test
    void shouldRejectMissingId() {
        McpToolException e =
                assertThrows(McpToolException.class, () -> tool.execute(args(Map.of(), Map.of())));
        assertThat(e.getMessage(), containsString("id"));
    }

    @Test
    void shouldRejectInvalidId() {
        McpToolException e =
                assertThrows(
                        McpToolException.class,
                        () -> tool.execute(args(Map.of("id", "abc"), Map.of())));
        assertThat(e.getMessage(), containsString("number"));
    }

    @Test
    void shouldRejectUnknownField() {
        McpToolException e =
                assertThrows(
                        McpToolException.class,
                        () ->
                                tool.execute(
                                        args(
                                                Map.of("id", "1"),
                                                Map.of("fields", List.of("cookies")))));
        assertThat(e.getMessage(), containsString("cookies"));
    }

    @Test
    void shouldRejectNonPositiveMaxBodyChars() {
        McpToolException e =
                assertThrows(
                        McpToolException.class,
                        () ->
                                tool.execute(
                                        args(
                                                Map.of("id", "1", "max_body_chars", "0"),
                                                Map.of("fields", List.of("responseBody")))));
        assertThat(e.getMessage(), containsString("max_body_chars"));
    }

    @Test
    void shouldRejectMissingHistoryEntry() {
        given(extHistory.getHistoryReference(99)).willReturn(null);

        McpToolException e =
                assertThrows(
                        McpToolException.class,
                        () -> tool.execute(args(Map.of("id", "99"), Map.of())));
        assertThat(e.getMessage(), containsString("99"));
    }

    @Test
    void bodyWindowShouldClampPositiveOffsetPastEnd() {
        BodyWindow window = BodyWindow.of("abcd", 10, 4);
        assertThat(window.text(), is(equalTo("")));
        assertThat(window.offset(), is(equalTo(4)));
        assertThat(window.length(), is(equalTo(4)));
        assertThat(window.returned(), is(equalTo(0)));
        assertThat(window.truncated(), is(true));
    }

    @Test
    void bodyWindowShouldClampNegativeOffsetBeforeStart() {
        BodyWindow window = BodyWindow.of("abcd", -100, 2);
        assertThat(window.text(), is(equalTo("ab")));
        assertThat(window.offset(), is(equalTo(0)));
        assertThat(window.returned(), is(equalTo(2)));
        assertThat(window.truncated(), is(true));
    }

    private void givenHistory(int id, String requestBody, String responseBody) throws Exception {
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET /test HTTP/1.1\r\nHost: example.com\r\n");
        msg.setRequestBody(requestBody);
        msg.setResponseHeader("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n");
        msg.setResponseBody(responseBody);

        HistoryReference href =
                mock(HistoryReference.class, withSettings().strictness(Strictness.LENIENT));
        given(href.getHttpMessage()).willReturn(msg);
        given(extHistory.getHistoryReference(id)).willReturn(href);
    }

    private static McpTool.ToolArguments args(
            Map<String, String> strings, Map<String, List<String>> lists) {
        return new McpTool.ToolArguments(strings, lists);
    }
}
