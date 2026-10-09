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
package org.zaproxy.addon.dev.llm;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

/** Unit tests for {@link FakeLlmDir} and {@link FakeLlmRules}. */
class FakeLlmDirUnitTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final String LOGIN_FORM_PAYLOAD =
            "{\"step\":1,\"url\":\"http://localhost:8080/auth/simple-json/\",\"pageTitle\":\"ZAP Test Server\","
                    + "\"inputElements\":[{\"tag\":\"input\",\"type\":\"text\",\"id\":\"user\",\"name\":\"user\"},"
                    + "{\"tag\":\"input\",\"type\":\"password\",\"id\":\"password\",\"name\":\"password\"}],"
                    + "\"previousActions\":[]}";

    private static final String HOME_PAYLOAD =
            "{\"step\":2,\"url\":\"http://localhost:8080/auth/simple-json/home.html\",\"inputElements\":[]}";

    private static final Path RULES_FILE =
            Path.of("src/main/zapHomeFiles/dev-add-on/llm/fake/rules.json");

    private final FakeLlmDir dir = dirWith(readRules());

    private static String readRules() {
        try {
            return Files.readString(RULES_FILE);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static FakeLlmDir dirWith(String rules) {
        TestProxyServer server = mock(TestProxyServer.class);
        when(server.getTextFile(any(), any())).thenReturn(rules);
        return new FakeLlmDir(server, "fake");
    }

    private HttpMessage post(String path, String body) throws Exception {
        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader(
                                "POST http://localhost:8080"
                                        + path
                                        + " HTTP/1.1\r\nHost: localhost:8080"));
        msg.setRequestBody(body);
        return msg;
    }

    private static String request(String prompt) {
        ObjectNode request = MAPPER.createObjectNode().put("model", "m");
        var messages = request.putArray("messages");
        messages.addObject().put("role", "system").put("content", "be nice");
        messages.addObject().put("role", "user").put("content", prompt);
        return request.toString();
    }

    private static JsonNode json(String text) throws Exception {
        return MAPPER.readTree(text);
    }

    private String contentOf(HttpMessage msg) throws Exception {
        return json(msg.getResponseBody().toString())
                .path("choices")
                .path(0)
                .path("message")
                .path("content")
                .asText();
    }

    @Test
    void shouldReplyToMatchingPrompt() throws Exception {
        HttpMessage msg = post("/llm/fake/v1/chat/completions", request("please ping me"));
        dir.handleMessage(mock(HttpMessageHandlerContext.class), msg);
        assertThat(msg.getResponseHeader().getStatusCode(), is(equalTo(200)));
        assertThat(contentOf(msg), is(equalTo("pong")));
        assertThat(msg.getResponseBody().toString(), containsString("\"total_tokens\""));
    }

    @Test
    void shouldReplyWithDefaultWhenNoRuleMatches() throws Exception {
        HttpMessage msg = post("/llm/fake/v1/chat/completions", request("zzz"));
        dir.handleMessage(mock(HttpMessageHandlerContext.class), msg);
        assertThat(contentOf(msg), is(equalTo(FakeLlmRules.NO_MATCH_REPLY)));
    }

    @Test
    void shouldReturnJsonReplyAsStringContent() throws Exception {
        HttpMessage msg = post("/llm/fake/v1/chat/completions", request(LOGIN_FORM_PAYLOAD));
        dir.handleMessage(mock(HttpMessageHandlerContext.class), msg);
        JsonNode reply = json(contentOf(msg));
        assertThat(reply.path("state").asText(), is(equalTo("IN_PROGRESS")));
        assertThat(reply.path("actions").size(), is(equalTo(3)));
    }

    @Test
    void shouldReturnSuccessOnceOnHomePage() throws Exception {
        HttpMessage msg = post("/llm/fake/v1/chat/completions", request(HOME_PAYLOAD));
        dir.handleMessage(mock(HttpMessageHandlerContext.class), msg);
        assertThat(json(contentOf(msg)).path("state").asText(), is(equalTo("SUCCESS")));
    }

    @Test
    void shouldRespondWithNoMatchReplyIfRulesFileMissing() throws Exception {
        HttpMessage msg = post("/llm/fake/v1/chat/completions", request("ping"));
        dirWith(null).handleMessage(mock(HttpMessageHandlerContext.class), msg);
        assertThat(contentOf(msg), is(equalTo(FakeLlmRules.NO_MATCH_REPLY)));
    }

    @Test
    void shouldReturnNullValuesFromRulesFile() throws Exception {
        HttpMessage msg = post("/llm/fake/v1/chat/completions", request(LOGIN_FORM_PAYLOAD));
        dir.handleMessage(mock(HttpMessageHandlerContext.class), msg);
        assertThat(contentOf(msg), containsString("\"value\":null"));
    }

    @Test
    void shouldRejectInvalidJson() throws Exception {
        HttpMessage msg = post("/llm/fake/v1/chat/completions", "not json");
        dir.handleMessage(mock(HttpMessageHandlerContext.class), msg);
        assertThat(msg.getResponseHeader().getStatusCode(), is(equalTo(400)));
    }

    @Test
    void shouldListModels() throws Exception {
        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader(
                                "GET http://localhost:8080/llm/fake/v1/models HTTP/1.1\r\nHost: localhost:8080"));
        dir.handleMessage(mock(HttpMessageHandlerContext.class), msg);
        assertThat(msg.getResponseBody().toString(), containsString("fake-llm"));
    }

    @Test
    void shouldUseRulesFromFileAndSkipInvalidOnes() throws Exception {
        TestProxyServer server = mock(TestProxyServer.class);
        FakeLlmDir custom = new FakeLlmDir(server, "fake");
        when(server.getTextFile(any(), any()))
                .thenReturn(
                        "[{\"match\":\"foo\",\"reply\":{\"a\":1}},{\"match\":\"(\",\"reply\":\"bad\"}]");
        HttpMessage msg = post("/llm/fake/v1/chat/completions", request("foo"));
        custom.handleMessage(mock(HttpMessageHandlerContext.class), msg);
        assertThat(contentOf(msg), is(equalTo("{\"a\":1}")));
    }

    @Test
    void shouldIgnoreNonUserMessagesAndHandleContentParts() throws Exception {
        JsonNode req =
                json(
                        "{\"messages\":[{\"role\":\"user\",\"content\":\"old\"},"
                                + "{\"role\":\"assistant\",\"content\":\"x\"},"
                                + "{\"role\":\"user\",\"content\":[{\"type\":\"text\",\"text\":\"new\"}]}]}");
        assertThat(FakeLlmDir.getLastUserMessage(req), is(equalTo("new")));
    }
}
