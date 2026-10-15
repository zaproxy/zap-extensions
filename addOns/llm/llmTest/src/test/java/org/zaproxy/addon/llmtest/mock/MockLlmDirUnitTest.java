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
package org.zaproxy.addon.llmtest.mock;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
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
import org.zaproxy.addon.dev.TestDirectory;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

/** Unit tests for {@link MockLlmDir} and {@link MockLlmRules}. */
class MockLlmDirUnitTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final Path HOME_FILES =
            Path.of("src/main/zapHomeFiles/addOnData/dev/server/llm/mock");

    private static final String COMPLETIONS = "/llm/mock/v1/chat/completions";
    private static final String EXAMPLE_COMPLETIONS = "/llm/mock/example/v1/chat/completions";

    private final TestProxyServer server = mock(TestProxyServer.class);
    private final MockLlmDir dir = new MockLlmDir(server, "mock");

    MockLlmDirUnitTest() {
        // Mounted as in the dev server, at /llm/mock.
        TestDirectory root = new TestDirectory(server, "");
        TestDirectory llm = new TestDirectory(server, "llm");
        root.addDirectory(llm);
        llm.addDirectory(dir);
        // The files are those shipped with the add-on.
        when(server.getTextFile(any(), any())).thenReturn(null);
        when(server.getTextFile(any(), eq("rules.json"))).thenReturn(read("rules.json"));
        when(server.getTextFile(any(), eq("example/rules.json")))
                .thenReturn(read("example/rules.json"));
    }

    private static String read(String file) {
        try {
            return Files.readString(HOME_FILES.resolve(file));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
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

    private HttpMessage handle(String path, String prompt) throws Exception {
        HttpMessage msg = post(path, request(prompt));
        dir.handleMessage(mock(HttpMessageHandlerContext.class), msg);
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

    private static String contentOf(HttpMessage msg) throws Exception {
        return json(msg.getResponseBody().toString())
                .path("choices")
                .path(0)
                .path("message")
                .path("content")
                .asText();
    }

    @Test
    void shouldReplyToMatchingPrompt() throws Exception {
        HttpMessage msg = handle(COMPLETIONS, "please ping me");
        assertThat(msg.getResponseHeader().getStatusCode(), is(equalTo(200)));
        assertThat(contentOf(msg), is(equalTo("pong")));
        assertThat(msg.getResponseBody().toString(), containsString("\"total_tokens\""));
    }

    @Test
    void shouldReplyWithDefaultWhenNoRuleMatches() throws Exception {
        assertThat(contentOf(handle(COMPLETIONS, "zzz")), is(equalTo(MockLlmRules.NO_MATCH_REPLY)));
    }

    @Test
    void shouldRespondWithNoMatchReplyIfRulesFileMissing() throws Exception {
        when(server.getTextFile(any(), eq("rules.json"))).thenReturn(null);
        assertThat(
                contentOf(handle(COMPLETIONS, "ping")), is(equalTo(MockLlmRules.NO_MATCH_REPLY)));
    }

    @Test
    void shouldReturnJsonReplyAsStringContent() throws Exception {
        when(server.getTextFile(any(), eq("rules.json")))
                .thenReturn("[{\"match\":\"foo\",\"reply\":{\"a\":1,\"b\":null}}]");
        assertThat(contentOf(handle(COMPLETIONS, "foo")), is(equalTo("{\"a\":1,\"b\":null}")));
    }

    @Test
    void shouldSkipInvalidRules() throws Exception {
        when(server.getTextFile(any(), eq("rules.json")))
                .thenReturn(
                        "[{\"match\":\"(\",\"reply\":\"bad\"},{\"match\":\"foo\",\"reply\":\"ok\"}]");
        assertThat(contentOf(handle(COMPLETIONS, "foo")), is(equalTo("ok")));
    }

    @Test
    void shouldRejectInvalidJson() throws Exception {
        HttpMessage msg = post(COMPLETIONS, "not json");
        dir.handleMessage(mock(HttpMessageHandlerContext.class), msg);
        assertThat(msg.getResponseHeader().getStatusCode(), is(equalTo(400)));
    }

    @Test
    void shouldListModels() throws Exception {
        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader(
                                "GET http://localhost:8080/llm/mock/v1/models HTTP/1.1\r\nHost: localhost:8080"));
        dir.handleMessage(mock(HttpMessageHandlerContext.class), msg);
        assertThat(msg.getResponseBody().toString(), containsString("mock-llm"));
    }

    @Test
    void shouldIgnoreNonUserMessagesAndHandleContentParts() throws Exception {
        JsonNode req =
                json(
                        "{\"messages\":[{\"role\":\"user\",\"content\":\"old\"},"
                                + "{\"role\":\"assistant\",\"content\":\"x\"},"
                                + "{\"role\":\"user\",\"content\":[{\"type\":\"text\",\"text\":\"new\"}]}]}");
        assertThat(MockLlmDir.getLastUserMessage(req), is(equalTo("new")));
    }

    @Test
    void shouldIgnoreMessagesThatAreNotAnArrayOfObjects() throws Exception {
        assertThat(
                MockLlmDir.getLastUserMessage(json("{\"messages\":{\"role\":\"user\"}}")),
                is(equalTo("")));
        assertThat(
                MockLlmDir.getLastUserMessage(json("{\"messages\":[null,\"user\"]}")),
                is(equalTo("")));
    }

    @Test
    void shouldHandleMalformedMessagesWithoutFailing() throws Exception {
        HttpMessage msg = post(COMPLETIONS, "{\"messages\":{\"role\":\"user\"}}");
        dir.handleMessage(mock(HttpMessageHandlerContext.class), msg);
        assertThat(msg.getResponseHeader().getStatusCode(), is(equalTo(200)));
    }

    @Test
    void shouldUseRuleSetNamedAsTheDirectory() throws Exception {
        dir.addRuleSet("mock", () -> "[{\"match\":\"ping\",\"reply\":\"mock mock\"}]");
        assertThat(
                contentOf(handle("/llm/mock/mock/v1/chat/completions", "ping")),
                is(equalTo("mock mock")));
        // The default rules are unaffected.
        assertThat(contentOf(handle(COMPLETIONS, "ping")), is(equalTo("pong")));
    }

    @Test
    void shouldRespondNotFoundForUnknownRuleSetNamedAsTheDirectory() throws Exception {
        for (String api : new String[] {"chat/completions", "models"}) {
            HttpMessage msg = handle("/llm/mock/mock/v1/" + api, "ping");
            assertThat(msg.getResponseHeader().getStatusCode(), is(equalTo(404)));
        }
    }

    @Test
    void shouldUseRuleSetFromFileByConvention() throws Exception {
        HttpMessage msg = handle(EXAMPLE_COMPLETIONS, "ping");
        assertThat(msg.getResponseHeader().getStatusCode(), is(equalTo(200)));
        assertThat(contentOf(msg), is(equalTo("pong from the example rule set")));
    }

    @Test
    void shouldNotUseDefaultRulesForRuleSet() throws Exception {
        // The default rules reply to hello, the example rule set does not.
        assertThat(
                contentOf(handle(EXAMPLE_COMPLETIONS, "hello")),
                is(equalTo(MockLlmRules.NO_MATCH_REPLY)));
    }

    @Test
    void shouldUseRuleSetAdded() throws Exception {
        dir.addRuleSet("added", () -> "[{\"match\":\"ping\",\"reply\":\"added pong\"}]");
        assertThat(
                contentOf(handle("/llm/mock/added/v1/chat/completions", "ping")),
                is(equalTo("added pong")));
    }

    @Test
    void shouldPreferRuleSetAddedOverFile() throws Exception {
        dir.addRuleSet("example", () -> "[{\"match\":\"ping\",\"reply\":\"override\"}]");
        assertThat(contentOf(handle(EXAMPLE_COMPLETIONS, "ping")), is(equalTo("override")));
    }

    @Test
    void shouldNoLongerFindRuleSetRemoved() throws Exception {
        dir.addRuleSet("added", () -> "[]");
        dir.removeRuleSet("added");
        HttpMessage msg = handle("/llm/mock/added/v1/chat/completions", "ping");
        assertThat(msg.getResponseHeader().getStatusCode(), is(equalTo(404)));
    }

    @Test
    void shouldRespondNotFoundForUnknownRuleSet() throws Exception {
        HttpMessage msg = handle("/llm/mock/nope/v1/chat/completions", "ping");
        assertThat(msg.getResponseHeader().getStatusCode(), is(equalTo(404)));
        assertThat(msg.getResponseBody().toString(), containsString("No such rule set: nope"));
    }

    @Test
    void shouldNotReadFilesForInvalidRuleSetNames() throws Exception {
        HttpMessage msg = handle("/llm/mock/../v1/chat/completions", "ping");
        assertThat(msg.getResponseHeader().getStatusCode(), is(equalTo(404)));
    }

    @Test
    void shouldRejectInvalidRuleSetNames() {
        assertThrows(IllegalArgumentException.class, () -> dir.addRuleSet("a/b", () -> "[]"));
        assertThrows(IllegalArgumentException.class, () -> dir.addRuleSet("..", () -> "[]"));
        assertThrows(IllegalArgumentException.class, () -> dir.addRuleSet("", () -> "[]"));
    }
}
