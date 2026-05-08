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
package org.zaproxy.addon.mcp.importer;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.parosproxy.paros.network.HttpMessage;

/** Unit tests for {@link VariantMcpJsonRpc}. */
class VariantMcpJsonRpcUnitTest {

    private VariantMcpJsonRpc variant;

    @BeforeEach
    void setUp() {
        variant = new VariantMcpJsonRpc();
    }

    // ---- getTreePath ----

    @Test
    void shouldReturnNullTreePathForGetRequest() throws Exception {
        HttpMessage msg = createGetMessage();
        assertThat(variant.getTreePath(msg), is(nullValue()));
    }

    @Test
    void shouldReturnNullTreePathForNonJsonRpcPost() throws Exception {
        HttpMessage msg = createPostMessage("{\"not\":\"jsonrpc\"}");
        assertThat(variant.getTreePath(msg), is(nullValue()));
    }

    @Test
    void shouldReturnNullTreePathForEmptyBody() throws Exception {
        HttpMessage msg = createPostMessage("");
        assertThat(variant.getTreePath(msg), is(nullValue()));
    }

    static Stream<Arguments> treePaths() {
        return Stream.of(
                arguments(
                        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\","
                                + "\"params\":{\"protocolVersion\":\"2024-11-05\"}}",
                        List.of("initialize")),
                arguments(
                        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}",
                        List.of("tools", "list")),
                arguments(
                        "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"resources/list\"}",
                        List.of("resources", "list")),
                arguments(
                        "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"prompts/list\"}",
                        List.of("prompts", "list")),
                // tools/call appends the tool name as a qualifier
                arguments(
                        "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\","
                                + "\"params\":{\"name\":\"zap_version\",\"arguments\":{}}}",
                        List.of("tools", "call", "zap_version")),
                // prompts/get appends the prompt name as a qualifier
                arguments(
                        "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"prompts/get\","
                                + "\"params\":{\"name\":\"zap_baseline_scan\",\"arguments\":{}}}",
                        List.of("prompts", "get", "zap_baseline_scan")),
                // resources/read uses the URI to build the path, grouped under "resources"
                arguments(
                        "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"resources/read\","
                                + "\"params\":{\"uri\":\"zap://alerts\"}}",
                        List.of("resources", "zap", "alerts")),
                // template var {alertRef} is stripped from the path
                arguments(
                        "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"resources/read\","
                                + "\"params\":{\"uri\":\"zap://alerts/{alertRef}\"}}",
                        List.of("resources", "zap", "alerts")),
                // non-template path segments are each their own node
                arguments(
                        "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"resources/read\","
                                + "\"params\":{\"uri\":\"logs://app/errors\"}}",
                        List.of("resources", "logs", "app", "errors")),
                // query string is stripped from the path
                arguments(
                        "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"resources/read\","
                                + "\"params\":{\"uri\":\"logs://app/errors?limit=100&level=warn\"}}",
                        List.of("resources", "logs", "app", "errors")));
    }

    @ParameterizedTest
    @MethodSource("treePaths")
    void shouldBuildTreePath(String body, List<String> expectedPath) throws Exception {
        assertThat(variant.getTreePath(createPostMessage(body)), equalTo(expectedPath));
    }

    // ---- getLeafName ----

    @Test
    void shouldReturnNullLeafNameForNonJsonRpc() throws Exception {
        HttpMessage msg = createGetMessage();
        assertThat(variant.getLeafName("foo", msg), is(nullValue()));
    }

    @Test
    void shouldReturnPostPrefixedLeafNameWithNoParams() throws Exception {
        // ZAP passes the URL path ("/") as nodeName; the variant derives the correct name from body
        HttpMessage msg =
                createPostMessage("{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}");
        assertThat(variant.getLeafName("/", msg), equalTo("POST: list()"));
    }

    @Test
    void shouldReturnPostPrefixedLeafNameWithParams() throws Exception {
        HttpMessage msg =
                createPostMessage(
                        "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\","
                                + "\"params\":{\"name\":\"zap_start_spider\","
                                + "\"arguments\":{\"target\":\"http://example.com\"}}}");
        assertThat(variant.getLeafName("/", msg), equalTo("POST: zap_start_spider(target)"));
    }

    @Test
    void shouldReturnPostPrefixedLeafNameWithMultipleParams() throws Exception {
        HttpMessage msg =
                createPostMessage(
                        "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\","
                                + "\"params\":{\"name\":\"zap_start_active_scan\","
                                + "\"arguments\":{\"target\":\"http://example.com\","
                                + "\"policy\":\"Default Policy\"}}}");
        assertThat(
                variant.getLeafName("/", msg),
                equalTo("POST: zap_start_active_scan(target,policy)"));
    }

    @Test
    void shouldReturnPostPrefixedLeafNameForResourcesReadAuthority() throws Exception {
        // Tree path ends at "alerts"; leaf name is derived from that, not the passed-in "/"
        HttpMessage msg =
                createPostMessage(
                        "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"resources/read\","
                                + "\"params\":{\"uri\":\"zap://alerts/{alertRef}\"}}");
        assertThat(variant.getLeafName("/", msg), equalTo("POST: alerts(alertRef)"));
    }

    @Test
    void shouldReturnPostPrefixedLeafNameForResourcesReadQueryParams() throws Exception {
        HttpMessage msg =
                createPostMessage(
                        "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"resources/read\","
                                + "\"params\":{\"uri\":\"logs://app/errors?limit=100&level=warn\"}}");
        assertThat(variant.getLeafName("/", msg), equalTo("POST: errors(limit,level)"));
    }

    // ---- helpers ----

    private static HttpMessage createPostMessage(String body) throws Exception {
        HttpMessage msg = new HttpMessage();
        String header =
                "POST / HTTP/1.1\r\n"
                        + "Host: localhost:8282\r\n"
                        + "Content-Type: application/json\r\n"
                        + "Content-Length: "
                        + body.length()
                        + "\r\n\r\n";
        msg.setRequestHeader(header);
        msg.setRequestBody(body);
        return msg;
    }

    private static HttpMessage createGetMessage() throws Exception {
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1\r\nHost: localhost:8282\r\n\r\n");
        return msg;
    }
}
