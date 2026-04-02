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
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.parosproxy.paros.core.scanner.NameValuePair;
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

    // ---- setMessage / getParamList — routing fields ignored ----

    @Test
    void shouldExtractNoParamsForToolsList() throws Exception {
        HttpMessage msg =
                createPostMessage("{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}");
        variant.setMessage(msg);
        assertThat(variant.getParamList(), is(empty()));
    }

    @Test
    void shouldIgnoreNameFieldForToolsCall() throws Exception {
        HttpMessage msg =
                createPostMessage(
                        "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\","
                                + "\"params\":{\"name\":\"zap_start_spider\",\"arguments\":{}}}");
        variant.setMessage(msg);
        // "name" is a routing field for tools/call — should not appear as a param
        assertThat(variant.getParamList(), is(empty()));
        for (NameValuePair p : variant.getParamList()) {
            assertThat(p.getName(), is(not(equalTo("name"))));
        }
    }

    @Test
    void shouldIgnoreNameFieldForPromptsGet() throws Exception {
        HttpMessage msg =
                createPostMessage(
                        "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"prompts/get\","
                                + "\"params\":{\"name\":\"zap_baseline_scan\",\"arguments\":{}}}");
        variant.setMessage(msg);
        assertThat(variant.getParamList(), is(empty()));
    }

    // ---- setMessage / getParamList — argument flattening ----

    @Test
    void shouldFlattenArgumentsForToolsCall() throws Exception {
        HttpMessage msg =
                createPostMessage(
                        "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\","
                                + "\"params\":{\"name\":\"zap_start_spider\","
                                + "\"arguments\":{\"target\":\"http://example.com\"}}}");
        variant.setMessage(msg);
        List<NameValuePair> params = variant.getParamList();
        // Only "target" should appear — no "name", no "arguments.target"
        assertThat(params.size(), is(1));
        assertThat(params.get(0).getName(), equalTo("target"));
        assertThat(params.get(0).getValue(), equalTo("http://example.com"));
        assertThat(params.get(0).getType(), equalTo(NameValuePair.TYPE_JSON));
    }

    @Test
    void shouldFlattenMultipleArgumentsForToolsCall() throws Exception {
        HttpMessage msg =
                createPostMessage(
                        "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\","
                                + "\"params\":{\"name\":\"zap_start_active_scan\","
                                + "\"arguments\":{\"target\":\"http://example.com\","
                                + "\"policy\":\"Default Policy\"}}}");
        variant.setMessage(msg);
        List<NameValuePair> params = variant.getParamList();
        assertThat(params.size(), is(2));
        assertThat(params.get(0).getName(), equalTo("target"));
        assertThat(params.get(1).getName(), equalTo("policy"));
    }

    @Test
    void shouldExposeNoParamForResourcesReadPlainUri() throws Exception {
        // Plain uri (no template, no query) is used for tree structure only — not a fuzz param
        HttpMessage msg =
                createPostMessage(
                        "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"resources/read\","
                                + "\"params\":{\"uri\":\"zap://alerts\"}}");
        variant.setMessage(msg);
        assertThat(variant.getParamList(), is(empty()));
    }

    // ---- template variable extraction ----

    @Test
    void shouldExtractTemplateVarFromUri() throws Exception {
        HttpMessage msg =
                createPostMessage(
                        "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"resources/read\","
                                + "\"params\":{\"uri\":\"zap://alerts/{alertRef}\"}}");
        variant.setMessage(msg);
        List<NameValuePair> params = variant.getParamList();
        // Should expose "alertRef" as a param, NOT the raw "uri" string
        assertThat(params.size(), is(1));
        assertThat(params.get(0).getName(), equalTo("alertRef"));
        assertThat(params.get(0).getValue(), equalTo(""));
        assertThat(params.get(0).getType(), equalTo(NameValuePair.TYPE_JSON));
    }

    @Test
    void shouldExtractTemplateVarFromHistoryUri() throws Exception {
        HttpMessage msg =
                createPostMessage(
                        "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"resources/read\","
                                + "\"params\":{\"uri\":\"zap://history/{id}\"}}");
        variant.setMessage(msg);
        List<NameValuePair> params = variant.getParamList();
        assertThat(params.size(), is(1));
        assertThat(params.get(0).getName(), equalTo("id"));
    }

    @Test
    void shouldExtractMultipleTemplateVarsFromUri() throws Exception {
        HttpMessage msg =
                createPostMessage(
                        "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"resources/read\","
                                + "\"params\":{\"uri\":\"zap://items/{type}/{id}\"}}");
        variant.setMessage(msg);
        List<NameValuePair> params = variant.getParamList();
        assertThat(params.size(), is(2));
        assertThat(params.get(0).getName(), equalTo("type"));
        assertThat(params.get(1).getName(), equalTo("id"));
    }

    @Test
    void shouldExtractQueryStringParamsFromUri() throws Exception {
        HttpMessage msg =
                createPostMessage(
                        "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"resources/read\","
                                + "\"params\":{\"uri\":\"logs://app/errors?limit=100&level=warn\"}}");
        variant.setMessage(msg);
        List<NameValuePair> params = variant.getParamList();
        assertThat(params.size(), is(2));
        assertThat(params.get(0).getName(), equalTo("limit"));
        assertThat(params.get(0).getValue(), equalTo("100"));
        assertThat(params.get(1).getName(), equalTo("level"));
        assertThat(params.get(1).getValue(), equalTo("warn"));
    }

    @Test
    void shouldClearParamsOnSubsequentSetMessage() throws Exception {
        HttpMessage msg1 =
                createPostMessage(
                        "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"resources/read\","
                                + "\"params\":{\"uri\":\"zap://alerts/{alertRef}\"}}");
        HttpMessage msg2 =
                createPostMessage("{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}");
        variant.setMessage(msg1);
        assertThat(variant.getParamList().size(), is(1));
        variant.setMessage(msg2);
        assertThat(variant.getParamList(), is(empty()));
    }

    // ---- setParameter — regular params ----

    @Test
    void shouldSetFlattenedArgumentParam() throws Exception {
        HttpMessage msg =
                createPostMessage(
                        "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\","
                                + "\"params\":{\"name\":\"zap_start_spider\","
                                + "\"arguments\":{\"target\":\"http://example.com\"}}}");
        variant.setMessage(msg);
        NameValuePair original = variant.getParamList().get(0); // "target"
        String result = variant.setParameter(msg, original, "target", "PAYLOAD");
        assertThat(result, equalTo("PAYLOAD"));
        assertThat(msg.getRequestBody().toString(), containsString("\"target\":\"PAYLOAD\""));
        // Envelope fields must be preserved
        assertThat(msg.getRequestBody().toString(), containsString("\"jsonrpc\":\"2.0\""));
        assertThat(msg.getRequestBody().toString(), containsString("\"method\":\"tools/call\""));
    }

    // ---- setParameter — template variable params ----

    @Test
    void shouldSetTemplateVarParam() throws Exception {
        HttpMessage msg =
                createPostMessage(
                        "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"resources/read\","
                                + "\"params\":{\"uri\":\"zap://alerts/{alertRef}\"}}");
        variant.setMessage(msg);
        NameValuePair original = variant.getParamList().get(0); // "alertRef"
        String result = variant.setParameter(msg, original, "alertRef", "10055-1");
        assertThat(result, equalTo("10055-1"));
        assertThat(
                msg.getRequestBody().toString(),
                containsString("\"uri\":\"zap://alerts/10055-1\""));
    }

    @Test
    void shouldPreserveOtherTemplateVarsWhenSettingOne() throws Exception {
        HttpMessage msg =
                createPostMessage(
                        "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"resources/read\","
                                + "\"params\":{\"uri\":\"zap://items/{type}/{id}\"}}");
        variant.setMessage(msg);
        NameValuePair original = variant.getParamList().get(0); // "type"
        variant.setParameter(msg, original, "type", "alert");
        assertThat(
                msg.getRequestBody().toString(),
                containsString("\"uri\":\"zap://items/alert/{id}\""));
    }

    // ---- setParameter — query string params ----

    @Test
    void shouldSetQueryStringParam() throws Exception {
        HttpMessage msg =
                createPostMessage(
                        "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"resources/read\","
                                + "\"params\":{\"uri\":\"logs://app/errors?limit=100&level=warn\"}}");
        variant.setMessage(msg);
        NameValuePair original = variant.getParamList().get(0); // "limit"
        String result = variant.setParameter(msg, original, "limit", "FUZZ");
        assertThat(result, equalTo("FUZZ"));
        assertThat(
                msg.getRequestBody().toString(),
                containsString("\"uri\":\"logs://app/errors?limit=FUZZ&level=warn\""));
    }

    @Test
    void shouldReturnNullForSetParameterOnNonJsonRpc() throws Exception {
        HttpMessage msg = createGetMessage();
        assertThat(variant.setParameter(msg, null, "key", "value"), is(nullValue()));
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
