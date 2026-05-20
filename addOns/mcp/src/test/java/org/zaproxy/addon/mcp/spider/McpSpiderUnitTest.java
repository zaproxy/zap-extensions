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
package org.zaproxy.addon.mcp.spider;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.mcp.importer.McpImporter;
import org.zaproxy.addon.mcp.importer.McpImporter.ImportConfig;
import org.zaproxy.addon.mcp.importer.McpImporter.ImportResults;
import org.zaproxy.addon.spider.parser.ParseContext;

/** Unit tests for {@link McpSpider}. */
class McpSpiderUnitTest {

    private List<String> importedUrls;
    private McpImporter importer;
    private McpSpider spider;

    @BeforeEach
    void setUp() {
        importedUrls = new ArrayList<>();
        importer = mock(McpImporter.class, withSettings().strictness(Strictness.LENIENT));
        willAnswer(
                        inv -> {
                            ImportConfig cfg = inv.getArgument(0);
                            importedUrls.add(cfg.serverUrl());
                            return new ImportResults(1, List.of());
                        })
                .given(importer)
                .importServer(any(ImportConfig.class));
        spider = new McpSpider(() -> importer);
    }

    @ParameterizedTest
    @CsvSource({
        // content-type, body snippet, expected canParse
        "application/json, '{\"jsonrpc\":\"2.0\",\"result\":{\"protocolVersion\":\"2024-11-05\"}}', true",
        "application/json, '{\"jsonrpc\":\"2.0\",\"method\":\"tools/list\"}', true",
        "application/json, '{\"jsonrpc\":\"2.0\",\"method\":\"resources/list\"}', true",
        "application/json, '{\"jsonrpc\":\"2.0\",\"method\":\"prompts/list\"}', true",
        "application/json; charset=utf-8, '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"mcp\":true}}', true",
        "application/json, '{\"server\":{\"name\":\"evmcp\"},\"protocolVersion\":\"2024-11-05\",\"capabilities\":{\"tools\":{}}}', true",
        "text/event-stream, 'event: endpoint\\ndata: /messages', true",
        "text/event-stream, 'data: {\"jsonrpc\":\"2.0\"}', true",
        "application/json, '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}', false",
        "application/json, '{\"foo\":\"bar\"}', false",
        "text/html, '<html><body>hi</body></html>', false",
        "text/event-stream, 'data: hello world', false",
    })
    void shouldDetectMcpResponses(String contentType, String body, boolean expected)
            throws Exception {
        // Given
        HttpMessage message = new HttpMessage();
        message.setResponseHeader(
                "HTTP/1.1 200 OK\r\nContent-Type: " + contentType.trim() + "\r\n\r\n");
        message.setResponseBody(body);
        ParseContext ctx = mock(ParseContext.class);
        given(ctx.getHttpMessage()).willReturn(message);

        // When
        boolean canParse = spider.canParseResource(ctx, false);

        // Then
        assertThat(canParse, is(equalTo(expected)));
    }

    @Test
    void shouldReturnTrueWhenMcpHeaderPresent() throws Exception {
        // Given
        HttpMessage message = new HttpMessage();
        message.setResponseHeader("HTTP/1.1 200 OK\\r\\nmcp-protocol-version: 1.0\r\n\r\n");
        message.setResponseBody("{\"jsonrpc\":\"2.0\"}");
        ParseContext ctx = mock(ParseContext.class);
        given(ctx.getHttpMessage()).willReturn(message);

        // When
        boolean canParse = spider.canParseResource(ctx, false);

        // Then
        assertThat(canParse, is(false));
    }

    @Test
    void shouldReturnFalseWhenContentTypeMissing() throws Exception {
        // Given
        HttpMessage message = new HttpMessage();
        message.setResponseHeader("HTTP/1.1 200 OK\r\n\r\n");
        message.setResponseBody("{\"jsonrpc\":\"2.0\"}");
        ParseContext ctx = mock(ParseContext.class);
        given(ctx.getHttpMessage()).willReturn(message);

        // When
        boolean canParse = spider.canParseResource(ctx, false);

        // Then
        assertThat(canParse, is(false));
    }

    @Test
    void shouldInvokeImporterOnResourceUrl() throws Exception {
        // Given
        ParseContext ctx = parseContextFor("http://example.com:8080/mcp");

        // When
        boolean consumed = spider.parseResource(ctx);

        // Then
        assertThat(consumed, is(false));
        assertThat(importedUrls, equalTo(List.of("http://example.com:8080/mcp")));
    }

    @Test
    void shouldNotConsumeWhenImporterThrows() throws Exception {
        // Given
        willAnswer(
                        inv -> {
                            throw new RuntimeException("boom");
                        })
                .given(importer)
                .importServer(any(ImportConfig.class));
        ParseContext ctx = parseContextFor("http://example.com/mcp");

        // When
        boolean consumed = spider.parseResource(ctx);

        // Then
        assertThat(consumed, is(false));
    }

    private static ParseContext parseContextFor(String url) throws Exception {
        HttpMessage message = new HttpMessage(new org.apache.commons.httpclient.URI(url, true));
        ParseContext ctx = mock(ParseContext.class);
        given(ctx.getHttpMessage()).willReturn(message);
        return ctx;
    }
}
