/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.zap.extension.openapi.spider;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.ValueProvider;
import org.zaproxy.addon.spider.parser.ParseContext;
import org.zaproxy.zap.extension.openapi.AbstractServerTest;
import org.zaproxy.zap.testutils.NanoServerHandler;

/** Unit test for {@link OpenApiSpider}. */
class OpenApiSpiderUnitTest extends AbstractServerTest {

    private ValueProvider valueProvider;
    private OpenApiSpider spider;

    @BeforeEach
    void setupSpider() {
        valueProvider = mock(ValueProvider.class);
        spider = new OpenApiSpider(() -> valueProvider);
    }

    @ParameterizedTest
    @CsvSource({
        "application/vnd.oai.openapi, , true",
        "json, swagger, true",
        "json, openapi, true",
        "yaml, swagger, true",
        "yaml, openapi, true",
        "json, not swag ger, false",
        "json, not open api, false",
        "yaml, not swag ger, false",
        "yaml, not open api, false",
        "not y aml or j son, swagger, false",
        "not y aml or j son, openapi, false"
    })
    void shouldProperlyDetectLikelyOpenApiResource(
            String contentType, String body, boolean expected) throws Exception {
        // Given
        HttpMessage message = new HttpMessage();
        message.setResponseHeader(
                """
                HTTP/1.1 200
                Content-Type: %s
                """
                        .formatted(contentType));
        message.setResponseBody(body);
        ParseContext ctx = mock(ParseContext.class);
        given(ctx.getHttpMessage()).willReturn(message);
        // When
        boolean canParse = spider.canParseResource(ctx, false);
        // Then
        assertThat(canParse, is(equalTo(expected)));
    }

    @Test
    void shouldParseResource() throws Exception {
        // Given
        List<String> accessedUris = new ArrayList<>();
        this.nano.addHandler(
                new NanoServerHandler("") {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        accessedUris.add(session.getUri());
                        return newFixedLengthResponse("");
                    }
                });
        HttpMessage message = getHttpMessage("");
        message.setResponseBody(
                "openapi: 3.0.0\n"
                        + "servers:\n"
                        + "  - url: http://localhost:"
                        + nano.getListeningPort()
                        + "\n"
                        + "paths:\n"
                        + "  /path:\n"
                        + "    get:\n"
                        + "      responses:\n"
                        + "        200:\n"
                        + "          content:\n"
                        + "            application/json: {}");
        ParseContext ctx = mock(ParseContext.class);
        given(ctx.getHttpMessage()).willReturn(message);
        // When
        spider.parseResource(ctx);
        // Then
        assertThat(accessedUris, contains("/path"));
    }
}
