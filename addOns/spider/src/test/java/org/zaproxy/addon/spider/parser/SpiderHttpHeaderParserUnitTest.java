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
package org.zaproxy.addon.spider.parser;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;

/** Unit test for {@link SpiderHttpHeaderParser}. */
class SpiderHttpHeaderParserUnitTest extends SpiderParserTestUtils<SpiderHttpHeaderParser> {

    @Override
    protected SpiderHttpHeaderParser createParser() {
        try {
            msg.setRequestHeader("GET / HTTP/1.1\r\nHost: example.com\r\n");
            msg.setResponseHeader("HTTP/1.1 200 OK\r\n");
        } catch (HttpMalformedHeaderException e) {
            throw new RuntimeException(e);
        }

        return new SpiderHttpHeaderParser();
    }

    @Test
    void shouldParseAnyMessage() {
        // Given / When
        boolean canParse = parser.canParseResource(ctx, false);
        // Then
        assertThat(canParse, is(equalTo(true)));
    }

    @Test
    void shouldParseAnyMessageEvenIfAlreadyParsed() {
        // Given
        boolean alreadyParsed = true;
        // When
        boolean canParse = parser.canParseResource(ctx, alreadyParsed);
        // Then
        assertThat(canParse, is(equalTo(true)));
    }

    @Test
    void shouldFailToParseAnUndefinedContext() {
        // Given
        ParseContext ctx = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> parser.parseResource(ctx));
    }

    @Test
    void shouldNotExtractUrlIfNoUrlHeadersPresent() {
        // Given / When
        boolean parsed = parser.parseResource(ctx);
        // Then
        assertThat(parsed, is(equalTo(false)));
        assertThat(listener.getUrlsFound(), is(empty()));
    }

    @ParameterizedTest
    @ValueSource(strings = {HttpHeader.CONTENT_LOCATION, HttpHeader.REFRESH, HttpHeader.LINK})
    void shouldNotExtractUrlIfUrlHeaderIsEmpty(String header) {
        // Given
        msg.getResponseHeader().addHeader(header, "");
        // When
        boolean parsed = parser.parseResource(ctx);
        // Then
        assertThat(parsed, is(equalTo(false)));
        assertThat(listener.getUrlsFound(), is(empty()));
    }

    @ParameterizedTest
    @NullAndEmptySource
    void shouldNotExtractUrlIfUrlFromLinkHeaderValueIsEmptyorNull(String value) {
        // Given
        msg.getResponseHeader().addHeader(HttpHeader.LINK, value);
        // When
        boolean parsed = parser.parseResource(ctx);
        // Then
        assertThat(parsed, is(equalTo(false)));
        assertThat(listener.getUrlsFound(), is(empty()));
    }

    @Test
    void shouldExtractUrlsFromMultipleLinkHeaders() {
        // Given
        msg.getResponseHeader()
                .addHeader(
                        HttpHeader.LINK,
                        "<https://www.example.info/wp-json/>; rel=\"https://api.w.org/\"");
        msg.getResponseHeader()
                .addHeader(
                        HttpHeader.LINK,
                        "<https://www.example.info/wp-json/wp/v2/pages/2>; rel=\"alternate\"; type=\"application/json\"");
        msg.getResponseHeader()
                .addHeader(HttpHeader.LINK, "<https://www.example.info/>; rel=shortlink");
        // The URL of the base message is http://example.com"
        msg.getResponseHeader().addHeader(HttpHeader.LINK, "</foo>; rel=rellink");
        // This next one should be ignored
        msg.getResponseHeader().addHeader("FLink", "<https://foo.bar>; rel=\"alt\"");
        // When
        boolean parsed = parser.parseResource(ctx);
        // Then
        assertThat(parsed, is(equalTo(false)));
        assertThat(
                listener.getUrlsFound(),
                containsInAnyOrder(
                        "https://www.example.info/wp-json/",
                        "https://www.example.info/wp-json/wp/v2/pages/2",
                        "https://www.example.info/",
                        "http://example.com/foo"));
    }

    @Test
    void shouldExtractUrlFromContentLocationHeader() {
        // Given
        String value = "http://example.com/contentlocation";
        msg.getResponseHeader().addHeader(HttpHeader.CONTENT_LOCATION, value);
        // When
        boolean parsed = parser.parseResource(ctx);
        // Then
        assertThat(parsed, is(equalTo(false)));
        assertThat(listener.getUrlsFound(), contains(value));
    }

    @Test
    void shouldExtractRelativeUrlFromContentLocationHeader() {
        // Given
        String url = "/rel/redirection";
        msg.getResponseHeader().addHeader(HttpHeader.CONTENT_LOCATION, url);
        // When
        boolean parsed = parser.parseResource(ctx);
        // Then
        assertThat(parsed, is(equalTo(false)));
        assertThat(listener.getUrlsFound(), contains("http://example.com" + url));
    }

    @Test
    void shouldExtractUrlsFromLinkHeader() {
        // Given
        String url1 = "http://example.com/link1";
        String url2 = "/link2";
        msg.getResponseHeader()
                .addHeader(
                        HttpHeader.LINK,
                        "<" + url1 + ">; param1=value1; param2=\"value2\";<" + url2 + ">");
        // When
        boolean parsed = parser.parseResource(ctx);
        // Then
        assertThat(parsed, is(equalTo(false)));
        assertThat(listener.getUrlsFound(), contains(url1, "http://example.com" + url2));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "<http://example.com",
                "http://example.com>",
                "more>bad<stuff",
                "https://www.example.com"
            })
    void shouldIgnoreInvalidLinkHeaders(String value) {
        // Given
        msg.getResponseHeader().addHeader(HttpHeader.LINK, value);
        // When
        boolean parsed = parser.parseResource(ctx);
        // Then
        assertThat(parsed, is(equalTo(false)));
        assertThat(listener.getUrlsFound(), is(empty()));
    }

    @Test
    void shouldExtractUrlFromRefreshHeader() {
        // Given
        String url = "http://example.com/refresh";
        msg.getResponseHeader().addHeader(HttpHeader.REFRESH, "999; url=" + url);
        // When
        boolean parsed = parser.parseResource(ctx);
        // Then
        assertThat(parsed, is(equalTo(false)));
        assertThat(listener.getUrlsFound(), contains(url));
    }

    @Test
    void shouldExtractRelativeUrlFromRefreshHeader() {
        // Given
        String url = "/rel/refresh";
        msg.getResponseHeader().addHeader(HttpHeader.REFRESH, "999; url=" + url);
        // When
        boolean parsed = parser.parseResource(ctx);
        // Then
        assertThat(parsed, is(equalTo(false)));
        assertThat(listener.getUrlsFound(), contains("http://example.com" + url));
    }
}
