/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpStatusCode;

/** Unit test for {@link SpiderRedirectParser}. */
class SpiderRedirectParserUnitTest extends SpiderParserTestUtils<SpiderRedirectParser> {

    private static final List<Integer> NON_REDIRECTION_STATUS_CODES;
    private static final List<Integer> REDIRECTION_STATUS_CODES;

    static {
        NON_REDIRECTION_STATUS_CODES = new ArrayList<>();
        REDIRECTION_STATUS_CODES = new ArrayList<>();
        Arrays.stream(HttpStatusCode.CODES)
                .forEach(
                        code -> {
                            if (HttpStatusCode.isRedirection(code)) {
                                REDIRECTION_STATUS_CODES.add(code);
                            } else {
                                NON_REDIRECTION_STATUS_CODES.add(code);
                            }
                        });
    }

    @Override
    protected SpiderRedirectParser createParser() {
        return new SpiderRedirectParser();
    }

    @Test
    void shouldFailToEvaluateAnUndefineContext() {
        // Given
        ParseContext ctx = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> parser.canParseResource(ctx, false));
    }

    @Test
    void shouldNotParseNonRedirectionMessages() {
        // Given
        for (int statusCode : NON_REDIRECTION_STATUS_CODES) {
            messageWithStatusCode(statusCode);
            // When
            boolean canParse = parser.canParseResource(ctx, false);
            // Then
            assertThat(Integer.toString(statusCode), canParse, is(equalTo(false)));
        }
    }

    @Test
    void shouldParseRedirectionMessages() {
        // Given
        for (int statusCode : REDIRECTION_STATUS_CODES) {
            messageWithStatusCode(statusCode);
            // When
            boolean canParse = parser.canParseResource(ctx, false);
            // Then
            assertThat(Integer.toString(statusCode), canParse, is(equalTo(true)));
        }
    }

    @Test
    void shouldParseRedirectionMessageEvenIfAlreadyParsed() {
        // Given
        boolean alreadyParsed = true;
        messageWithStatusCode(HttpStatusCode.FOUND);
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
    void shouldExtractUrlFromLocationHeader() {
        // Given
        String location = "http://example.com/redirection";
        messageWithLocationAndStatusCode(location, HttpStatusCode.FOUND);
        // When
        boolean parsed = parser.parseResource(ctx);
        // Then
        assertThat(parsed, is(equalTo(true)));
        assertThat(listener.getUrlsFound(), contains(location));
    }

    @Test
    void shouldExtractRelativeUrlFromLocationHeader() {
        // Given
        String location = "/rel/redirection";
        messageWithLocationAndStatusCode(location, HttpStatusCode.FOUND);
        // When
        boolean parsed = parser.parseResource(ctx);
        // Then
        assertThat(parsed, is(equalTo(true)));
        assertThat(listener.getUrlsFound(), contains("http://example.com" + location));
    }

    @Test
    void shouldNotExtractUrlIfLocationHeaderIsEmpty() {
        // Given
        String location = "";
        messageWithLocationAndStatusCode(location, HttpStatusCode.FOUND);
        // When
        boolean parsed = parser.parseResource(ctx);
        // Then
        assertThat(parsed, is(equalTo(true)));
        assertThat(listener.getUrlsFound(), is(empty()));
    }

    @Test
    void shouldNotExtractUrlIfLocationHeaderIsNotPresent() {
        // Given
        messageWithStatusCode(HttpStatusCode.FOUND);
        // When
        boolean parsed = parser.parseResource(ctx);
        // Then
        assertThat(parsed, is(equalTo(true)));
        assertThat(listener.getUrlsFound(), is(empty()));
    }

    private void messageWithStatusCode(int statusCode) {
        try {
            msg.setRequestHeader("GET / HTTP/1.1\r\nHost: example.com\r\n");
            msg.setResponseHeader("HTTP/1.1 " + statusCode + " Reason\r\n");
        } catch (HttpMalformedHeaderException e) {
            throw new RuntimeException(e);
        }
    }

    private void messageWithLocationAndStatusCode(String location, int statusCode) {
        messageWithStatusCode(statusCode);
        msg.getResponseHeader().addHeader(HttpHeader.LOCATION, location);
    }
}
