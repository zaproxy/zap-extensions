/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.BDDMockito.given;

import org.junit.jupiter.api.Test;

/** Unit test for {@link SpiderRobotstxtParser}. */
class SpiderRobotstxtParserUnitTest extends SpiderParserTestUtils<SpiderRobotstxtParser> {

    private static final String ROBOTS_TXT_PATH = "/robots.txt";

    @Override
    protected SpiderRobotstxtParser createParser() {
        try {
            msg.setRequestHeader("GET / HTTP/1.1\r\nHost: example.com\r\n");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        given(spiderOptions.isParseRobotsTxt()).willReturn(true);
        return new SpiderRobotstxtParser();
    }

    @Test
    void shouldNotFailToEvaluateAnUndefinedPath() {
        // Given
        given(ctx.getPath()).willReturn(null);
        // When / Then
        assertDoesNotThrow(() -> parser.canParseResource(ctx, false));
    }

    @Test
    void shouldParseRobotsTxtPath() {
        // Given
        given(ctx.getPath()).willReturn(ROBOTS_TXT_PATH);
        // When
        boolean canParse = parser.canParseResource(ctx, false);
        // Then
        assertThat(canParse, is(equalTo(true)));
    }

    @Test
    void shouldParseRobotsTxtPathWithDifferentCase() {
        // Given
        given(ctx.getPath()).willReturn("/RoBoTs.TxT");
        // When
        boolean canParse = parser.canParseResource(ctx, false);
        // Then
        assertThat(canParse, is(equalTo(true)));
    }

    @Test
    void shouldParseRobotsTxtPathEvenIfAlreadyParsed() {
        // Given
        boolean parsed = true;
        given(ctx.getPath()).willReturn(ROBOTS_TXT_PATH);
        // When
        boolean canParse = parser.canParseResource(ctx, parsed);
        // Then
        assertThat(canParse, is(equalTo(true)));
    }

    @Test
    void shouldNotParseNonRobotsTxtPath() {
        // Given
        given(ctx.getPath()).willReturn("/");
        // When
        boolean canParse = parser.canParseResource(ctx, false);
        // Then
        assertThat(canParse, is(equalTo(false)));
    }

    @Test
    void shouldFailToParseAnUndefinedContext() {
        // Given
        ParseContext ctx = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> parser.parseResource(ctx));
    }

    @Test
    void shouldNotBeCompletelyParsedIfParseDisabled() {
        // Given
        messageWith("");
        given(spiderOptions.isParseRobotsTxt()).willReturn(false);
        // When
        boolean completelyParsed = parser.parseResource(ctx);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
    }

    @Test
    void shouldBeAlwaysCompletelyParsedIfParseEnabled() {
        // Given
        messageWith("");
        // When
        boolean completelyParsed = parser.parseResource(ctx);
        // Then
        assertThat(completelyParsed, is(equalTo(true)));
    }

    @Test
    void shouldNotFindUrlsIfThereIsNone() {
        // Given
        messageWith(
                body(
                        "# Just Comments & User-Agents...",
                        "User-Agent: *",
                        "# Disallow: /x/y/z",
                        "User-Agent: bot",
                        "<pre>",
                        "# Allow: /a/b/c",
                        "",
                        "# ...",
                        "Allow:   # no path"));
        // When
        parser.parseResource(ctx);
        // Then
        assertThat(listener.getUrlsFound(), is(empty()));
    }

    @Test
    void shouldFindUrls() {
        // Given
        messageWith(
                body(
                        "User-Agent: *",
                        "Disallow: /x/y/z    # Comment",
                        " User-Agent: bot     # Comment",
                        "Allow: /a/b/c.html",
                        "<pre> Allow: /nohtmltags/",
                        "  Allow:    /%  ",
                        "Allow: /%20file.txt",
                        "Allow: /abc/*"));
        // When
        parser.parseResource(ctx);
        // Then
        assertThat(
                listener.getUrlsFound(),
                contains(
                        "http://example.com/x/y/z",
                        "http://example.com/a/b/c.html",
                        "http://example.com/nohtmltags/",
                        "http://example.com/%25",
                        "http://example.com/%20file.txt",
                        "http://example.com/abc/"));
    }

    private void messageWith(String body) {
        try {
            msg.setResponseHeader("HTTP/1.1 200 OK\r\nContent-Length: " + body.length());
            msg.setResponseBody(body);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static String body(String... strings) {
        if (strings == null || strings.length == 0) {
            return "";
        }
        StringBuilder strBuilder = new StringBuilder(strings.length * 25);
        for (String string : strings) {
            if (strBuilder.length() > 0) {
                strBuilder.append("\n");
            }
            strBuilder.append(string);
        }
        return strBuilder.toString();
    }
}
