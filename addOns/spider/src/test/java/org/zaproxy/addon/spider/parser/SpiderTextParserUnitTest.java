/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
import static org.mockito.BDDMockito.given;

import org.junit.jupiter.api.Test;

/** Unit test for {@link SpiderTextParser}. */
class SpiderTextParserUnitTest extends SpiderParserTestUtils<SpiderTextParser> {

    private static final String EMPTY_BODY = "";

    @Override
    protected SpiderTextParser createParser() {
        return new SpiderTextParser();
    }

    @Test
    void shouldFailToEvaluateAnUndefinedContext() {
        // Given
        ParseContext ctx = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> parser.canParseResource(ctx, false));
    }

    @Test
    void shouldNotParseMessageIfAlreadyParsed() {
        // Given
        boolean parsed = true;
        // When
        boolean canParse = parser.canParseResource(ctx, parsed);
        // Then
        assertThat(canParse, is(equalTo(false)));
    }

    @Test
    void shouldNotParseNonTextResponse() {
        // Given
        messageWith("application/xyz", EMPTY_BODY);
        boolean parsed = false;
        // When
        boolean canParse = parser.canParseResource(ctx, parsed);
        // Then
        assertThat(canParse, is(equalTo(false)));
    }

    @Test
    void shouldNotParseTextHtmlResponse() {
        // Given
        messageWith("text/html", EMPTY_BODY);
        boolean parsed = false;
        // When
        boolean canParse = parser.canParseResource(ctx, parsed);
        // Then
        assertThat(canParse, is(equalTo(false)));
    }

    @Test
    void shouldParseTextResponse() {
        // Given
        messageWith(EMPTY_BODY);
        boolean parsed = false;
        // When
        boolean canParse = parser.canParseResource(ctx, parsed);
        // Then
        assertThat(canParse, is(equalTo(true)));
    }

    @Test
    void shouldParseTextResponseEvenIfProvidedPathIsNull() {
        // Given
        messageWith(EMPTY_BODY);
        given(ctx.getPath()).willReturn(null);
        boolean parsed = false;
        // When
        boolean canParse = parser.canParseResource(ctx, parsed);
        // Then
        assertThat(canParse, is(equalTo(true)));
    }

    @Test
    void shouldNotParseTextResponseIfAlreadyParsed() {
        // Given
        messageWith(EMPTY_BODY);
        boolean parsed = true;
        // When
        boolean canParse = parser.canParseResource(ctx, parsed);
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
    void shouldNeverConsiderCompletelyParsed() {
        // Given
        messageWith("Non Empty Body...");
        // When
        boolean completelyParsed = parser.parseResource(ctx);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
    }

    @Test
    void shouldNotFindUrlsIfThereIsNone() {
        // Given
        messageWith(
                body(
                        "Body with no HTTP/S URLs",
                        " ://example.com/ ",
                        "More text...  ftp://ftp.example.com/ ",
                        "Even more text... //noscheme.example.com "));
        // When
        boolean completelyParsed = parser.parseResource(ctx);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
        assertThat(listener.getNumberOfUrlsFound(), is(equalTo(0)));
        assertThat(listener.getUrlsFound(), is(empty()));
    }

    @Test
    void shouldFindUrlsInCommentsWithoutElements() {
        // Given
        messageWith(
                body(
                        "Body with HTTP/S URLs",
                        " - http://plaincomment.example.com some text not part of URL",
                        "- \"https://plaincomment.example.com/z.php?x=y\" more text not part of URL",
                        "- 'http://plaincomment.example.com/c.pl?x=y' even more text not part of URL",
                        "- <https://plaincomment.example.com/d.asp?x=y> ...",
                        "- http://plaincomment.example.com/e/e1/e2.html?x=y#stop fragment should be ignored",
                        "- (https://plaincomment.example.com/surrounded/with/parenthesis) parenthesis should not be included",
                        "- [https://plaincomment.example.com/surrounded/with/brackets] brackets should not be included",
                        "- {https://plaincomment.example.com/surrounded/with/curly/brackets} curly brackets should not be included",
                        "- mixed case URLs HtTpS://ExAmPlE.CoM/path/ should also be found"));
        // When
        boolean completelyParsed = parser.parseResource(ctx);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
        assertThat(listener.getNumberOfUrlsFound(), is(equalTo(9)));
        assertThat(
                listener.getUrlsFound(),
                contains(
                        "http://plaincomment.example.com/",
                        "https://plaincomment.example.com/z.php?x=y",
                        "http://plaincomment.example.com/c.pl?x=y",
                        "https://plaincomment.example.com/d.asp?x=y",
                        "http://plaincomment.example.com/e/e1/e2.html?x=y",
                        "https://plaincomment.example.com/surrounded/with/parenthesis",
                        "https://plaincomment.example.com/surrounded/with/brackets",
                        "https://plaincomment.example.com/surrounded/with/curly/brackets",
                        "https://example.com/path/"));
    }

    private void messageWith(String body) {
        messageWith("text/xyz", body);
    }

    private void messageWith(String contentType, String body) {
        messageWith("200 OK", contentType, body);
    }

    private void messageWith(String statusCodeMessage, String contentType, String body) {
        try {
            msg.setRequestHeader("GET / HTTP/1.1\r\nHost: example.com\r\n");
            msg.setResponseHeader(
                    "HTTP/1.1 "
                            + statusCodeMessage
                            + "\r\n"
                            + "Content-Type: "
                            + contentType
                            + "; charset=UTF-8\r\n"
                            + "Content-Length: "
                            + body.length());
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
