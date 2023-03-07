/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.BDDMockito.given;

import java.nio.file.Files;
import java.nio.file.Path;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.Test;

/** Unit test for {@link DsStoreParser}. */
class DsStoreParserUnitTest extends SpiderParserTestUtils<DsStoreParser> {

    private static final Path BASE_DIR_TEST_FILES =
            getResourcePath(DsStoreParserUnitTest.class, "dsstore");
    private static final byte[] MAGIC_BYTES = {0, 0, 0, 1};

    @Override
    protected DsStoreParser createParser() {
        try {
            msg.setRequestHeader("GET / HTTP/1.1\r\nHost: example.com\r\n");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        given(spiderOptions.isParseDsStore()).willReturn(true);
        return new DsStoreParser();
    }

    @Test
    void shouldFailToEvaluateAnUndefinedContext() {
        // Given
        ParseContext ctx = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> parser.canParseResource(ctx, false));
    }

    @Test
    void shouldFailToEvaluateAnUndefinedPath() {
        // Given
        given(ctx.getPath()).willReturn(null);
        // When / Then
        assertThrows(NullPointerException.class, () -> parser.canParseResource(ctx, false));
    }

    @Test
    void shouldParseRelevantMessageEvenIfAlreadyParsed() {
        // Given
        boolean parsed = true;
        given(ctx.getPath()).willReturn("/.DS_Store");
        msg.setResponseBody(MAGIC_BYTES);
        // When
        boolean canParse = parser.canParseResource(ctx, parsed);
        // Then
        assertThat(canParse, is(equalTo(true)));
    }

    @Test
    void shouldNotParseMessageIfDoesNotContainMagicByes() {
        // Given
        boolean parsed = true;
        given(ctx.getPath()).willReturn("/.DS_Store");
        byte[] bytes = {0, 0, 0, 0};
        msg.setResponseBody(bytes);
        // When
        boolean canParse = parser.canParseResource(ctx, parsed);
        // Then
        assertThat(canParse, is(equalTo(false)));
    }

    @Test
    void shouldNotParseAnUndefinedContext() {
        // Given
        ParseContext ctx = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> parser.parseResource(ctx));
    }

    @Test
    void shouldNotParseMessageIfParseOfDsStoreIsDisabled() {
        // Given
        given(spiderOptions.isParseDsStore()).willReturn(false);
        // When
        boolean completelyParsed = parser.parseResource(ctx);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
    }

    @Test
    void shouldNotParseMessageWithoutMagicBytes() {
        // Given
        messageWithDsStore("200 Ok", "not.DS_Store");
        // When
        boolean completelyParsed = parser.parseResource(ctx);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
    }

    @Test
    void shouldNotParseDsStoreMessageIfClientError() throws URIException, NullPointerException {
        // Given
        msg.getRequestHeader().setURI(new URI("http://example.com/.DS_Store", true));
        msg.getResponseHeader().setStatusCode(404);
        // When
        boolean completelyParsed = parser.parseResource(ctx);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
    }

    @Test
    void shouldNotParseDsStoreMessageIfServerError() throws URIException, NullPointerException {
        // Given
        msg.getRequestHeader().setURI(new URI("http://example.com/.DS_Store", true));
        msg.getResponseHeader().setStatusCode(500);
        // When
        boolean completelyParsed = parser.parseResource(ctx);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
    }

    @Test
    void shouldNotParseEmptyResponse() throws URIException, NullPointerException {
        // Given
        msg.getRequestHeader().setURI(new URI("http://example.com/.DS_Store", true));
        msg.getResponseHeader().setStatusCode(200);
        msg.setResponseBody("");
        // When
        boolean completelyParsed = parser.parseResource(ctx);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
    }

    @Test
    void shouldNotParseMalformedDsStoreMessage() {
        // Given
        messageWith("not.DS_Store");
        // When
        boolean completelyParsed = parser.parseResource(ctx);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
    }

    @Test
    void shouldFindUrlsInValidDsStore() throws Exception {
        // Given
        messageWithDsStore("200 Ok", "1.DS_Store");
        // When
        boolean completelyParsed = parser.parseResource(ctx);
        // Then
        assertThat(completelyParsed, is(equalTo(true)));
        assertThat(listener.getNumberOfUrlsFound(), is(equalTo(1)));
        assertThat(listener.getUrlsFound(), contains("http://example.com/code"));
    }

    @Test
    void shouldFindMultipleUrlsInValidDsStore() throws Exception {
        // Given
        messageWithDsStore("200 Ok", "4.DS_Store");
        // When
        boolean completelyParsed = parser.parseResource(ctx);
        // Then
        assertThat(completelyParsed, is(equalTo(true)));
        assertThat(listener.getNumberOfUrlsFound(), is(equalTo(4)));
        assertThat(
                listener.getUrlsFound(),
                contains(
                        "http://example.com/.settings",
                        "http://example.com/libs",
                        "http://example.com/res",
                        "http://example.com/src"));
    }

    private void messageWith(String filename) {
        messageWith("200 OK", filename);
    }

    private void messageWith(String statusCodeMessage, String filename) {
        try {
            String fileContents = readFile(BASE_DIR_TEST_FILES.resolve(filename));
            msg.setResponseHeader(
                    "HTTP/1.1 "
                            + statusCodeMessage
                            + "\r\n"
                            + "Content-Length: "
                            + fileContents.length());
            msg.setResponseBody(fileContents);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void messageWithDsStore(String statusCodeMessage, String filename) {
        try {
            msg.setResponseHeader("HTTP/1.1 " + statusCodeMessage + "\r\n");
            msg.setResponseBody(Files.readAllBytes(BASE_DIR_TEST_FILES.resolve(filename)));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
