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
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.BDDMockito.given;

import java.nio.file.Path;
import net.htmlparser.jericho.Source;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.spider.SpiderParam;

/** Unit test for {@link SpiderSitemapXmlParser}. */
class SpiderSitemapXmlParserUnitTest extends SpiderParserTestUtils<SpiderSitemapXmlParser> {

    private static final String ROOT_PATH = "/";
    private static final int BASE_DEPTH = 0;

    private static final Path BASE_DIR_TEST_FILES =
            getResourcePath(SpiderSitemapXmlParserUnitTest.class, "sitemapxml");

    @Override
    protected SpiderSitemapXmlParser createParser() {
        given(spiderOptions.isParseSitemapXml()).willReturn(true);
        return new SpiderSitemapXmlParser(spiderOptions);
    }

    @Test
    void shouldFailToCreateParserWithUndefinedSpiderOptions() {
        // Given
        SpiderParam undefinedSpiderOptions = null;
        // When / Then
        assertThrows(
                IllegalArgumentException.class,
                () -> new SpiderSitemapXmlParser(undefinedSpiderOptions));
    }

    @Test
    void shouldNotFailToEvaluateAnUndefinedMessage() {
        // Given
        HttpMessage undefinedMessage = null;
        // When
        boolean canParse = parser.canParseResource(undefinedMessage, ROOT_PATH, false);
        // Then
        assertThat(canParse, is(equalTo(false)));
    }

    @Test
    void shouldFailToEvaluateAnUndefinedPath() {
        // Given
        String undefinedPath = null;
        // When / Then
        assertThrows(
                NullPointerException.class,
                () -> parser.canParseResource(new HttpMessage(), undefinedPath, false));
    }

    @Test
    void shouldParsePathThatEndsWithSitemapXml() {
        // Given
        boolean parsed = false;
        // When
        boolean canParse = parser.canParseResource(new HttpMessage(), "/sitemap.xml", parsed);
        // Then
        assertThat(canParse, is(equalTo(true)));
    }

    @Test
    void shouldParseMessageEvenIfAlreadyParsed() {
        // Given
        boolean parsed = true;
        // When
        boolean canParse = parser.canParseResource(new HttpMessage(), "/sitemap.xml", parsed);
        // Then
        assertThat(canParse, is(equalTo(true)));
    }

    @Test
    void shouldNotParseAnUndefinedMessage() {
        // Given
        HttpMessage undefinedMessage = null;
        // When
        boolean completelyParsed =
                parser.parseResource(undefinedMessage, new Source(""), BASE_DEPTH);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
    }

    @Test
    void shouldNotRequireSourceToParseMessage() {
        // Given
        Source undefinedSource = null;
        messageWith("NoUrlsSitemap.xml");
        // When
        boolean completelyParsed = parser.parseResource(msg, undefinedSource, BASE_DEPTH);
        // Then
        assertThat(completelyParsed, is(equalTo(true)));
    }

    @Test
    void shouldNotParseMessageIfParseOfSitemapXmlIsDisabled() {
        // Given
        messageWith("NoUrlsSitemap.xml");
        given(spiderOptions.isParseSitemapXml()).willReturn(false);
        // When
        boolean completelyParsed = parser.parseResource(msg, null, BASE_DEPTH);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
    }

    @Test
    void shouldNotParseNonXmlMessage() {
        // Given
        messageWith("text/html", "NoUrlsSitemap.xml");
        // When
        boolean completelyParsed = parser.parseResource(msg, null, BASE_DEPTH);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
    }

    @Test
    void shouldNotParseXmlMessageIfClientError() {
        // Given
        messageWith("404 Not Found", "text/xml", "NoUrlsSitemap.xml");
        // When
        boolean completelyParsed = parser.parseResource(msg, null, BASE_DEPTH);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
    }

    @Test
    void shouldNotParseXmlMessageIfServerError() {
        // Given
        messageWith("500 Internal Server Error", "text/xml", "NoUrlsSitemap.xml");
        // When
        boolean completelyParsed = parser.parseResource(msg, null, BASE_DEPTH);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
    }

    @Test
    void shouldNotParseEmptyXmlMessage() {
        // Given
        messageWith("EmptyFile.xml");
        // When
        boolean completelyParsed = parser.parseResource(msg, null, BASE_DEPTH);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
    }

    @Test
    void shouldNotParseMalformedXmlMessage() {
        // Given
        messageWith("MalformedSitemap.xml");
        // When
        boolean completelyParsed = parser.parseResource(msg, null, BASE_DEPTH);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
    }

    @Test
    void shouldNotParseXmlMessageWithDoctype() {
        // Given
        messageWith("DoctypeSitemap.xml");
        // When
        boolean completelyParsed = parser.parseResource(msg, null, BASE_DEPTH);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
    }

    @Test
    void shouldNotFindUrlsIfNoneDefinedInSitemap() {
        // Given
        messageWith("NoUrlsSitemap.xml");
        // When
        boolean completelyParsed = parser.parseResource(msg, null, BASE_DEPTH);
        // Then
        assertThat(completelyParsed, is(equalTo(true)));
        assertThat(listener.getNumberOfUrlsFound(), is(equalTo(0)));
    }

    @Test
    void shouldNotFindUrlsIfUrlHasNoLocationIsEmptyInSitemap() {
        // Given
        messageWith("UrlNoLocationSitemap.xml");
        // When
        boolean completelyParsed = parser.parseResource(msg, null, BASE_DEPTH);
        // Then
        assertThat(completelyParsed, is(equalTo(true)));
        assertThat(listener.getNumberOfUrlsFound(), is(equalTo(0)));
    }

    @Test
    void shouldNotFindUrlsIfUrlLocationIsEmptyInSitemap() {
        // Given
        messageWith("UrlEmptyLocationSitemap.xml");
        // When
        boolean completelyParsed = parser.parseResource(msg, null, BASE_DEPTH);
        // Then
        assertThat(completelyParsed, is(equalTo(true)));
        assertThat(listener.getNumberOfUrlsFound(), is(equalTo(0)));
    }

    @Test
    void shouldFindUrlsInValidSitemapXml() throws Exception {
        // Given
        messageWith("MultipleUrlsSitemap.xml");
        // When
        boolean completelyParsed = parser.parseResource(msg, null, BASE_DEPTH);
        // Then
        assertThat(completelyParsed, is(equalTo(true)));
        assertThat(listener.getNumberOfUrlsFound(), is(equalTo(5)));
        assertThat(
                listener.getUrlsFound(),
                contains(
                        "https://example.org/",
                        "http://subdomain.example.com/",
                        "http://example.com/relative",
                        "ftp://example.com/",
                        "http://www.example.com/%C7"));
    }

    private void messageWith(String filename) {
        messageWith("text/xml", filename);
    }

    private void messageWith(String contentType, String filename) {
        messageWith("200 OK", contentType, filename);
    }

    private void messageWith(String statusCodeMessage, String contentType, String filename) {
        try {
            String fileContents = readFile(BASE_DIR_TEST_FILES.resolve(filename));
            msg.setRequestHeader("GET / HTTP/1.1\r\nHost: example.com\r\n");
            msg.setResponseHeader(
                    "HTTP/1.1 "
                            + statusCodeMessage
                            + "\r\n"
                            + "Content-Type: "
                            + contentType
                            + "; charset=UTF-8\r\n"
                            + "Content-Length: "
                            + fileContents.length());
            msg.setResponseBody(fileContents);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
