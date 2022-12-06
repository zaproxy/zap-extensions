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
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;

/** Unit test for {@link SvgHrefParser}. */
class SvgHrefParserUnitTest extends SpiderParserTestUtils<SvgHrefParser> {

    private static final String SVG_CONTENT_TYPE = "image/svg+xml";
    private static final String XML_CONTENT_TYPE = "text/xml";

    @Override
    protected SvgHrefParser createParser() {
        return new SvgHrefParser();
    }

    @Test
    void shouldBeAbleToParseRelevantRequest() {
        // Given
        messageWith("test.svg");
        // When
        boolean canParse = parser.canParseResource(ctx, false);
        // Then
        assertTrue(canParse);
    }

    @Test
    void shouldNotBeAbleToParseIrrelevantRequest() {
        // Given
        messageWith("test.test");
        // When
        boolean canParse = parser.canParseResource(ctx, false);
        // Then
        assertFalse(canParse);
    }

    @Test
    void shouldBeAbleToParseRelevantResponse() {
        // Given
        messageWith("svgimage");
        msg.getResponseHeader().addHeader(HttpHeader.CONTENT_TYPE, SVG_CONTENT_TYPE);
        // When
        boolean canParse = parser.canParseResource(ctx, false);
        // Then
        assertTrue(canParse);
    }

    @Test
    void shouldNotBeAbleToParseIrrelevantResponse() {
        // Given
        messageWith("test.xml");
        msg.getResponseHeader().addHeader(HttpHeader.CONTENT_TYPE, XML_CONTENT_TYPE);
        // When
        boolean canParse = parser.canParseResource(ctx, false);
        // Then
        assertFalse(canParse);
    }

    @Test
    void shouldNotParseResourceWhenNotSvg() {
        // Given
        messageWith("test");
        msg.setResponseBody("Foo Bar");
        // When
        boolean parse = parser.parseResource(ctx);
        // Then
        assertFalse(parse);
    }

    @Test
    void shouldNotParseResourceWhenNoHrefInSvg() {
        // Given
        messageWith("test.svg");
        msg.setResponseBody(
                "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n"
                        + "<svg width=\"5cm\" height=\"3cm\" viewBox=\"0 0 5 3\" version=\"1.1\" xmlns=\"http://www.w3.org/2000/svg\">\n"
                        + "  <rect x=\".01\" y=\".01\" width=\"4.98\" height=\"2.98\" fill=\"none\" stroke=\"blue\" stroke-width=\".03\"/>\n"
                        + "</svg>");
        // When
        boolean parse = parser.parseResource(ctx);
        // Then
        assertFalse(parse);
    }

    @Test
    void shouldNotParseResourceWhenSaxParseExceptionEncountered() {
        // Given
        messageWith("test.svg");
        msg.setResponseBody(
                "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n"
                        + "<svg width=\"5cm\" height=\"3cm\" viewBox=\"0 0 5 3\" version=\"1.1\" xmlns=\"http://www.w3.org/2000/svg\">\n"
                        + "  <rect x=\".01\" y=\".01\" width=\"4.98\" height=\"2.98\" fill=\"none\" stroke=\"blue\" stroke-width=\".03\"/>\n"
                        // The following line produces a SAXParseException other than the DOCTYPE
                        // issue tested elsewhere due to the ampersand outside of a CDATA block
                        + "<text x=\"20\" y=\"35\" class=\"small\">Test & Text</text>"
                        + "</svg>");
        // When
        boolean parse = parser.parseResource(ctx);
        // Then
        assertFalse(parse);
    }

    @Test
    void shouldNotParseResourceWithDoctypeDeclaration() {
        // Given
        messageWith("test.svg");
        msg.setResponseBody(
                "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n"
                        + "<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd\">\n"
                        + "<svg width=\"5cm\" height=\"3cm\" viewBox=\"0 0 5 3\" version=\"1.1\" xmlns=\"http://www.w3.org/2000/svg\">\n"
                        + "  <rect x=\".01\" y=\".01\" width=\"4.98\" height=\"2.98\" fill=\"none\" stroke=\"blue\" stroke-width=\".03\"/>\n"
                        + "  <a HREF=\"http://www.w3.org\">\n"
                        + "    <ellipse cx=\"2.5\" cy=\"1.5\" rx=\"2\" ry=\"1\" fill=\"red\"/>\n"
                        + "  </a>"
                        + "</svg>");
        // When
        boolean parse = parser.parseResource(ctx);
        // Then
        assertFalse(parse);
    }

    @ParameterizedTest
    @ValueSource(strings = {"href", "HREF", "xlink:href", "XLINK:HREF"})
    void shouldParseValidResourceWithHref(String elementName) {
        // Given
        messageWith("test.svg");
        msg.setResponseBody(
                "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n"
                        + "<svg width=\"5cm\" height=\"3cm\" viewBox=\"0 0 5 3\" version=\"1.1\" xmlns=\"http://www.w3.org/2000/svg\">\n"
                        + "  <rect x=\".01\" y=\".01\" width=\"4.98\" height=\"2.98\" fill=\"none\" stroke=\"blue\" stroke-width=\".03\"/>\n"
                        + "  <a "
                        + elementName
                        + "=\"http://www.w3.org\">\n"
                        + "    <ellipse cx=\"2.5\" cy=\"1.5\" rx=\"2\" ry=\"1\" fill=\"red\"/>\n"
                        + "  </a>"
                        + "</svg>");
        // When
        boolean parse = parser.parseResource(ctx);
        // Then
        assertTrue(parse);
    }

    private static Stream<Arguments> createInputAndExpectedPairs() {
        return Stream.of(
                Arguments.of("http://www.example.org/", "http://www.example.org/"),
                Arguments.of("test.html", "http://www.example.com/test.html"),
                Arguments.of("test", "http://www.example.com/test"),
                Arguments.of("/test", "http://www.example.com/test"),
                Arguments.of("//www.example.com/foo", "http://www.example.com/foo"));
    }

    @ParameterizedTest
    @MethodSource("createInputAndExpectedPairs")
    void shouldParseValidResourceWithVariousUrls(String url, String expectedUrl) {
        // Given
        messageWith("test.svg");
        msg.setResponseBody(
                "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n"
                        + "<svg width=\"5cm\" height=\"3cm\" viewBox=\"0 0 5 3\" version=\"1.1\" xmlns=\"http://www.w3.org/2000/svg\">\n"
                        + "  <rect x=\".01\" y=\".01\" width=\"4.98\" height=\"2.98\" fill=\"none\" stroke=\"blue\" stroke-width=\".03\"/>\n"
                        + "  <a href=\""
                        + url
                        + "\">\n"
                        + "    <ellipse cx=\"2.5\" cy=\"1.5\" rx=\"2\" ry=\"1\" fill=\"red\"/>\n"
                        + "  </a>"
                        + "</svg>");
        // When
        boolean parse = parser.parseResource(ctx);
        // Then
        assertTrue(parse);
        assertThat(listener.getNumberOfUrlsFound(), is(equalTo(1)));
        assertThat(listener.getUrlsFound().get(0), is(equalTo(expectedUrl)));
    }

    @Test
    void shouldParseUrlFromUseTag() {
        // Given
        messageWith("test.svg");
        msg.setResponseBody("<svg><use href=\"//example.org/use_element/upload.php#x\"/></svg>");
        // When
        boolean parse = parser.parseResource(ctx);
        // Then
        assertTrue(parse);
        assertThat(listener.getNumberOfUrlsFound(), is(equalTo(1)));
        assertThat(
                listener.getUrlsFound().get(0),
                is(equalTo("http://example.org/use_element/upload.php")));
    }

    @ParameterizedTest
    @ValueSource(strings = {"href", "HREF", "xlink:href", "XLINK:HREF"})
    void shouldParseValidResourceWithSvgTagWithImageTag(String attributeName) {
        // Given
        messageWith("test.html");
        msg.setResponseBody(
                "<!DOCTYPE html>\n"
                        + "<h1>SVG Tag Test</h1>\n"
                        + "<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\">\n"
                        + "  <image "
                        + attributeName
                        + "=\"/test/html/file.svg\"/>\n"
                        + "</svg>\n"
                        + "<p>\n"
                        + "  The attribute points at a URL for the image file.\n"
                        + "</p>");
        msg.getResponseHeader().addHeader(HttpHeader.CONTENT_TYPE, "text/html");
        // When
        boolean parse = parser.parseResource(ctx);
        // Then
        assertTrue(parse);
    }

    @ParameterizedTest
    @ValueSource(strings = {"href", "HREF", "xlink:href", "XLINK:HREF"})
    void shouldParseValidResourceWithSvgTagWithScriptTag(String attributeName) {
        // Given
        messageWith("test.html");
        msg.setResponseBody(
                "<!DOCTYPE html>\n"
                        + "<h1>SVG Tag Test</h1>\n"
                        + "<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\">\n"
                        + "  <script "
                        + attributeName
                        + "=\"/test/html/getImage\"/>\n"
                        + "</svg>\n"
                        + "<p>\n"
                        + "  The attribute points at a URL for the script file.\n"
                        + "</p>");
        msg.getResponseHeader().addHeader(HttpHeader.CONTENT_TYPE, "text/html");
        // When
        boolean parse = parser.parseResource(ctx);
        // Then
        assertTrue(parse);
    }

    @ParameterizedTest
    @ValueSource(strings = {"href", "HREF", "xlink:href", "XLINK:HREF"})
    void shouldNotParseResourceWithSvgTagWithOtherTag(String attributeName) {
        // Given
        messageWith("test.html");
        msg.setResponseBody(
                "<!DOCTYPE html>\n"
                        + "<h1>SVG Tag Test</h1>\n"
                        + "<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\">\n"
                        + "  <other "
                        + attributeName
                        + "=\"/test/html/getImage\"/>\n"
                        + "</svg>\n"
                        + "<p>\n"
                        + "  The attribute in \"other\" tag.\n"
                        + "</p>");
        msg.getResponseHeader().addHeader(HttpHeader.CONTENT_TYPE, "text/html");
        // When
        boolean parse = parser.parseResource(ctx);
        // Then
        assertFalse(parse);
    }

    private void messageWith(String path) {
        try {
            msg.setRequestHeader("GET http://www.example.com/" + path + " HTTP/1.1");
        } catch (HttpMalformedHeaderException e) {
            // ignore
        }

        try {
            msg.setResponseHeader(
                    "HTTP/1.1 200 OK\r\n"
                            + "Content-Length: "
                            + msg.getResponseBody().length()
                            + "\r\n");
        } catch (HttpMalformedHeaderException e) {
            // ignore
        }
    }
}
