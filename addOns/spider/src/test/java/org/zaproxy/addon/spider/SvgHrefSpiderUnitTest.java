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
package org.zaproxy.addon.spider;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import net.htmlparser.jericho.Source;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

class SvgHrefSpiderUnitTest {

    private static final String SVG_CONTENT_TYPE = "image/svg+xml";
    private static final String XML_CONTENT_TYPE = "text/xml";

    SvgHrefSpider shs;

    @BeforeEach
    void setup() {
        shs = new SvgHrefSpider();
    }

    @Test
    void shouldBeAbleToParseRelevantRequest() {
        // Given
        HttpMessage msg = createMessage("test.svg");
        // When
        boolean canParse = shs.canParseResource(msg, "", false);
        // Then
        assertTrue(canParse);
    }

    @Test
    void shouldNotBeAbleToParseIrrelevantRequest() {
        // Given
        HttpMessage msg = createMessage("test.test");
        // When
        boolean canParse = shs.canParseResource(msg, "", false);
        // Then
        assertFalse(canParse);
    }

    @Test
    void shouldBeAbleToParseRelevantResponse() {
        // Given
        HttpMessage msg = createMessage("svgimage");
        msg.getResponseHeader().addHeader(HttpHeader.CONTENT_TYPE, SVG_CONTENT_TYPE);
        // When
        boolean canParse = shs.canParseResource(msg, "", false);
        // Then
        assertTrue(canParse);
    }

    @Test
    void shouldNotBeAbleToParseIrrelevantResponse() {
        // Given
        HttpMessage msg = createMessage("test.xml");
        msg.getResponseHeader().addHeader(HttpHeader.CONTENT_TYPE, XML_CONTENT_TYPE);
        // When
        boolean canParse = shs.canParseResource(msg, "", false);
        // Then
        assertFalse(canParse);
    }

    @Test
    void shouldNotParseResourceWhenNotSvg() {
        // Given
        HttpMessage msg = createMessage("test");
        msg.setResponseBody("Foo Bar");
        // When
        boolean parse = shs.parseResource(msg, new Source(msg.getResponseBody().toString()), 0);
        // Then
        assertFalse(parse);
    }

    @Test
    void shouldNotParseResourceWhenNoHrefInSvg() {
        // Given
        HttpMessage msg = createMessage("test.svg");
        msg.setResponseBody(
                "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n"
                        + "<svg width=\"5cm\" height=\"3cm\" viewBox=\"0 0 5 3\" version=\"1.1\" xmlns=\"http://www.w3.org/2000/svg\">\n"
                        + "  <rect x=\".01\" y=\".01\" width=\"4.98\" height=\"2.98\" fill=\"none\" stroke=\"blue\" stroke-width=\".03\"/>\n"
                        + "</svg>");
        // When
        boolean parse = shs.parseResource(msg, new Source(msg.getResponseBody().toString()), 0);
        // Then
        assertFalse(parse);
    }

    @Test
    void shouldNotParseResourceWhenSaxParseExceptionEncountered() {
        // Given
        HttpMessage msg = createMessage("test.svg");
        msg.setResponseBody(
                "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n"
                        + "<svg width=\"5cm\" height=\"3cm\" viewBox=\"0 0 5 3\" version=\"1.1\" xmlns=\"http://www.w3.org/2000/svg\">\n"
                        + "  <rect x=\".01\" y=\".01\" width=\"4.98\" height=\"2.98\" fill=\"none\" stroke=\"blue\" stroke-width=\".03\"/>\n"
                        // The following line produces a SAXParseException other than the DOCTYPE
                        // issue tested elsewhere due to the ampersand outside of a CDATA block
                        + "<text x=\"20\" y=\"35\" class=\"small\">Test & Text</text>"
                        + "</svg>");
        // When
        boolean parse = shs.parseResource(msg, new Source(msg.getResponseBody().toString()), 0);
        // Then
        assertFalse(parse);
    }

    @Test
    void shouldNotParseResourceWithDoctypeDeclaration() {
        // Given
        HttpMessage msg = createMessage("test.svg");
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
        boolean parse = shs.parseResource(msg, new Source(msg.getResponseBody().toString()), 0);
        // Then
        assertFalse(parse);
    }

    @ParameterizedTest
    @ValueSource(strings = {"href", "HREF", "xlink:href", "XLINK:HREF"})
    void shouldParseValidResourceWithHref(String elementName) {
        // Given
        HttpMessage msg = createMessage("test.svg");
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
        boolean parse = shs.parseResource(msg, new Source(msg.getResponseBody().toString()), 0);
        // Then
        assertTrue(parse);
    }

    @ParameterizedTest
    @ValueSource(strings = {"http://www.w3.org/", "test.html", "test", "/test"})
    void shouldParseValidResourceWithVariousUrls(String url) {
        // Given
        HttpMessage msg = createMessage("test.svg");
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
        boolean parse = shs.parseResource(msg, new Source(msg.getResponseBody().toString()), 0);
        // Then
        assertTrue(parse);
    }

    private HttpMessage createMessage(String path) {
        HttpMessage msg = new HttpMessage();
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
        return msg;
    }
}
