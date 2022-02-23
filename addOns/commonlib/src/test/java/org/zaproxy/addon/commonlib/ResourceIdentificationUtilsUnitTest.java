/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.commonlib;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import java.io.IOException;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit tests for {@link ResourceIdentificationUtils}. */
class ResourceIdentificationUtilsUnitTest extends TestUtils {

    private static final String URI = "https://www.example.com";
    private HttpMessage msg;

    @BeforeEach
    void createHttpMessage() throws IOException {
        msg = new HttpMessage();
        msg.setRequestHeader("GET " + URI + " HTTP/1.1");
    }

    @ParameterizedTest
    @ValueSource(strings = {"font.woff", "font.woff2", "font.ttf", "font.otf"})
    void shouldReturnTrueWhenRequestUrlSeemsToBeAFontFile(String fileName)
            throws HttpMalformedHeaderException, URIException, NullPointerException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.getRequestHeader().setURI(new URI("http://example.com/" + fileName, false));
        // When
        boolean result = ResourceIdentificationUtils.isFont(msg);
        // Then
        assertThat(result, is(equalTo(true)));
    }

    @Test
    void shouldReturnFalseWhenRequestUrlDoesNotSeemToBeAFontFile()
            throws HttpMalformedHeaderException, URIException, NullPointerException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.getRequestHeader().setURI(new URI("http://example.com/any.xml", false));
        // When
        boolean result = ResourceIdentificationUtils.isFont(msg);
        // Then
        assertThat(result, is(equalTo(false)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"something.js", "something.jsx"})
    void shouldReturnTrueWhenRequestUrlSeemsToBeAJavaScriptFile(String fileName)
            throws HttpMalformedHeaderException, URIException, NullPointerException {
        // Given
        msg.getRequestHeader().setURI(new URI("http://example.com/" + fileName, false));
        // When
        boolean result = ResourceIdentificationUtils.isJavaScript(msg);
        // Then
        assertThat(result, is(equalTo(true)));
    }

    @Test
    void shouldReturnTrueWhenResponseSeemsToBeAJavaScriptFile()
            throws HttpMalformedHeaderException, URIException, NullPointerException {
        // Given
        msg.getRequestHeader().setURI(new URI("http://example.com/any.js", true));
        msg.getResponseHeader().setHeader(HttpResponseHeader.CONTENT_TYPE, "text/javascript");
        // When
        boolean result = ResourceIdentificationUtils.isJavaScript(msg);
        // Then
        assertThat(result, is(equalTo(true)));
    }

    @Test
    void shouldReturnTrueWhenRequestUrlSeemsToBeAnImageFile()
            throws HttpMalformedHeaderException, URIException, NullPointerException {
        // Given
        msg.getRequestHeader().setURI(new URI("http://example.com/something.jpg", false));
        // When
        boolean result = ResourceIdentificationUtils.isImage(msg);
        // Then
        assertThat(result, is(equalTo(true)));
    }

    @Test
    void shouldReturnFalseWhenRequestUrlDoesNotSeemToBeAnImageFile()
            throws HttpMalformedHeaderException, URIException, NullPointerException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.getRequestHeader().setURI(new URI("http://example.com/any.xml", false));
        // When
        boolean result = ResourceIdentificationUtils.isImage(msg);
        // Then
        assertThat(result, is(equalTo(false)));
    }

    @Test
    void shouldReturnTrueWhenResponseSeemsToBeAnImageFile()
            throws HttpMalformedHeaderException, URIException, NullPointerException {
        // Given
        msg.getRequestHeader().setURI(new URI("http://example.com/logo", true));
        msg.getResponseHeader().setHeader(HttpResponseHeader.CONTENT_TYPE, "image/jpg");
        // When
        boolean result = ResourceIdentificationUtils.isImage(msg);
        // Then
        assertThat(result, is(equalTo(true)));
    }

    @Test
    void shouldReturnFalseWhenResponseDoesNotSeemsToBeAnImageFile()
            throws HttpMalformedHeaderException, URIException, NullPointerException {
        // Given
        msg.getRequestHeader().setURI(new URI("http://example.com/logo", true));
        msg.getResponseHeader().setHeader(HttpResponseHeader.CONTENT_TYPE, "text/html");
        // When
        boolean result = ResourceIdentificationUtils.isImage(msg);
        // Then
        assertThat(result, is(equalTo(false)));
    }

    @Test
    void shouldReturnTrueWhenRequestUrlSeemsToBeACssFile()
            throws HttpMalformedHeaderException, URIException, NullPointerException {
        // Given
        msg.getRequestHeader().setURI(new URI("http://example.com/something.css", false));
        // When
        boolean result = ResourceIdentificationUtils.isCss(msg);
        // Then
        assertThat(result, is(equalTo(true)));
    }

    @Test
    void shouldReturnTrueWhenResponseSeemsToBeACssFile()
            throws HttpMalformedHeaderException, URIException, NullPointerException {
        // Given
        msg.getRequestHeader().setURI(new URI("http://example.com/styles", true));
        msg.getResponseHeader().setHeader(HttpResponseHeader.CONTENT_TYPE, "text/css");
        // When
        boolean result = ResourceIdentificationUtils.isCss(msg);
        // Then
        assertThat(result, is(equalTo(true)));
    }

    @Test
    void shouldReportControlCharactersInBinaryResponse()
            throws HttpMalformedHeaderException, IOException {
        // Given
        msg.setResponseBody("�PNG\n\n");
        // When
        boolean result = ResourceIdentificationUtils.responseContainsControlChars(msg);
        // Then
        assertThat(result, is(equalTo(true)));
    }

    @ParameterizedTest
    @EmptySource
    @ValueSource(strings = {"foobar", "\tfoobar\r\n"})
    void shouldNotReportControlCharactersInNonBinaryResponse(String content)
            throws HttpMalformedHeaderException, IOException {
        // Given
        msg.setResponseBody(content);
        // When
        boolean result = ResourceIdentificationUtils.responseContainsControlChars(msg);
        // Then
        assertThat(result, is(equalTo(false)));
    }
}
