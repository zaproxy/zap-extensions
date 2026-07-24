/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.client.spider;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;

import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;

/** Unit test for {@link StaticResourceCache}. */
class StaticResourceCacheUnitTest {

    private static final String URL = "http://example.com/assets/style.css";
    private static final String BODY = "body { margin: 0; }";
    private static final String ETAG = "\"abc123\"";
    private static final String LAST_MODIFIED = "Wed, 01 Jul 2026 10:00:00 GMT";

    private StaticResourceCache cache;

    @BeforeEach
    void setUp() {
        cache = new StaticResourceCache();
    }

    @Test
    void shouldNotServeResponseWhenCacheEmpty() throws Exception {
        // Given
        HttpMessage msg = createRequest(URL);
        // When
        boolean served = cache.handleRequest(msg);
        // Then
        assertThat(served, is(equalTo(false)));
        assertThat(msg.getResponseHeader().isEmpty(), is(equalTo(true)));
    }

    @Test
    void shouldServeCachedResponseForRepeatedGet() throws Exception {
        // Given
        cache.handleResponse(createMessage(URL, "text/css", BODY));
        HttpMessage msg = createRequest(URL);
        // When
        boolean served = cache.handleRequest(msg);
        // Then
        assertThat(served, is(equalTo(true)));
        assertThat(msg.getResponseHeader().getStatusCode(), is(equalTo(200)));
        assertThat(msg.getResponseBody().toString(), is(equalTo(BODY)));
        assertThat(msg.getResponseHeader().getContentLength(), is(equalTo(BODY.length())));
    }

    @Test
    void shouldNotServeCachedResponseForDifferentUrl() throws Exception {
        // Given
        cache.handleResponse(createMessage(URL, "text/css", BODY));
        HttpMessage msg = createRequest(URL + "?v=2");
        // When
        boolean served = cache.handleRequest(msg);
        // Then
        assertThat(served, is(equalTo(false)));
    }

    @Test
    void shouldServe304WhenIfNoneMatchMatches() throws Exception {
        // Given
        cache.handleResponse(createMessageWithValidators());
        HttpMessage msg = createRequest(URL);
        msg.getRequestHeader().setHeader(HttpHeader.IF_NONE_MATCH, ETAG);
        // When
        boolean served = cache.handleRequest(msg);
        // Then
        assertThat(served, is(equalTo(true)));
        assertThat(msg.getResponseHeader().getStatusCode(), is(equalTo(304)));
        assertThat(msg.getResponseBody().length(), is(equalTo(0)));
        assertThat(msg.getResponseHeader().getHeader("ETag"), is(equalTo(ETAG)));
        assertThat(msg.getResponseHeader().getHeader("Date"), is(notNullValue()));
    }

    @Test
    void shouldIncludeCacheHeadersFromStoredResponseIn304() throws Exception {
        // Given
        HttpMessage stored = createMessageWithValidators();
        stored.getResponseHeader().setHeader(HttpHeader.CACHE_CONTROL, "public, max-age=3600");
        stored.getResponseHeader().setHeader("Expires", "Thu, 02 Jul 2026 10:00:00 GMT");
        stored.getResponseHeader().setHeader("Vary", "Accept-Encoding");
        cache.handleResponse(stored);
        HttpMessage msg = createRequest(URL);
        msg.getRequestHeader().setHeader(HttpHeader.IF_NONE_MATCH, ETAG);
        // When
        boolean served = cache.handleRequest(msg);
        // Then
        assertThat(served, is(equalTo(true)));
        assertThat(msg.getResponseHeader().getStatusCode(), is(equalTo(304)));
        assertThat(
                msg.getResponseHeader().getHeader(HttpHeader.CACHE_CONTROL),
                is(equalTo("public, max-age=3600")));
        assertThat(
                msg.getResponseHeader().getHeader("Expires"),
                is(equalTo("Thu, 02 Jul 2026 10:00:00 GMT")));
        assertThat(msg.getResponseHeader().getHeader("Vary"), is(equalTo("Accept-Encoding")));
        assertThat(msg.getResponseHeader().getHeader("Date"), is(notNullValue()));
    }

    @Test
    void shouldServe304WhenIfModifiedSinceMatches() throws Exception {
        // Given
        cache.handleResponse(createMessageWithValidators());
        HttpMessage msg = createRequest(URL);
        msg.getRequestHeader().setHeader(HttpHeader.IF_MODIFIED_SINCE, LAST_MODIFIED);
        // When
        boolean served = cache.handleRequest(msg);
        // Then
        assertThat(served, is(equalTo(true)));
        assertThat(msg.getResponseHeader().getStatusCode(), is(equalTo(304)));
        assertThat(msg.getResponseBody().length(), is(equalTo(0)));
        assertThat(msg.getResponseHeader().getHeader("Last-Modified"), is(equalTo(LAST_MODIFIED)));
    }

    @Test
    void shouldServeFullResponseWhenValidatorsDoNotMatch() throws Exception {
        // Given
        cache.handleResponse(createMessageWithValidators());
        HttpMessage msg = createRequest(URL);
        msg.getRequestHeader().setHeader(HttpHeader.IF_NONE_MATCH, "\"other\"");
        // When
        boolean served = cache.handleRequest(msg);
        // Then
        assertThat(served, is(equalTo(true)));
        assertThat(msg.getResponseHeader().getStatusCode(), is(equalTo(200)));
        assertThat(msg.getResponseBody().toString(), is(equalTo(BODY)));
    }

    @Test
    void shouldNotServeWhenRequestHasAuthorization() throws Exception {
        // Given
        cache.handleResponse(createMessage(URL, "text/css", BODY));
        HttpMessage msg = createRequest(URL);
        msg.getRequestHeader().setHeader(HttpHeader.AUTHORIZATION, "Basic 0123456789");
        // When
        boolean served = cache.handleRequest(msg);
        // Then
        assertThat(served, is(equalTo(false)));
    }

    @Test
    void shouldNotCacheNonGetRequests() throws Exception {
        // Given
        HttpMessage stored = createMessage(URL, "text/css", BODY);
        stored.getRequestHeader().setMethod("POST");
        cache.handleResponse(stored);
        // When
        boolean served = cache.handleRequest(createRequest(URL));
        // Then
        assertThat(served, is(equalTo(false)));
    }

    @Test
    void shouldNotCacheRequestsWithAuthorization() throws Exception {
        // Given
        HttpMessage stored = createMessage(URL, "text/css", BODY);
        stored.getRequestHeader().setHeader(HttpHeader.AUTHORIZATION, "Basic 0123456789");
        cache.handleResponse(stored);
        // When
        boolean served = cache.handleRequest(createRequest(URL));
        // Then
        assertThat(served, is(equalTo(false)));
    }

    @ParameterizedTest
    @ValueSource(ints = {204, 301, 304, 404, 500})
    void shouldNotCacheNonOkResponses(int statusCode) throws Exception {
        // Given
        HttpMessage stored = createMessage(URL, "text/css", BODY);
        stored.getResponseHeader().setStatusCode(statusCode);
        cache.handleResponse(stored);
        // When
        boolean served = cache.handleRequest(createRequest(URL));
        // Then
        assertThat(served, is(equalTo(false)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"text/html", "application/json", "application/xml", "text/plain"})
    void shouldNotCacheNonStaticContentTypes(String contentType) throws Exception {
        // Given
        cache.handleResponse(createMessage(URL, contentType, BODY));
        // When
        boolean served = cache.handleRequest(createRequest(URL));
        // Then
        assertThat(served, is(equalTo(false)));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "text/css",
                "text/css; charset=UTF-8",
                "text/javascript",
                "application/javascript",
                "image/png",
                "image/svg+xml",
                "font/woff2"
            })
    void shouldCacheStaticContentTypes(String contentType) throws Exception {
        // Given
        cache.handleResponse(createMessage(URL, contentType, BODY));
        // When
        boolean served = cache.handleRequest(createRequest(URL));
        // Then
        assertThat(served, is(equalTo(true)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"no-store", "no-cache", "private", "public, no-cache, max-age=0"})
    void shouldNotCacheResponsesWithCacheControlOptOut(String cacheControl) throws Exception {
        // Given
        HttpMessage stored = createMessage(URL, "text/css", BODY);
        stored.getResponseHeader().setHeader(HttpHeader.CACHE_CONTROL, cacheControl);
        cache.handleResponse(stored);
        // When
        boolean served = cache.handleRequest(createRequest(URL));
        // Then
        assertThat(served, is(equalTo(false)));
    }

    @Test
    void shouldNotCacheResponsesWithVaryOtherThanAcceptEncoding() throws Exception {
        // Given
        HttpMessage stored = createMessage(URL, "text/css", BODY);
        stored.getResponseHeader().setHeader("Vary", "Cookie");
        cache.handleResponse(stored);
        // When
        boolean served = cache.handleRequest(createRequest(URL));
        // Then
        assertThat(served, is(equalTo(false)));
    }

    @Test
    void shouldCacheResponsesWithVaryAcceptEncoding() throws Exception {
        // Given
        HttpMessage stored = createMessage(URL, "text/css", BODY);
        stored.getResponseHeader().setHeader("Vary", "Accept-Encoding");
        cache.handleResponse(stored);
        // When
        boolean served = cache.handleRequest(createRequest(URL));
        // Then
        assertThat(served, is(equalTo(true)));
    }

    @Test
    void shouldNotCacheResponsesWithBodyBiggerThanLimit() throws Exception {
        // Given
        HttpMessage stored = createMessage(URL, "text/css", "");
        stored.setResponseBody(new byte[1024 * 1024 + 1]);
        cache.handleResponse(stored);
        // When
        boolean served = cache.handleRequest(createRequest(URL));
        // Then
        assertThat(served, is(equalTo(false)));
    }

    @Test
    void shouldEvictOldestEntryWhenFull() throws Exception {
        // Given
        cache.handleResponse(createMessage(URL, "text/css", BODY));
        for (int i = 0; i < 500; i++) {
            cache.handleResponse(
                    createMessage("http://example.com/assets/" + i + ".css", "text/css", BODY));
        }
        // When
        boolean served = cache.handleRequest(createRequest(URL));
        // Then
        assertThat(served, is(equalTo(false)));
    }

    private static HttpMessage createRequest(String url) throws Exception {
        return new HttpMessage(new URI(url, true));
    }

    private static HttpMessage createMessage(String url, String contentType, String body)
            throws Exception {
        HttpMessage msg = createRequest(url);
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + HttpHeader.CONTENT_TYPE
                        + ": "
                        + contentType
                        + "\r\n"
                        + HttpHeader.CONTENT_LENGTH
                        + ": "
                        + body.length());
        msg.setResponseBody(body);
        return msg;
    }

    private static HttpMessage createMessageWithValidators() throws Exception {
        HttpMessage msg = createMessage(URL, "text/css", BODY);
        msg.getResponseHeader().setHeader("ETag", ETAG);
        msg.getResponseHeader().setHeader("Last-Modified", LAST_MODIFIED);
        return msg;
    }
}
