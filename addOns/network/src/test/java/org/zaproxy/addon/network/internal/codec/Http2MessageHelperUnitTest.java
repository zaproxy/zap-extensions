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
package org.zaproxy.addon.network.internal.codec;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasItems;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.zaproxy.addon.network.internal.codec.Http2MessageHelper.copyHeaders;
import static org.zaproxy.addon.network.internal.codec.Http2MessageHelper.createHttp2Headers;
import static org.zaproxy.addon.network.internal.codec.Http2MessageHelper.createTrailerHttp2Headers;
import static org.zaproxy.addon.network.internal.codec.Http2MessageHelper.setHttpRequest;
import static org.zaproxy.addon.network.internal.codec.Http2MessageHelper.setHttpResponse;

import io.netty.handler.codec.http2.DefaultHttp2Headers;
import io.netty.handler.codec.http2.Http2Error;
import io.netty.handler.codec.http2.Http2Exception;
import io.netty.handler.codec.http2.Http2Headers;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.parosproxy.paros.network.HttpBody;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;

/** Unit test for {@link Http2MessageHelper}. */
class Http2MessageHelperUnitTest {

    private static final int STREAM_ID = 15;

    private Http2Headers headers;
    private HttpMessage msg;

    @BeforeEach
    void setUp() {
        headers = new DefaultHttp2Headers(false);
        msg = new HttpMessage();
    }

    static Stream<String> schemes() {
        return Stream.of(HttpHeader.HTTP, HttpHeader.HTTPS);
    }

    static Stream<String> statusCodes() {
        return Arrays.stream(HttpStatusCode.CODES).mapToObj(String::valueOf);
    }

    @ParameterizedTest
    @MethodSource("schemes")
    void shouldSetRequest(String scheme) throws Exception {
        // Given
        headers.method("METHOD");
        headers.scheme(scheme);
        headers.authority("127.0.0.1:8080");
        headers.path("/path?query=a");
        headers.add("header-a", "value-a");
        headers.add("header-b", "value-b");
        // When
        setHttpRequest(STREAM_ID, headers, msg);
        // Then
        assertRequestHeader(
                "METHOD " + scheme + "://127.0.0.1:8080/path?query=a HTTP/2",
                "header-a: value-a",
                "header-b: value-b");
        assertRequestBody("");
    }

    @ParameterizedTest
    @NullAndEmptySource
    void shouldNotSetRequestWithMissingMethod(String method) throws Exception {
        // Given
        if (method != null) {
            headers.method(method);
        }
        headers.scheme(HttpHeader.HTTPS);
        headers.authority("127.0.0.1:8080");
        headers.path("/path?query=a");
        headers.add("header-a", "value-a");
        // When / Then
        Http2Exception e =
                assertThrows(Http2Exception.class, () -> setHttpRequest(STREAM_ID, headers, msg));
        assertThat(e.getMessage(), is(equalTo("HTTP/2 headers does not have a method.")));
        assertThat(e.error(), is(equalTo(Http2Error.PROTOCOL_ERROR)));
        assertThat(msg.getRequestHeader().isEmpty(), is(equalTo(true)));
        assertRequestBody("");
    }

    @ParameterizedTest
    @NullAndEmptySource
    void shouldNotSetRequestWithMissingScheme(String scheme) throws Exception {
        // Given
        headers.method("METHOD");
        if (scheme != null) {
            headers.scheme(scheme);
        }
        headers.authority("127.0.0.1:8080");
        headers.path("/path?query=a");
        headers.add("header-a", "value-a");
        // When / Then
        Http2Exception e =
                assertThrows(Http2Exception.class, () -> setHttpRequest(STREAM_ID, headers, msg));
        assertThat(e.getMessage(), is(equalTo("HTTP/2 headers does not have a scheme.")));
        assertThat(e.error(), is(equalTo(Http2Error.PROTOCOL_ERROR)));
        assertThat(msg.getRequestHeader().isEmpty(), is(equalTo(true)));
        assertRequestBody("");
    }

    @ParameterizedTest
    @MethodSource("schemes")
    void shouldNotSetRequestWithMissingAuthority(String scheme) throws Exception {
        // Given
        headers.method("METHOD");
        headers.scheme(scheme);
        headers.path("/path?query=a");
        headers.add("header-a", "value-a");
        // When / Then
        Http2Exception e =
                assertThrows(Http2Exception.class, () -> setHttpRequest(STREAM_ID, headers, msg));
        assertThat(e.getMessage(), is(equalTo("HTTP/2 headers does not have an authority.")));
        assertThat(e.error(), is(equalTo(Http2Error.PROTOCOL_ERROR)));
        assertThat(msg.getRequestHeader().isEmpty(), is(equalTo(true)));
        assertRequestBody("");
    }

    @ParameterizedTest
    @NullAndEmptySource
    void shouldSetRequestWithMissingPath(String path) throws Exception {
        // Given
        headers.method("METHOD");
        headers.scheme("https");
        headers.authority("127.0.0.1:8080");
        if (path != null) {
            headers.path(path);
        }
        headers.add("header-a", "value-a");
        headers.add("header-b", "value-b");
        // When
        setHttpRequest(STREAM_ID, headers, msg);
        // Then
        assertRequestHeader(
                "METHOD https://127.0.0.1:8080/ HTTP/2", "header-a: value-a", "header-b: value-b");
        assertRequestBody("");
    }

    @ParameterizedTest
    @MethodSource("schemes")
    void shouldSetRequestIncludingInvalidPseudoHeaders(String scheme) throws Exception {
        // Given
        headers.method("METHOD");
        headers.scheme(scheme);
        headers.authority("127.0.0.1:8080");
        headers.path("/path?query=a");
        headers.add("header-a", "value-a");
        headers.add(":invalid-1", "value-1");
        headers.add("header-b", "value-b");
        headers.add(":invalid-2", "value-2");
        // When
        setHttpRequest(STREAM_ID, headers, msg);
        // Then
        assertRequestHeader(
                "METHOD " + scheme + "://127.0.0.1:8080/path?query=a HTTP/2",
                ":invalid-1: value-1",
                ":invalid-2: value-2",
                "header-a: value-a",
                "header-b: value-b");
        assertRequestBody("");
    }

    @ParameterizedTest
    @MethodSource("schemes")
    void shouldSetRequestMergingCookieHeaders(String scheme) throws Exception {
        // Given
        headers.method("METHOD");
        headers.scheme(scheme);
        headers.authority("127.0.0.1:8080");
        headers.path("/path?query=a");
        headers.add("header-a", "value-a");
        headers.add("cookie", "sid=B");
        headers.add("cookie", "csrftoken=A");
        headers.add("header-b", "value-b");
        headers.add("cookie", "a=2");
        // When
        setHttpRequest(STREAM_ID, headers, msg);
        // Then
        assertRequestHeader(
                "METHOD " + scheme + "://127.0.0.1:8080/path?query=a HTTP/2",
                "header-a: value-a",
                "header-b: value-b",
                "cookie: sid=B; csrftoken=A; a=2");
        assertRequestBody("");
    }

    @ParameterizedTest
    @MethodSource("schemes")
    void shouldSetRequestKeepingAndMergingCookieHeaders(String scheme) throws Exception {
        // Given
        headers.method("METHOD");
        headers.scheme(scheme);
        headers.authority("127.0.0.1:8080");
        headers.path("/path?query=a");
        headers.add("header-a", "value-a");
        headers.add("cookie", "sid=B; csrftoken=A");
        headers.add("header-b", "value-b");
        headers.add("cookie", "a=2");
        // When
        setHttpRequest(STREAM_ID, headers, msg);
        // Then
        assertRequestHeader(
                "METHOD " + scheme + "://127.0.0.1:8080/path?query=a HTTP/2",
                "header-a: value-a",
                "header-b: value-b",
                "cookie: sid=B; csrftoken=A; a=2");
        assertRequestBody("");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @MethodSource("schemes")
    void shouldSetConnectRequest(String scheme) throws Exception {
        // Given
        headers.method("CONNECT");
        if (scheme != null) {
            headers.scheme(scheme);
        }
        headers.authority("127.0.0.1:8080");
        headers.path("path should not be used");
        headers.add("header", "value");
        // When
        setHttpRequest(STREAM_ID, headers, msg);
        // Then
        assertRequestHeader("CONNECT 127.0.0.1:8080 HTTP/2", "header: value");
        assertRequestBody("");
    }

    @ParameterizedTest
    @MethodSource("schemes")
    void shouldSetOptionsRequest(String scheme) throws Exception {
        // Given
        headers.method("OPTIONS");
        headers.scheme(scheme);
        headers.authority("127.0.0.1:8080");
        headers.path("/path");
        // When
        setHttpRequest(STREAM_ID, headers, msg);
        // Then
        assertRequestHeader("OPTIONS " + scheme + "://127.0.0.1:8080/path HTTP/2");
        assertRequestBody("");
    }

    @ParameterizedTest
    @MethodSource("schemes")
    void shouldSetAsteriskOptionsRequest(String scheme) throws Exception {
        // Given
        headers.method("OPTIONS");
        headers.scheme(scheme);
        headers.authority("127.0.0.1:8080");
        headers.path("*");
        // When / Then
        setHttpRequest(STREAM_ID, headers, msg);
        // XXX Not supported by core, should result in e.g.:
        // assertRequestHeader("OPTIONS * HTTP/2");
        assertRequestHeader("OPTIONS " + scheme + "://null* HTTP/2");
        assertRequestBody("");
    }

    @ParameterizedTest
    @MethodSource("statusCodes")
    void shouldSetResponse(String statusCode) throws Exception {
        // Given
        headers.status(statusCode);
        headers.add("header-a", "value-a");
        headers.add("header-b", "value-b");
        // When
        setHttpResponse(STREAM_ID, headers, msg);
        // Then
        assertResponseHeader("HTTP/2 " + statusCode, "header-a: value-a", "header-b: value-b");
        assertResponseBody("");
    }

    @ParameterizedTest
    @NullAndEmptySource
    void shouldNotSetResponseWithMissingStatus(String status) throws Exception {
        // Given
        if (status != null) {
            headers.status(status);
        }
        headers.add("header-a", "value-a");
        // When / Then
        Http2Exception e =
                assertThrows(Http2Exception.class, () -> setHttpResponse(STREAM_ID, headers, msg));
        assertThat(e.getMessage(), startsWith("HTTP/2 headers does not have a status."));
        assertThat(e.error(), is(equalTo(Http2Error.PROTOCOL_ERROR)));
        assertThat(msg.getResponseHeader().isEmpty(), is(equalTo(true)));
        assertResponseBody("");
    }

    @Test
    void shouldNotSetResponseWithInvalidStatus() throws Exception {
        // Given
        headers.status("Not a number");
        headers.add("header-a", "value-a");
        // When / Then
        Http2Exception e =
                assertThrows(Http2Exception.class, () -> setHttpResponse(STREAM_ID, headers, msg));
        assertThat(e.getMessage(), startsWith("Failed to find pattern: "));
        assertThat(e.error(), is(equalTo(Http2Error.PROTOCOL_ERROR)));
        assertThat(msg.getResponseHeader().isEmpty(), is(equalTo(false)));
        assertThat(msg.getResponseHeader().isMalformedHeader(), is(equalTo(true)));
        assertResponseBody("");
    }

    @Test
    void shouldAddHeadersToRequest() throws Exception {
        // Given
        headers.add("header-a", "value-a");
        headers.add("header-b", "value-b");
        // When
        copyHeaders(STREAM_ID, headers, msg, true);
        // Then
        assertRequestHeaderFields("header-a: value-a", "header-b: value-b");
        assertRequestBody("");
    }

    @Test
    void shouldAddHeadersToRequestMergingCookies() throws Exception {
        // Given
        headers.add("header-a", "value-a");
        headers.add("cookie", "a=b");
        headers.add("header-b", "value-b");
        headers.add("cookie", "c=d");
        // When
        copyHeaders(STREAM_ID, headers, msg, true);
        // Then
        assertRequestHeaderFields("header-a: value-a", "header-b: value-b", "cookie: a=b; c=d");
        assertRequestBody("");
    }

    @Test
    void shouldAddHeadersToRequestMergingEmptyCookies() throws Exception {
        // Given
        headers.add("header-a", "value-a");
        headers.add("cookie", "");
        headers.add("cookie", "a=b");
        headers.add("header-b", "value-b");
        headers.add("cookie", "");
        // When
        copyHeaders(STREAM_ID, headers, msg, true);
        // Then
        assertRequestHeaderFields("header-a: value-a", "header-b: value-b", "cookie: a=b; ");
        assertRequestBody("");
    }

    @Test
    void shouldAddHeadersToRequestKeepingSingleCookie() throws Exception {
        // Given
        headers.add("header-a", "value-a");
        headers.add("cookie", "a=b");
        headers.add("header-b", "value-b");
        // When
        copyHeaders(STREAM_ID, headers, msg, true);
        // Then
        assertRequestHeaderFields("header-a: value-a", "header-b: value-b", "cookie: a=b");
        assertRequestBody("");
    }

    @Test
    void shouldNotAddHeadersNoLongerApplicableToRequest() throws Exception {
        // Given
        headers.add("header-a", "value-a");
        headers.add("Transfer-Encoding", "chunked");
        headers.add("header-b", "value-b");
        // When
        copyHeaders(STREAM_ID, headers, msg, true);
        // Then
        assertRequestHeaderFields("header-a: value-a", "header-b: value-b");
        assertRequestBody("");
    }

    @Test
    void shouldAddHeadersToResponse() throws Exception {
        // Given
        headers.add("header-a", "value-a");
        headers.add("header-b", "value-b");
        // When
        copyHeaders(STREAM_ID, headers, msg, false);
        // Then
        assertResponseHeaderFields("header-a: value-a", "header-b: value-b");
        assertResponseBody("");
    }

    @Test
    void shouldNotAddHeadersNoLongerApplicableToResponse() throws Exception {
        // Given
        headers.add("header-a", "value-a");
        headers.add("Transfer-Encoding", "chunked");
        headers.add("header-b", "value-b");
        // When
        copyHeaders(STREAM_ID, headers, msg, false);
        // Then
        assertResponseHeaderFields("header-a: value-a", "header-b: value-b");
        assertResponseBody("");
    }

    @ParameterizedTest
    @MethodSource("schemes")
    void shouldCreateHttp2HeadersFromRequest(String scheme) throws Exception {
        // Given
        String method = "METHOD";
        String authority = "127.0.0.1:8080";
        String path = "/path?a=b";
        HttpHeader header = msg.getRequestHeader();
        header.setMessage(method + " " + scheme + "://" + authority + path + " HTTP/2");
        header.addHeader("a", "1");
        header.addHeader("b", "2");
        // When
        headers = createHttp2Headers(scheme, header);
        // Then
        assertThat(headers.method(), is(equalTo(method)));
        assertThat(headers.scheme(), is(equalTo(scheme)));
        assertThat(headers.authority(), is(equalTo(authority)));
        assertThat(headers.path(), is(equalTo(path)));
        assertThat(headers.status(), is(nullValue()));
        assertThat(
                toHeaderFields(headers),
                contains(
                        header(":scheme", scheme),
                        header(":method", method),
                        header(":path", path),
                        header(":authority", authority),
                        header("a", "1"),
                        header("b", "2")));
    }

    @ParameterizedTest
    @MethodSource("schemes")
    void shouldCreateHttp2HeadersAddingPathIfEmpty(String scheme) throws Exception {
        // Given
        HttpHeader header = msg.getRequestHeader();
        header.setMessage("METHOD http://127.0.0.1:8080 HTTP/2");
        // When
        headers = createHttp2Headers(scheme, header);
        // Then
        String path = "/";
        assertThat(headers.path(), is(equalTo(path)));
        assertThat(toHeaderFields(headers), hasItem(header(":path", path)));
    }

    @Test
    void shouldCreateHttp2HeadersFromRequestWithSingleCookie() throws Exception {
        // Given
        HttpHeader header = msg.getRequestHeader();
        header.setMessage("METHOD http://127.0.0.1:8080/path HTTP/2");
        header.addHeader("Cookie", "a=b");
        // When
        headers = createHttp2Headers("http", header);
        // Then
        assertThat(toHeaderFields(headers, false), contains(header("cookie", "a=b")));
    }

    @Test
    void shouldCreateHttp2HeadersFromRequestSplittingCookies() throws Exception {
        // Given
        HttpHeader header = msg.getRequestHeader();
        header.setMessage("METHOD http://127.0.0.1:8080/path HTTP/2");
        header.addHeader("Cookie", "a=b; c=d;  e=f;g=h");
        // When
        headers = createHttp2Headers("http", header);
        // Then
        assertThat(
                toHeaderFields(headers, false),
                contains(
                        header("cookie", "a=b"),
                        header("cookie", "c=d"),
                        header("cookie", "e=f"),
                        header("cookie", "g=h")));
    }

    @Test
    void shouldCreateHttp2HeadersFromRequestWithEmptyCookie() throws Exception {
        // Given
        HttpHeader header = msg.getRequestHeader();
        header.setMessage("METHOD http://127.0.0.1:8080/path HTTP/2");
        header.addHeader("Cookie", "");
        // When
        headers = createHttp2Headers("http", header);
        // Then
        assertThat(toHeaderFields(headers, false), contains(header("cookie", "")));
    }

    @Test
    void shouldCreateHttp2HeadersFromRequestWithHostHeader() throws Exception {
        // Given
        HttpHeader header = msg.getRequestHeader();
        header.setMessage("METHOD http://127.0.0.1:8080/path HTTP/2");
        String host = "example.org";
        header.addHeader("Host", host);
        // When
        headers = createHttp2Headers("http", header);
        // Then
        assertThat(headers.authority(), is(equalTo(host)));
        assertThat(
                toHeaderFields(headers),
                hasItems(header(":authority", host), header("host", host)));
    }

    @ParameterizedTest
    @MethodSource("statusCodes")
    void shouldCreateHttp2HeadersFromResponse(String status) throws Exception {
        // Given
        HttpHeader header = msg.getResponseHeader();
        header.setMessage("HTTP/2 " + status + " Reason");
        header.addHeader("a", "1");
        header.addHeader("b", "2");
        // When
        headers = createHttp2Headers("http", header);
        // Then
        assertThat(headers.status(), is(equalTo(status)));
        assertThat(
                toHeaderFields(headers),
                contains(header(":status", status), header("a", "1"), header("b", "2")));
    }

    @Test
    void shouldCreateHttp2HeadersFromRequestTrailers() throws Exception {
        // Given
        Map<String, Object> properties = new HashMap<>();
        properties.put(
                "zap.h2.trailers.req",
                List.of(new HttpHeaderField("a", "1"), new HttpHeaderField("b", "2")));
        msg.setUserObject(properties);
        // When
        headers = createTrailerHttp2Headers(msg, true);
        // Then
        assertThat(toHeaderFields(headers), contains(header("a", "1"), header("b", "2")));
    }

    @Test
    void shouldCreateHttp2HeadersFromResponseTrailers() throws Exception {
        // Given
        Map<String, Object> properties = new HashMap<>();
        properties.put(
                "zap.h2.trailers.resp",
                List.of(new HttpHeaderField("a", "1"), new HttpHeaderField("b", "2")));
        msg.setUserObject(properties);
        // When
        headers = createTrailerHttp2Headers(msg, false);
        // Then
        assertThat(toHeaderFields(headers), contains(header("a", "1"), header("b", "2")));
    }

    private void assertRequestHeader(String requestLine, String... headerFields) {
        assertHeader(msg.getRequestHeader(), requestLine, headerFields);
    }

    private static void assertHeader(
            HttpHeader httpHeader, String startLine, String... headerFields) {
        assertThat(httpHeader.isEmpty(), is(equalTo(false)));
        String allHeaderFields = mergeHeaderFields(headerFields);
        assertThat(
                httpHeader.toString(), is(equalTo(startLine + "\r\n" + allHeaderFields + "\r\n")));
    }

    private static String mergeHeaderFields(String[] headerFields) {
        String allHeaderFields = String.join("\r\n", headerFields);
        if (headerFields != null && headerFields.length > 0) {
            allHeaderFields += "\r\n";
        }
        return allHeaderFields;
    }

    private void assertRequestBody(String contents) {
        assertBody(msg.getRequestBody(), contents);
    }

    private static void assertBody(HttpBody httpBody, String contents) {
        assertThat(contents.toString(), is(equalTo(contents)));
    }

    private void assertResponseHeader(String statusLine, String... headerFields) {
        assertHeader(msg.getResponseHeader(), statusLine, headerFields);
    }

    private void assertResponseBody(String contents) {
        assertBody(msg.getResponseBody(), contents);
    }

    private void assertRequestHeaderFields(String... headerFields) {
        assertHeaderFields(msg.getRequestHeader(), headerFields);
    }

    private static void assertHeaderFields(HttpHeader httpHeader, String... headerFields) {
        String allHeaderFields = mergeHeaderFields(headerFields);
        assertThat(httpHeader.getHeadersAsString(), is(equalTo(allHeaderFields)));
    }

    private void assertResponseHeaderFields(String... headerFields) {
        assertHeaderFields(msg.getResponseHeader(), headerFields);
    }

    private static HttpHeaderField header(String name, String value) {
        return new HttpHeaderField(name, value);
    }

    private static List<HttpHeaderField> toHeaderFields(Http2Headers headers) {
        return toHeaderFields(headers, true);
    }

    private static List<HttpHeaderField> toHeaderFields(
            Http2Headers headers, boolean pseudoHeaders) {
        List<HttpHeaderField> list = new ArrayList<>();
        for (Entry<CharSequence, CharSequence> header : headers) {
            String name = header.getKey().toString();
            if (!pseudoHeaders && name.startsWith(":")) {
                continue;
            }
            list.add(new HttpHeaderField(name, header.getValue().toString()));
        }
        return list;
    }
}
