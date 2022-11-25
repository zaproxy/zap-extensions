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
package org.zaproxy.addon.network.internal.client.apachev5.h2;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.message.BasicHeader;
import org.apache.hc.core5.http.message.BasicHttpResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMessage;

/** Unit test for {@link HttpMessageResponseConsumer}. */
class HttpMessageResponseConsumerUnitTest {

    private HttpMessage msg;
    private HttpMessageResponseConsumer consumer;

    @BeforeEach
    void setup() throws Exception {
        msg = new HttpMessage();
        msg.setResponseHeader("HTTP/1.1 404 Not Found");
        msg.setResponseBody("Existing Body Content");
        consumer = new HttpMessageResponseConsumer(msg);
    }

    @ParameterizedTest
    @ValueSource(ints = {200, 500, 404})
    void shouldBuildResponseHeader(int statusCode) {
        // Given
        HttpResponse response = new BasicHttpResponse(statusCode);
        response.addHeader("header-a", "value-a");
        response.addHeader("header-b", "value-b");
        // When
        consumer.buildResult(response, null, null);
        // Then
        assertResponseHeader("HTTP/2 " + statusCode, "header-a: value-a", "header-b: value-b");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"Body 1", "Body 2"})
    void shouldBuildResponseBody(String body) {
        // Given
        HttpResponse response = new BasicHttpResponse(200);
        byte[] entity = body == null ? null : body.getBytes(StandardCharsets.ISO_8859_1);
        // When
        consumer.buildResult(response, entity, null);
        // Then
        String expectedBody = body == null ? "" : body;
        assertThat(msg.getResponseBody().toString(), is(equalTo(expectedBody)));
    }

    @Test
    void shouldSetTrailersIntoMessage() throws Exception {
        // Given
        List<? extends Header> trailers =
                List.of(new BasicHeader("a", "1"), new BasicHeader("b", "2"));
        // When
        consumer.streamEnd(trailers);
        // Then
        assertThat(
                msg.getUserObject(),
                is(
                        equalTo(
                                Map.of(
                                        "zap.h2.trailers.resp",
                                        List.of(
                                                new HttpHeaderField("a", "1"),
                                                new HttpHeaderField("b", "2"))))));
    }

    @Test
    void shouldNotSetTrailersIntoMessageIfNone() throws Exception {
        // Given
        List<? extends Header> trailers = null;
        // When
        consumer.streamEnd(trailers);
        // Then
        assertThat(msg.getUserObject(), is(nullValue()));
    }

    private void assertResponseHeader(String statusLine, String... headerFields) {
        assertHeader(msg.getResponseHeader(), statusLine, headerFields);
    }

    private static void assertHeader(
            HttpHeader httpHeader, String startLine, String... headerFields) {
        assertThat(httpHeader.isEmpty(), is(equalTo(false)));
        String allHeaderFields = String.join("\r\n", headerFields);
        if (headerFields != null && headerFields.length > 0) {
            allHeaderFields += "\r\n";
        }
        assertThat(
                httpHeader.toString(), is(equalTo(startLine + "\r\n" + allHeaderFields + "\r\n")));
    }
}
