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
package org.zaproxy.zap.extension.fuzz.httpfuzzer.processors;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerTaskProcessorUtils;
import org.zaproxy.zap.network.HttpRequestBody;
import org.zaproxy.zap.utils.I18N;

/** Unit test for {@link RequestContentLengthUpdaterProcessor}. */
class RequestContentLengthUpdaterProcessorUnitTest {

    @BeforeEach
    void setUp() throws Exception {
        I18N i18n = mock(I18N.class);
        given(i18n.getString(any())).willReturn("");
        Constant.messages = i18n;
    }

    @Test
    void shouldReturnANonNullInstance() {
        // Given
        RequestContentLengthUpdaterProcessor processor =
                RequestContentLengthUpdaterProcessor.getInstance();
        // When / Then
        assertThat(processor, is(notNullValue()));
    }

    @Test
    void shouldReturnsAlwaysSameInstance() {
        // Given
        RequestContentLengthUpdaterProcessor processor =
                RequestContentLengthUpdaterProcessor.getInstance();
        RequestContentLengthUpdaterProcessor processor2 =
                RequestContentLengthUpdaterProcessor.getInstance();
        // When / Then
        assertThat(processor, is(equalTo(processor2)));
    }

    @Test
    void shouldHaveANonNullName() {
        // Given
        RequestContentLengthUpdaterProcessor processor = new RequestContentLengthUpdaterProcessor();
        // When
        String name = processor.getName();
        // Then
        assertThat(name, is(notNullValue()));
    }

    @Test
    void shouldCreateProcessorWithUndefinedMethod() {
        // Given
        String undefinedMethod = null;
        // When / Then
        assertDoesNotThrow(() -> new RequestContentLengthUpdaterProcessor(undefinedMethod));
    }

    @Test
    void shouldFailToProcessAnUndefinedMessage() {
        // Given
        RequestContentLengthUpdaterProcessor processor = new RequestContentLengthUpdaterProcessor();
        HttpMessage undefinedMessage = null;
        HttpFuzzerTaskProcessorUtils utils = createUtils();
        // When / Then
        assertThrows(
                NullPointerException.class,
                () -> processor.processMessage(utils, undefinedMessage));
    }

    @Test
    void shouldNotRequireUtilsToProcessMessage() {
        // Given
        RequestContentLengthUpdaterProcessor processor = new RequestContentLengthUpdaterProcessor();
        // When / Then
        assertDoesNotThrow(() -> processor.processMessage(null, new HttpMessage()));
    }

    @Test
    void shouldReturnSameMessageWhenProcessing() {
        // Given
        RequestContentLengthUpdaterProcessor processor = new RequestContentLengthUpdaterProcessor();
        HttpMessage message = new HttpMessage();
        // When
        HttpMessage processedMessage = processor.processMessage(createUtils(), message);
        // Then
        assertThat(processedMessage, is(equalTo(message)));
    }

    @Test
    void shouldNotAddContentLengthIfEmptyBody() {
        // Given
        RequestContentLengthUpdaterProcessor processor =
                new RequestContentLengthUpdaterProcessor("POST");
        HttpMessage messageEmptyBody = createHttpMessage("POST");
        // When
        processor.processMessage(createUtils(), messageEmptyBody);
        // Then
        assertThat(
                messageEmptyBody.getRequestHeader().getHeader(HttpRequestHeader.CONTENT_LENGTH),
                is(equalTo(null)));
    }

    @Test
    void shouldAddContentLengthIfNotEmptyBody() {
        // Given
        RequestContentLengthUpdaterProcessor processor =
                new RequestContentLengthUpdaterProcessor("POST");
        HttpMessage messageWithBody = createHttpMessage("POST", null, "body");
        // When
        processor.processMessage(createUtils(), messageWithBody);
        // Then
        assertThat(
                messageWithBody.getRequestHeader().getHeader(HttpRequestHeader.CONTENT_LENGTH),
                is(equalTo("4")));
    }

    @Test
    void shouldUpdateExistingContentLengthIfEmptyBody() {
        // Given
        RequestContentLengthUpdaterProcessor processor =
                new RequestContentLengthUpdaterProcessor("POST");
        HttpMessage messageEmptyBody = createHttpMessage("POST", 15);
        // When
        processor.processMessage(createUtils(), messageEmptyBody);
        // Then
        assertThat(
                messageEmptyBody.getRequestHeader().getHeader(HttpRequestHeader.CONTENT_LENGTH),
                is(equalTo("0")));
    }

    @Test
    void shouldUpdateContentLengthForAnyMethodWhenNoMethodIsSpecified() {
        // Given
        RequestContentLengthUpdaterProcessor processor = new RequestContentLengthUpdaterProcessor();
        String body = "RequestBody";
        HttpMessage postMessage = createHttpMessage("POST", 5, body);
        HttpMessage getMessage = createHttpMessage("GET", 80, body);
        HttpMessage xyzMessage = createHttpMessage("XYZ", 0, body);
        // When
        processor.processMessage(createUtils(), postMessage);
        processor.processMessage(createUtils(), getMessage);
        processor.processMessage(createUtils(), xyzMessage);
        // Then
        assertThat(
                postMessage.getRequestHeader().getHeader(HttpRequestHeader.CONTENT_LENGTH),
                is(equalTo("11")));
        assertThat(
                getMessage.getRequestHeader().getHeader(HttpRequestHeader.CONTENT_LENGTH),
                is(equalTo("11")));
        assertThat(
                xyzMessage.getRequestHeader().getHeader(HttpRequestHeader.CONTENT_LENGTH),
                is(equalTo("11")));
    }

    @Test
    void shouldUpdateContentLengthForAnyMethodWithInstance() {
        // Given
        RequestContentLengthUpdaterProcessor processor =
                RequestContentLengthUpdaterProcessor.getInstance();
        String body = "RequestBody";
        HttpMessage postMessage = createHttpMessage("POST", 5, body);
        HttpMessage getMessage = createHttpMessage("GET", 80, body);
        HttpMessage xyzMessage = createHttpMessage("XYZ", 0, body);
        // When
        processor.processMessage(createUtils(), postMessage);
        processor.processMessage(createUtils(), getMessage);
        processor.processMessage(createUtils(), xyzMessage);
        // Then
        assertThat(
                postMessage.getRequestHeader().getHeader(HttpRequestHeader.CONTENT_LENGTH),
                is(equalTo("11")));
        assertThat(
                getMessage.getRequestHeader().getHeader(HttpRequestHeader.CONTENT_LENGTH),
                is(equalTo("11")));
        assertThat(
                xyzMessage.getRequestHeader().getHeader(HttpRequestHeader.CONTENT_LENGTH),
                is(equalTo("11")));
    }

    @Test
    void shouldUpdateContentLengthForSpecifiedMethodOnly() {
        // Given
        RequestContentLengthUpdaterProcessor processor =
                new RequestContentLengthUpdaterProcessor("POST");
        String body = "RequestBody";
        HttpMessage postMessage = createHttpMessage("POST", 50, body);
        HttpMessage getMessage = createHttpMessage("GET", 4, body);
        HttpMessage xyzMessage = createHttpMessage("XYZ", 8, body);
        // When
        processor.processMessage(createUtils(), postMessage);
        processor.processMessage(createUtils(), getMessage);
        processor.processMessage(createUtils(), xyzMessage);
        // Then
        assertThat(
                postMessage.getRequestHeader().getHeader(HttpRequestHeader.CONTENT_LENGTH),
                is(equalTo("11")));
        assertThat(
                getMessage.getRequestHeader().getHeader(HttpRequestHeader.CONTENT_LENGTH),
                is(equalTo("4")));
        assertThat(
                xyzMessage.getRequestHeader().getHeader(HttpRequestHeader.CONTENT_LENGTH),
                is(equalTo("8")));
    }

    @Test
    void shouldAcceptResultsAlways() {
        // Given
        RequestContentLengthUpdaterProcessor processor = new RequestContentLengthUpdaterProcessor();
        // When
        boolean acceptResult = processor.processResult(null, null);
        // Then
        assertThat(acceptResult, is(equalTo(true)));
    }

    private static HttpMessage createHttpMessage(String method) {
        return createHttpMessage(method, null);
    }

    private static HttpMessage createHttpMessage(String method, Integer contentLength) {
        return createHttpMessage(method, contentLength, "");
    }

    private static HttpMessage createHttpMessage(
            String method, Integer contentLength, String body) {
        StringBuilder sb = new StringBuilder(150);
        sb.append(method).append(" http://example.org/ HTTP/1.1\r\n");
        if (contentLength != null) {
            sb.append(HttpRequestHeader.CONTENT_LENGTH)
                    .append(": ")
                    .append(contentLength)
                    .append("\r\n");
        }

        try {
            return new HttpMessage(new HttpRequestHeader(sb.toString()), new HttpRequestBody(body));
        } catch (HttpMalformedHeaderException e) {
            throw new RuntimeException(e);
        }
    }

    private static HttpFuzzerTaskProcessorUtils createUtils() {
        return new HttpFuzzerTaskProcessorTestUtils();
    }

    private static class HttpFuzzerTaskProcessorTestUtils extends HttpFuzzerTaskProcessorUtils {

        protected HttpFuzzerTaskProcessorTestUtils() {
            super(null, null, 0, null);
        }
    }
}
