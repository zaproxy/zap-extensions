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
package org.zaproxy.addon.network.internal;

import static java.util.Arrays.asList;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.network.HttpBody;
import org.parosproxy.paros.network.HttpHeader;
import org.zaproxy.zap.network.HttpEncodingDeflate;
import org.zaproxy.zap.network.HttpEncodingGzip;

/** Unit test for {@link ContentEncodingsHandler}. */
class ContentEncodingsHandlerUnitTest {

    private ContentEncodingsHandler handler;

    @BeforeEach
    void setUp() {
        handler = new ContentEncodingsHandler();
    }

    @ParameterizedTest
    @ValueSource(strings = {HttpHeader.GZIP, "x-gzip"})
    void shouldSetGzipEncodingToBody(String contentEncodingHeader) {
        // Given
        HttpHeader header = mock(HttpHeader.class);
        given(header.getHeader(HttpHeader.CONTENT_ENCODING)).willReturn(contentEncodingHeader);
        HttpBody body = mock(HttpBody.class);
        // When
        handler.handle(header, body);
        // Then
        verify(body).setContentEncodings(asList(HttpEncodingGzip.getSingleton()));
    }

    @Test
    void shouldSetDeflateEncodingToBody() {
        // Given
        HttpHeader header = mock(HttpHeader.class);
        given(header.getHeader(HttpHeader.CONTENT_ENCODING)).willReturn(HttpHeader.DEFLATE);
        HttpBody body = mock(HttpBody.class);
        // When
        handler.handle(header, body);
        // Then
        verify(body).setContentEncodings(asList(HttpEncodingDeflate.getSingleton()));
    }

    @Test
    @EnabledIf(
            value = "org.zaproxy.addon.network.internal.HttpEncodingBrotli#isAvailable",
            disabledReason = "OS not supported")
    void shouldSetBrotliEncodingToBody() {
        // Given
        HttpHeader header = mock(HttpHeader.class);
        given(header.getHeader(HttpHeader.CONTENT_ENCODING)).willReturn("br");
        HttpBody body = mock(HttpBody.class);
        // When
        handler.handle(header, body);
        // Then
        verify(body).setContentEncodings(asList(HttpEncodingBrotli.getSingleton()));
    }

    @ParameterizedTest
    @NullAndEmptySource
    void shouldNotSetContentEncodingToBodyIfContentEncodingIsNotPresentOrIsEmpty(
            String contentEncoding) {
        // Given
        HttpHeader header = mock(HttpHeader.class);
        given(header.getHeader(HttpHeader.CONTENT_ENCODING)).willReturn(contentEncoding);
        HttpBody body = mock(HttpBody.class);
        // When
        handler.handle(header, body);
        // Then
        verify(body).setContentEncodings(List.of());
    }

    @Test
    void shouldNotSetContentEncodingToBodyIfContentEncodingNotSupported() {
        // Given
        HttpHeader header = mock(HttpHeader.class);
        given(header.getHeader(HttpHeader.CONTENT_ENCODING)).willReturn("Encoding Not Supported");
        HttpBody body = mock(HttpBody.class);
        // When
        handler.handle(header, body);
        // Then
        verify(body).setContentEncodings(List.of());
    }
}
