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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;

/** Unit test for {@link HttpEncodingBrotli}. */
@EnabledIf(
        value = "org.zaproxy.addon.network.internal.HttpEncodingBrotli#isAvailable",
        disabledReason = "OS not supported")
class HttpEncodingBrotliUnitTest {

    private static final byte[] CONTENT = "42".getBytes(StandardCharsets.UTF_8);
    private static final byte[] CONTENT_ENCODED = {-117, 0, -128, 52, 50, 3};

    private HttpEncodingBrotli encoding = HttpEncodingBrotli.getSingleton();

    @Test
    void shouldEncodeContent() throws IOException {
        // Given / When
        byte[] encodedContent = encoding.encode(CONTENT);
        // Then
        assertThat(encodedContent, is(equalTo(CONTENT_ENCODED)));
    }

    @Test
    void shouldDecodeContent() throws IOException {
        // Given / When
        byte[] decodedContent = encoding.decode(CONTENT_ENCODED);
        // Then
        assertThat(decodedContent, is(equalTo(CONTENT)));
    }

    @Test
    void shouldThrowExceptionWhenDecodingIfNotProperlyEncoded() {
        // Given
        byte[] invalidContent = new byte[] {'I', 'n', 'v', 'a', 'l', 'i', 'd'};
        // When / Then
        assertThrows(IOException.class, () -> encoding.decode(invalidContent));
    }
}
