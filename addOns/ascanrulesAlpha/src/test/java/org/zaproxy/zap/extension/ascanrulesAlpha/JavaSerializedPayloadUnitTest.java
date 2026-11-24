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
package org.zaproxy.zap.extension.ascanrulesAlpha;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

/** Unit test for {@link JavaSerializedPayload}. */
class JavaSerializedPayloadUnitTest {

    @Test
    void shouldStartWithJavaSerializationMagicBytes() {
        // Given / When
        byte[] payload = JavaSerializedPayload.create("example.com");
        // Then
        assertThat(
                Arrays.copyOf(payload, 4),
                is(equalTo(new byte[] {(byte) 0xac, (byte) 0xed, 0x00, 0x05})));
    }

    @Test
    void shouldDeserializeToMapWithUrlOfGivenHostUsingOnlyExpectedClasses() throws Exception {
        // Given
        // A literal IP address, so that deserializing does not need a DNS lookup.
        byte[] payload = JavaSerializedPayload.create("127.0.0.1");
        // When
        Object object;
        try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(payload))) {
            in.setObjectInputFilter(
                    ObjectInputFilter.Config.createFilter(
                            "java.util.HashMap;java.util.Map$Entry;java.net.URL;java.lang.String;!*"));
            object = in.readObject();
        }
        // Then
        assertThat(object, is(instanceOf(Map.class)));
        Map<?, ?> map = (Map<?, ?>) object;
        assertThat(map.size(), is(equalTo(1)));
        URL url = (URL) map.keySet().iterator().next();
        assertThat(url.getHost(), is(equalTo("127.0.0.1")));
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 15, 63, 253})
    void shouldWriteHostWithItsLength(int length) {
        // Given
        String host = "a".repeat(length);
        byte[] expected = serializedString(host);
        // When
        byte[] payload = JavaSerializedPayload.create(host);
        // Then
        assertThat(indexOf(payload, expected) != -1, is(equalTo(true)));
        assertThat(
                payload.length,
                is(equalTo(JavaSerializedPayload.create("HOSTPLACEHOLDER").length - 15 + length)));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"exa mple.com", "example.com/path", "example.com:80", "é.com"})
    void shouldRejectInvalidHosts(String host) {
        // Given / When / Then
        assertThrows(IllegalArgumentException.class, () -> JavaSerializedPayload.create(host));
    }

    @Test
    void shouldRejectTooLongHost() {
        // Given
        String host = "a".repeat(254);
        // When / Then
        assertThrows(IllegalArgumentException.class, () -> JavaSerializedPayload.create(host));
    }

    @Test
    void shouldEncodeWithStandardAlphabetAndPaddingByDefault() {
        // Given
        byte[] payload = JavaSerializedPayload.create("example.com");
        // When
        String encoded = JavaSerializedPayload.encodeLike("rO0ABXQABWhlbGxv", payload);
        // Then
        assertThat(encoded, is(equalTo(Base64.getEncoder().encodeToString(payload))));
    }

    @Test
    void shouldEncodeWithUrlSafeAlphabetIfOriginalUsesIt() {
        // Given
        byte[] payload = JavaSerializedPayload.create("example.com");
        // When
        String encoded = JavaSerializedPayload.encodeLike("rO0ABXQABW_l-Gxv", payload);
        // Then
        assertThat(encoded, is(equalTo(Base64.getUrlEncoder().encodeToString(payload))));
    }

    @Test
    void shouldEncodeWithoutPaddingIfOriginalHasNone() {
        // Given
        byte[] payload = JavaSerializedPayload.create("example.com");
        // When
        String encoded = JavaSerializedPayload.encodeLike("rO0ABXQAA2hleQ", payload);
        // Then
        assertThat(
                encoded, is(equalTo(Base64.getEncoder().withoutPadding().encodeToString(payload))));
    }

    private static byte[] serializedString(String value) {
        byte[] bytes = value.getBytes(StandardCharsets.US_ASCII);
        byte[] serialized = new byte[3 + bytes.length];
        serialized[0] = 0x74;
        serialized[1] = (byte) (bytes.length >> 8);
        serialized[2] = (byte) bytes.length;
        System.arraycopy(bytes, 0, serialized, 3, bytes.length);
        return serialized;
    }

    private static int indexOf(byte[] source, byte[] target) {
        for (int i = 0; i <= source.length - target.length; i++) {
            if (Arrays.equals(source, i, i + target.length, target, 0, target.length)) {
                return i;
            }
        }
        return -1;
    }
}
