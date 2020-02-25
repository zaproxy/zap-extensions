/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP Development Team
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
package org.zaproxy.zap.extension.websocket.utility;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;

/** Encode or decode from byte[] to Utf8 and vice versa. */
public final class Utf8Util {

    private Utf8Util() {}

    /**
     * Helper method to encode payload into UTF-8 string.
     *
     * @param utf8bytes
     * @return readable representation
     * @throws InvalidUtf8Exception
     */
    public static String encodePayloadToUtf8(byte[] utf8bytes) throws InvalidUtf8Exception {
        return encodePayloadToUtf8(utf8bytes, 0, utf8bytes.length);
    }

    /**
     * Helper method to encode payload into UTF-8 string.
     *
     * @param utf8bytes
     * @param offset
     * @param length
     * @return readable representation
     * @throws InvalidUtf8Exception
     */
    public static String encodePayloadToUtf8(byte[] utf8bytes, int offset, int length)
            throws InvalidUtf8Exception {
        try {
            return StandardCharsets.UTF_8
                    .newDecoder()
                    .decode(ByteBuffer.wrap(utf8bytes, offset, length))
                    .toString();
        } catch (CharacterCodingException e) {
            throw new InvalidUtf8Exception("Unable to decode given bytes as UTF-8!", e);
        }
    }

    /**
     * Helper method that takes an UTF-8 string and returns its byte representation.
     *
     * @param utf8string
     * @return byte representation
     */
    public static byte[] decodePayloadFromUtf8(String utf8string) {
        return utf8string.getBytes(StandardCharsets.UTF_8);
    }
}
