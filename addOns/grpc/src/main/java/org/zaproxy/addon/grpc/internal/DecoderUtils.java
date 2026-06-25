/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.grpc.internal;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class DecoderUtils {

    public static final int PAYLOAD_HEADER_SIZE = 5;

    public static final int DOUBLE_EXPONENT_LEN = 11;

    public static final int FLOAT_EXPONENT_LEN = 8;

    public static final int DOUBLE_MANTISSA_LEN = 52;

    public static final int FLOAT_MANTISSA_LEN = 23;

    public static final byte[] EMPTY_BYTE_ARRAY = new byte[0];

    public enum DecodingMethod {
        BASE64_ENCODED,
        DIRECT
    }

    static boolean isGraphic(byte ch) {
        // Check if the character is printable
        // Printable characters have unicode values greater than 32 (excluding control
        // characters) and aren't whitespace
        return (ch > 32 && ch != 127 && ch <= 255 && !Character.isWhitespace(ch));
    }

    public static String toHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder(2 * bytes.length);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }

    public static boolean isFloat(int value) {
        int exp = (value >> FLOAT_MANTISSA_LEN) & ((1 << FLOAT_EXPONENT_LEN) - 1);
        exp -= (1 << (FLOAT_EXPONENT_LEN - 1)) - 1;
        if (exp < 0) {
            exp = -exp;
        }
        int bigExp = (1 << (FLOAT_EXPONENT_LEN - 1)) - 1;
        return exp < bigExp;
    }

    public static boolean isDouble(long value) {
        long exp = (value >> DOUBLE_MANTISSA_LEN) & ((1 << DOUBLE_EXPONENT_LEN) - 1);
        exp -= (1 << (DOUBLE_EXPONENT_LEN - 1)) - 1;
        if (exp < 0) {
            exp = -exp;
        }
        int bigExp = (1 << (DOUBLE_EXPONENT_LEN - 1)) - 1;
        return exp < bigExp;
    }

    public static byte[] extractPayload(byte[] input) {
        if (input.length <= PAYLOAD_HEADER_SIZE) {
            return EMPTY_BYTE_ARRAY;
        }
        return Arrays.copyOfRange(input, PAYLOAD_HEADER_SIZE, input.length);
    }

    static byte[] splitMessageBodyAndStatusCode(byte[] encodedText)
            throws UnsupportedEncodingException {
        String encodedString = new String(encodedText, StandardCharsets.UTF_8);

        String[] parts = encodedString.split("=");

        String base64EncodedMessageBodyText = parts[0];

        return base64EncodedMessageBodyText.getBytes(StandardCharsets.UTF_8);
    }
}
