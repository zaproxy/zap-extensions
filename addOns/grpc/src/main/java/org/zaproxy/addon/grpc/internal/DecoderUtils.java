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

import com.google.protobuf.CodedInputStream;
import java.io.IOException;
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

    public static final int VARINT_WIRE_TYPE = 0;
    public static final int BIT64_WIRE_TYPE = 1;
    public static final int LENGTH_DELIMITED_WIRE_TYPE = 2;
    public static final int BIT32_WIRE_TYPE = 5;

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

    public static String decodeField(int tag, CodedInputStream inputStream) throws IOException {
        StringBuilder decodedValueBuilder = new StringBuilder();
        decodedValueBuilder.append(tag >> 3).append(":");
        int wireType = (tag & 0x7);
        switch (wireType) {
            case VARINT_WIRE_TYPE:
                long varintValue = inputStream.readRawVarint64();
                decodedValueBuilder.append(wireType).append("::").append(varintValue);
                break;

            case BIT64_WIRE_TYPE:
                long longValue = inputStream.readRawLittleEndian64();
                decodedValueBuilder.append(wireType);
                if (DecoderUtils.isDouble(longValue)) {
                    decodedValueBuilder.append("D::").append(Double.longBitsToDouble(longValue));
                } else {
                    decodedValueBuilder.append("::").append(longValue);
                }
                break;

            case BIT32_WIRE_TYPE:
                decodedValueBuilder.append(wireType);
                int intValue = inputStream.readRawLittleEndian32();
                if (DecoderUtils.isFloat(intValue)) {
                    decodedValueBuilder.append("F::").append(Float.intBitsToFloat(intValue));
                } else {
                    decodedValueBuilder.append("::").append(intValue);
                }
                break;

            case LENGTH_DELIMITED_WIRE_TYPE:
                decodedValueBuilder.append(wireType);
                String decoded = inputStream.readStringRequireUtf8();
                byte[] stringBytes = decoded.getBytes();
                // assume wire type 2 as Nested Message
                // child nested message , recursively check each nestedMessage field
                // if not able to successfully decode as NestedMessage field, then consider it
                // as string
                // still need to check for packed repeated fields
                String validMessage = checkNestedMessage(stringBytes);
                if (validMessage.isEmpty()) {
                    // not a nested message check for printable characters
                    int unprintable = 0;
                    int runes = stringBytes.length;
                    for (byte stringByte : stringBytes) {
                        if (!DecoderUtils.isGraphic(stringByte)) {
                            unprintable++;
                        }
                    }

                    // assume not a human readable string
                    // decode it as hex values
                    if ((double) unprintable / runes > 0.3) {
                        decodedValueBuilder
                                .append("B::")
                                .append(DecoderUtils.toHexString(stringBytes));
                    } else {
                        decodedValueBuilder.append("::").append('"').append(decoded).append('"');
                    }
                } else {
                    decodedValueBuilder.append("N::").append(validMessage);
                }

                break;

            default:
                return "";
        }
        return decodedValueBuilder.toString();
    }

    public static String checkNestedMessage(byte[] stringBytes) {
        ProtoBufNestedMessageDecoder protobufNestedMessageDecoder =
                new ProtoBufNestedMessageDecoder();
        return protobufNestedMessageDecoder.decode(stringBytes);
    }

    static byte[] splitMessageBodyAndStatusCode(byte[] encodedText)
            throws UnsupportedEncodingException {
        String encodedString = new String(encodedText, StandardCharsets.UTF_8);

        String[] parts = encodedString.split("=");

        String base64EncodedMessageBodyText = parts[0];

        return base64EncodedMessageBodyText.getBytes(StandardCharsets.UTF_8);
    }
}
