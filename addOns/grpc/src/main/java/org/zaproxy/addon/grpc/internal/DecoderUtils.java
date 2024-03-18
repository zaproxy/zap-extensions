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
import java.util.Arrays;

public class DecoderUtils {

    static boolean isGraphic(byte ch) {
        // Check if the character is printable
        // Printable characters have unicode values greater than 32 (excluding control
        // characters) and aren't whitespace
        return (ch > 32 && ch != 127 && ch <= 255 && !Character.isWhitespace(ch));
    }

    public static String toHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }

    public static boolean isFloat(int value) {
        int bitLen = 32;
        int expLen = 8;
        int mantLen = bitLen - expLen - 1;
        int exp = (value >> mantLen) & ((1 << expLen) - 1);
        exp -= (1 << (expLen - 1)) - 1;
        if (exp < 0) {
            exp = -exp;
        }
        int bigExp = (1 << (expLen - 1)) - 1;
        return exp < bigExp;
    }

    public static boolean isDouble(long value) {
        int bitLen = 64;
        int expLen = 11;
        int mantLen = bitLen - expLen - 1;
        long exp = (value >> mantLen) & ((1 << expLen) - 1);
        exp -= (1 << (expLen - 1)) - 1;
        if (exp < 0) {
            exp = -exp;
        }
        int bigExp = (1 << (expLen - 1)) - 1;
        return exp < bigExp;
    }

    public static byte[] extractPayload(byte[] input) {
        if (input.length <= 5) {
            return new byte[0];
        }
        return Arrays.copyOfRange(input, 5, input.length);
    }

    public static String decodeField(int tag, CodedInputStream inputStream) throws IOException {
        String decodedValue = (tag >> 3) + ":";
        int wireType = (tag & 0x7);
        switch (wireType) {
            case 0: // Varint
                long varintValue = inputStream.readRawVarint64();
                decodedValue += wireType + "::" + varintValue;
                break;

            case 1: // 64-bit
                long longValue = inputStream.readRawLittleEndian64();
                decodedValue += Integer.toString(wireType);
                if (DecoderUtils.isDouble(longValue)) {
                    decodedValue += "D::" + Double.longBitsToDouble(longValue);
                } else {
                    decodedValue += "::" + longValue;
                }
                break;

            case 5: // 32-bit
                decodedValue += Integer.toString(wireType);
                int intValue = inputStream.readRawLittleEndian32();
                if (DecoderUtils.isFloat(intValue)) {
                    decodedValue += "F::" + Float.intBitsToFloat(intValue);
                } else {
                    decodedValue += "::" + intValue;
                }
                break;

            case 2: // Length-Prefixed string
                decodedValue += Integer.toString(wireType);
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
                        decodedValue += "B::" + DecoderUtils.toHexString(stringBytes);
                    } else {
                        decodedValue += "::" + decoded;
                    }
                } else decodedValue += "N::" + validMessage;

                break;

            default:
                return "";
        }
        return decodedValue;
    }

    public static String checkNestedMessage(byte[] stringBytes) {
        ProtoBufNestedMessageDecoder protobufNestedMessageDecoder =
                new ProtoBufNestedMessageDecoder();
        return protobufNestedMessageDecoder.startDecoding(stringBytes);
    }
}
