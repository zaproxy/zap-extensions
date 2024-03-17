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

public class ProtoBufNestedMessageDecoder {
    private CodedInputStream inputStream;

    public String startDecoding(byte[] inputData) {
        this.inputStream = CodedInputStream.newInstance(inputData);
        boolean check = true;
        String output = "{";
        while (check) {
            String validField = decodeField();
            if (validField.isEmpty()) return validField;
            else output += "\"" + validField + "\"";
            try {
                if (inputStream.isAtEnd()) {
                    check = false;
                }
            } catch (IOException e) {
                return "";
            }
        }
        output += "}";
        return output;
    }

    private String decodeField() {
        int tag;
        try {
            tag = inputStream.readTag();
        } catch (IOException e) {
            return "";
        }

        // field number 0 is reserved for error
        if (tag >> 3 == 0) {
            return "";
        }

        // extract field number
        String decodedValue = (tag >> 3) + ":";
        int wireType = (tag & 0x7);
        try {
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
                    // child nested message
                    String validMessage = checkNestedMessage(stringBytes);
                    if (validMessage.length() == 0) {
                        // not a nested message check for printable characters
                        int unprintable = 0;
                        int runes = stringBytes.length;
                        for (byte stringByte : stringBytes) {
                            if (!DecoderUtils.isGraphic(stringByte)) {
                                unprintable++;
                            }
                        }
                        // decode it as hex values if more than 30% of the characters are
                        // unprintable
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
        } catch (IOException e) {
            return "";
        }
        return decodedValue;
    }

    private String checkNestedMessage(byte[] stringBytes) {
        ProtoBufNestedMessageDecoder protobufNestedMessageDecoder =
                new ProtoBufNestedMessageDecoder();
        return protobufNestedMessageDecoder.startDecoding(stringBytes);
    }
}
