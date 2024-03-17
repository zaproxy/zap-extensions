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
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ProtoBufMessageDecoder {

    private static final Logger LOGGER = LogManager.getLogger(ProtoBufMessageDecoder.class);

    private byte[] inputData;
    private List<String> decodedToList;
    private StringBuilder decodedToString;
    private CodedInputStream inputStream;

    public ProtoBufMessageDecoder() {
        this.decodedToList = new ArrayList<>();
        this.decodedToString = new StringBuilder();
    }

    public void startDecoding(byte[] inputEncodedData) {
        decodedToList.clear();
        decodedToString.setLength(0);
        if (inputEncodedData.length == 0) {
            return;
        }
        this.inputData = inputEncodedData;
        this.inputStream = CodedInputStream.newInstance(inputData);
        boolean check = true;
        while (check) {
            decodeField();
            try {
                if (inputStream.isAtEnd()) {
                    check = false;
                }
            } catch (IOException e) {
                LOGGER.debug("Error while decoding the message", e.getMessage());
            }
        }
    }

    private void decodeField() {
        int tag;
        try {
            tag = inputStream.readTag();
        } catch (IOException e) {
            LOGGER.debug("Error while reading the Tag", e.getMessage());
            return;
        }

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
                    return;
            }
        } catch (IOException e) {
            LOGGER.debug("Error while decoding the field", e.getMessage());
            return;
        }

        decodedToList.add(decodedValue);
        decodedToString.append(decodedValue).append("\n");
    }

    private String checkNestedMessage(byte[] stringBytes) {
        ProtoBufNestedMessageDecoder protobufNestedMessageDecoder =
                new ProtoBufNestedMessageDecoder();
        return protobufNestedMessageDecoder.startDecoding(stringBytes);
    }

    public String getDecodedOuput() {
        return decodedToString.toString();
    }

    public List<String> getDecodedToList() {
        return decodedToList;
    }
}
