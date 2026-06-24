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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.parosproxy.paros.Constant;

public final class EncoderUtils {

    private EncoderUtils() {}

    public static String removeFirstAndLastCurlyBraces(String text)
            throws InvalidProtobufFormatException {
        // Check if the string starts with '{' and ends with '}' for nested message
        if (text != null
                && text.length() >= 2
                && text.charAt(0) == '{'
                && text.charAt(text.length() - 1) == '}') {
            // Remove the first and last characters using substring
            int first = text.indexOf('\n');
            int last = text.lastIndexOf('\n');
            if (first == -1 || last == -1)
                throw new InvalidProtobufFormatException(
                        Constant.messages.getString("grpc.encoder.nested.message.newline.error"));
            return text.substring(first + 1, last);
        }
        throw new InvalidProtobufFormatException(
                Constant.messages.getString("grpc.encoder.nested.message.braces.error"));
    }

    public static List<String> parseIntoList(String inputString)
            throws InvalidProtobufFormatException {
        if (inputString == null || inputString.isEmpty()) {
            return Collections.emptyList();
        }
        List<String> output = new ArrayList<>();
        String[] temp = inputString.split("\n");

        StringBuilder field = new StringBuilder();
        int countOpenCurlyBraces = 0;

        for (String s : temp) {
            if (s.charAt(s.length() - 1) != '{'
                    && s.charAt(0) != '}'
                    && countOpenCurlyBraces == 0) {
                output.add(s);
            } else if (s.charAt(s.length() - 1) == '{') {
                countOpenCurlyBraces++;
                field.append(s).append('\n');
            } else if (s.charAt(0) == '}') {
                countOpenCurlyBraces--;
                if (countOpenCurlyBraces == 0) {
                    field.append(s);
                    output.add(field.toString());
                    field.setLength(0);
                } else {
                    field.append(s).append('\n');
                }
            } else {
                field.append(s).append('\n');
            }
        }

        if (countOpenCurlyBraces != 0) {
            throw new InvalidProtobufFormatException(
                    Constant.messages.getString(
                            "grpc.encoder.nested.message.missing.braces.error"));
        }
        return output;
    }

    public static byte[] hexStringToByteArray(String hexString) {
        // Ensure even length
        if (hexString.length() % 2 != 0) {
            throw new IllegalArgumentException(
                    Constant.messages.getString("grpc.encoder.message.invalid.hex.string.error"));
        }

        // Create byte array with correct size
        byte[] result = new byte[hexString.length() / 2];

        // Parse hex pairs and fill the byte array
        for (int i = 0; i < result.length; i++) {
            String hexByte = hexString.substring(i * 2, i * 2 + 2);
            int byteValue = Integer.parseInt(hexByte, 16); // Parse as base-16 (hex)
            result[i] = (byte) byteValue;
        }

        return result;
    }

    public static String removeDoubleQuotes(String str) throws InvalidProtobufFormatException {
        if (str.startsWith("\"") && str.endsWith("\"")) {
            return str.substring(1, str.length() - 1);
        }
        throw new InvalidProtobufFormatException(
                Constant.messages.getString("grpc.encoder.message.missing.quotes.error"));
    }

    static String[] validateAndSplitInput(String input) throws InvalidProtobufFormatException {
        String[] inputArray = input.split("::", 2);
        if (inputArray.length == 0) {
            throw new InvalidProtobufFormatException(
                    Constant.messages.getString("grpc.encoder.message.missing.field.wire.error"));
        }
        String[] fieldNumWireType = inputArray[0].split(":", 2);
        if (fieldNumWireType.length != 2) {
            throw new InvalidProtobufFormatException(
                    Constant.messages.getString("grpc.encoder.message.missing.field.wire.error"));
        }
        return fieldNumWireType;
    }

    static int getWiretype(String tag) throws InvalidProtobufFormatException {
        try {
            if (tag.length() > 1) {
                return Integer.parseInt(String.valueOf(tag.charAt(0)));
            }
            return Integer.parseInt(tag);
        } catch (NumberFormatException e) {
            throw new InvalidProtobufFormatException(
                    Constant.messages.getString("grpc.encoder.message.missing.field.wire.error"));
        }
    }

    static char getTypeSpecifier(String tag) {
        if (tag.length() > 1) {
            return tag.charAt(1);
        }
        // default value, give no information
        return 'n';
    }

    static int getFieldNumber(String fieldNumber) throws InvalidProtobufFormatException {
        try {
            return Integer.parseInt(fieldNumber);
        } catch (NumberFormatException e) {
            throw new InvalidProtobufFormatException(
                    Constant.messages.getString("grpc.encoder.message.missing.field.wire.error"));
        }
    }
}
