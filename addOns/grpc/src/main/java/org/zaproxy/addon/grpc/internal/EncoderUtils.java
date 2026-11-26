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

import com.google.protobuf.CodedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.parosproxy.paros.Constant;

public final class EncoderUtils {

    public static final int VARINT_WIRE_TYPE = 0;
    public static final int BIT64_WIRE_TYPE = 1;
    public static final int LENGTH_DELIMITED_WIRE_TYPE = 2;
    public static final int BIT32_WIRE_TYPE = 5;

    private EncoderUtils() {}

    public static String removeFirstAndLastCurlyBraces(String text)
            throws InvalidProtobufFormatException {
        // Check if the string starts with '{' and ends with '}' for nested message
        if (text != null
                && text.length() >= 2
                && text.charAt(0) == '{'
                && text.charAt(text.length() - 1) == '}') {
            String inner = text.substring(1, text.length() - 1);
            // Empty nested messages are valid protobuf values. The editor representation can be
            // either "{}" or "{\n}".
            if (inner.isEmpty() || "\n".equals(inner)) {
                return "";
            }
            if (inner.charAt(0) != '\n' || inner.charAt(inner.length() - 1) != '\n') {
                throw new InvalidProtobufFormatException(
                        Constant.messages.getString("grpc.encoder.nested.message.newline.error"));
            }
            return inner.substring(1, inner.length() - 1);
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

    static String escapeString(String value) {
        StringBuilder escaped = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            switch (ch) {
                case '\\':
                    escaped.append("\\\\");
                    break;
                case '"':
                    escaped.append("\\\"");
                    break;
                case '\b':
                    escaped.append("\\b");
                    break;
                case '\f':
                    escaped.append("\\f");
                    break;
                case '\n':
                    escaped.append("\\n");
                    break;
                case '\r':
                    escaped.append("\\r");
                    break;
                case '\t':
                    escaped.append("\\t");
                    break;
                default:
                    escaped.append(ch);
                    break;
            }
        }
        return escaped.toString();
    }

    static String unescapeString(String value) {
        StringBuilder unescaped = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (ch != '\\' || i + 1 >= value.length()) {
                unescaped.append(ch);
                continue;
            }

            char next = value.charAt(++i);
            switch (next) {
                case '\\':
                    unescaped.append('\\');
                    break;
                case '"':
                    unescaped.append('"');
                    break;
                case 'b':
                    unescaped.append('\b');
                    break;
                case 'f':
                    unescaped.append('\f');
                    break;
                case 'n':
                    unescaped.append('\n');
                    break;
                case 'r':
                    unescaped.append('\r');
                    break;
                case 't':
                    unescaped.append('\t');
                    break;
                default:
                    unescaped.append('\\').append(next);
                    break;
            }
        }
        return unescaped.toString();
    }

    public static String removeDoubleQuotes(String str) throws InvalidProtobufFormatException {
        if (str.startsWith("\"") && str.endsWith("\"")) {
            return unescapeString(str.substring(1, str.length() - 1));
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

    static void writeFields(List<String> inputString, CodedOutputStream codedOutputStream)
            throws IOException, InvalidProtobufFormatException {
        for (String input : inputString) {
            String[] inputArray = input.split("::", 2);

            String[] fieldNumWireType = validateAndSplitInput(input);

            String tag = fieldNumWireType[1];
            int wireType = getWiretype(tag);
            char typeSpecifier = getTypeSpecifier(tag);

            int fieldNumber = getFieldNumber(fieldNumWireType[0]);

            switch (wireType) {
                case VARINT_WIRE_TYPE:
                    long value = Long.parseLong(inputArray[1]);
                    codedOutputStream.writeInt64(fieldNumber, value);
                    break;
                case BIT64_WIRE_TYPE:
                    if (typeSpecifier == 'D') {
                        codedOutputStream.writeDouble(
                                fieldNumber, Double.parseDouble(inputArray[1]));
                    } else {
                        codedOutputStream.writeFixed64(fieldNumber, Long.parseLong(inputArray[1]));
                    }
                    break;
                case LENGTH_DELIMITED_WIRE_TYPE:
                    String val = inputArray[1];

                    if (typeSpecifier == 'B') {
                        byte[] byteArray = hexStringToByteArray(inputArray[1]);
                        codedOutputStream.writeByteArray(fieldNumber, byteArray);
                    } else if (typeSpecifier == 'N') {
                        // Nested messages are explicitly marked as such by the decoder/editor.
                        // A zero-length byte array is a valid empty embedded message, not failure.
                        byte[] byteArray = getNestedMessageEncodedValue(val);
                        codedOutputStream.writeByteArray(fieldNumber, byteArray);
                    } else {
                        // human readable string
                        // remove double quotes
                        val = EncoderUtils.removeDoubleQuotes(val);
                        codedOutputStream.writeString(fieldNumber, val);
                    }

                    break;
                case BIT32_WIRE_TYPE:
                    if (typeSpecifier == 'F') {
                        codedOutputStream.writeFloat(fieldNumber, Float.parseFloat(inputArray[1]));
                    } else {
                        codedOutputStream.writeFixed32(
                                fieldNumber, Integer.parseInt(inputArray[1]));
                    }

                    break;
                default:
                    throw new InvalidProtobufFormatException(
                            Constant.messages.getString(
                                    "grpc.encoder.message.invalid.wiretype.error"));
            }
        }
    }

    static byte[] getNestedMessageEncodedValue(String nestedMessage)
            throws IOException, InvalidProtobufFormatException {
        return encodeNestedMessage(nestedMessage).toByteArray();
    }

    public static ByteArrayOutputStream encodeNestedMessage(String nestedMessage)
            throws IOException, InvalidProtobufFormatException {

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        CodedOutputStream codedOutputStream = CodedOutputStream.newInstance(outputStream);
        nestedMessage = EncoderUtils.removeFirstAndLastCurlyBraces(nestedMessage);
        if (nestedMessage.isEmpty()) {
            return outputStream;
        }

        List<String> nestedMessageFields = EncoderUtils.parseIntoList(nestedMessage);

        EncoderUtils.writeFields(nestedMessageFields, codedOutputStream);
        codedOutputStream.flush();

        return outputStream;
    }

    static int getSerializedSize(List<String> inputString) throws InvalidProtobufFormatException {
        int size = 0;

        for (String input : inputString) {
            String[] inputArray = input.split("::", 2);

            String[] fieldNumWireType = validateAndSplitInput(input);

            String tag = fieldNumWireType[1];
            int wireType = getWiretype(tag);
            char typeSpecifier = getTypeSpecifier(tag);

            int fieldNumber = getFieldNumber(fieldNumWireType[0]);
            switch (wireType) {
                case VARINT_WIRE_TYPE:
                    size +=
                            CodedOutputStream.computeInt64Size(
                                    fieldNumber, Long.parseLong(inputArray[1]));
                    break;
                case BIT64_WIRE_TYPE:
                    if (typeSpecifier == 'D') {
                        size +=
                                CodedOutputStream.computeDoubleSize(
                                        fieldNumber, Double.parseDouble(inputArray[1]));
                    } else {
                        size +=
                                CodedOutputStream.computeFixed64Size(
                                        fieldNumber, Long.parseLong(inputArray[1]));
                    }
                    break;
                case LENGTH_DELIMITED_WIRE_TYPE:
                    String val = inputArray[1];
                    if (typeSpecifier == 'B') {
                        byte[] byteArray = hexStringToByteArray(inputArray[1]);
                        size += CodedOutputStream.computeByteArraySize(fieldNumber, byteArray);
                    } else if (typeSpecifier == 'N') {
                        size += computeNestedMessageSize(fieldNumber, val);
                    } else {
                        // human readable string
                        val = EncoderUtils.removeDoubleQuotes(inputArray[1]);
                        size += CodedOutputStream.computeStringSize(fieldNumber, val);
                    }
                    break;
                case BIT32_WIRE_TYPE:
                    if (typeSpecifier == 'F') {
                        size +=
                                CodedOutputStream.computeFloatSize(
                                        fieldNumber, Float.parseFloat(inputArray[1]));
                    } else {
                        size +=
                                CodedOutputStream.computeFixed32Size(
                                        fieldNumber, Integer.parseInt(inputArray[1]));
                    }
                    break;
                default:
                    throw new InvalidProtobufFormatException(
                            Constant.messages.getString(
                                    "grpc.encoder.message.invalid.wiretype.error"));
            }
        }
        return size;
    }

    static int computeNestedMessageSize(int fieldNumber, String nestedMessage)
            throws InvalidProtobufFormatException {
        int nestedMessageSize = computeSize(nestedMessage);
        return CodedOutputStream.computeTagSize(fieldNumber)
                + CodedOutputStream.computeUInt32SizeNoTag(nestedMessageSize)
                + nestedMessageSize;
    }

    static int computeSize(String nestedMessage) throws InvalidProtobufFormatException {
        nestedMessage = EncoderUtils.removeFirstAndLastCurlyBraces(nestedMessage);
        List<String> nestedMessageFields = EncoderUtils.parseIntoList(nestedMessage);
        return EncoderUtils.getSerializedSize(nestedMessageFields);
    }
}
