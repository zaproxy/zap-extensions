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
package org.zaproxy.addon.grpc.internal;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.UnknownFieldSet;
import com.google.protobuf.WireFormat;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.parosproxy.paros.Constant;

public final class ZapProtoTextCodec {

    private ZapProtoTextCodec() {}

    public static String format(UnknownFieldSet fields) {
        StringBuilder output = new StringBuilder();
        for (String line : formatToList(fields)) {
            output.append(line).append('\n');
        }
        return output.toString();
    }

    public static List<String> formatToList(UnknownFieldSet fields) {
        List<String> lines = new ArrayList<>();
        for (Map.Entry<Integer, UnknownFieldSet.Field> entry : fields.asMap().entrySet()) {
            int fieldNumber = entry.getKey();
            UnknownFieldSet.Field field = entry.getValue();
            for (Long value : field.getVarintList()) {
                lines.add(fieldNumber + ":" + WireFormat.WIRETYPE_VARINT + "::" + value);
            }
            for (Long value : field.getFixed64List()) {
                lines.add(formatFixed64(fieldNumber, value));
            }
            for (Integer value : field.getFixed32List()) {
                lines.add(formatFixed32(fieldNumber, value));
            }
            for (ByteString value : field.getLengthDelimitedList()) {
                lines.add(formatLengthDelimited(fieldNumber, value.toByteArray()));
            }
        }
        return lines;
    }

    public static UnknownFieldSet parse(String text)
            throws InvalidProtobufFormatException, IOException {
        return parse(EncoderUtils.parseIntoList(text));
    }

    public static UnknownFieldSet parse(List<String> lines)
            throws InvalidProtobufFormatException, IOException {
        UnknownFieldSet.Builder builder = UnknownFieldSet.newBuilder();
        Map<Integer, UnknownFieldSet.Field.Builder> fieldBuilders = new LinkedHashMap<>();
        for (String line : lines) {
            addLine(fieldBuilders, line);
        }
        for (Map.Entry<Integer, UnknownFieldSet.Field.Builder> entry : fieldBuilders.entrySet()) {
            builder.addField(entry.getKey(), entry.getValue().build());
        }
        return builder.build();
    }

    private static void addLine(
            Map<Integer, UnknownFieldSet.Field.Builder> fieldBuilders, String line)
            throws InvalidProtobufFormatException, IOException {
        String[] inputArray = line.split("::", 2);
        String[] fieldNumWireType = EncoderUtils.validateAndSplitInput(line);

        String tag = fieldNumWireType[1];
        int wireType = EncoderUtils.getWiretype(tag);
        char typeSpecifier = EncoderUtils.getTypeSpecifier(tag);
        int fieldNumber = EncoderUtils.getFieldNumber(fieldNumWireType[0]);

        UnknownFieldSet.Field.Builder fieldBuilder =
                fieldBuilders.computeIfAbsent(
                        fieldNumber, ignored -> UnknownFieldSet.Field.newBuilder());

        switch (wireType) {
            case WireFormat.WIRETYPE_VARINT:
                fieldBuilder.addVarint(Long.parseLong(inputArray[1]));
                break;
            case WireFormat.WIRETYPE_FIXED64:
                if (typeSpecifier == 'D') {
                    fieldBuilder.addFixed64(
                            Double.doubleToRawLongBits(Double.parseDouble(inputArray[1])));
                } else {
                    fieldBuilder.addFixed64(Long.parseLong(inputArray[1]));
                }
                break;
            case WireFormat.WIRETYPE_LENGTH_DELIMITED:
                fieldBuilder.addLengthDelimited(
                        ByteString.copyFrom(encodeLengthDelimited(inputArray[1], typeSpecifier)));
                break;
            case WireFormat.WIRETYPE_FIXED32:
                if (typeSpecifier == 'F') {
                    fieldBuilder.addFixed32(
                            Float.floatToRawIntBits(Float.parseFloat(inputArray[1])));
                } else {
                    fieldBuilder.addFixed32(Integer.parseInt(inputArray[1]));
                }
                break;
            default:
                throw new InvalidProtobufFormatException(
                        Constant.messages.getString("grpc.encoder.message.invalid.wiretype.error"));
        }
    }

    private static byte[] encodeLengthDelimited(String value, char typeSpecifier)
            throws InvalidProtobufFormatException, IOException {
        if (typeSpecifier == 'B') {
            return EncoderUtils.hexStringToByteArray(value);
        }
        if (typeSpecifier == 'N') {
            byte[] nestedBytes = encodeNestedMessage(value);
            if (nestedBytes.length == 0) {
                return value.getBytes(StandardCharsets.UTF_8);
            }
            return nestedBytes;
        }
        return EncoderUtils.removeDoubleQuotes(value).getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] encodeNestedMessage(String nestedMessage)
            throws InvalidProtobufFormatException, IOException {
        try {
            String inner = EncoderUtils.removeFirstAndLastCurlyBraces(nestedMessage);
            if (inner.isEmpty()) {
                return UnknownFieldSet.newBuilder().build().toByteArray();
            }
            return parse(EncoderUtils.parseIntoList(inner)).toByteArray();
        } catch (Exception e) {
            return new byte[0];
        }
    }

    private static String formatFixed64(int fieldNumber, long value) {
        StringBuilder decodedValueBuilder = new StringBuilder();
        decodedValueBuilder.append(fieldNumber).append(':').append(WireFormat.WIRETYPE_FIXED64);
        if (DecoderUtils.isDouble(value)) {
            decodedValueBuilder.append('D').append("::").append(Double.longBitsToDouble(value));
        } else {
            decodedValueBuilder.append("::").append(value);
        }
        return decodedValueBuilder.toString();
    }

    private static String formatFixed32(int fieldNumber, int value) {
        StringBuilder decodedValueBuilder = new StringBuilder();
        decodedValueBuilder.append(fieldNumber).append(':').append(WireFormat.WIRETYPE_FIXED32);
        if (DecoderUtils.isFloat(value)) {
            decodedValueBuilder.append('F').append("::").append(Float.intBitsToFloat(value));
        } else {
            decodedValueBuilder.append("::").append(value);
        }
        return decodedValueBuilder.toString();
    }

    private static String formatLengthDelimited(int fieldNumber, byte[] bytes) {
        StringBuilder decodedValueBuilder = new StringBuilder();
        decodedValueBuilder
                .append(fieldNumber)
                .append(':')
                .append(WireFormat.WIRETYPE_LENGTH_DELIMITED);

        String nestedMessage = tryFormatNestedMessage(bytes);
        if (nestedMessage.isEmpty()) {
            String decoded = new String(bytes, StandardCharsets.UTF_8);
            int unprintable = 0;
            for (byte stringByte : bytes) {
                if (!DecoderUtils.isGraphic(stringByte)) {
                    unprintable++;
                }
            }
            if (bytes.length > 0 && (double) unprintable / bytes.length > 0.3) {
                decodedValueBuilder.append("B::").append(DecoderUtils.toHexString(bytes));
            } else {
                decodedValueBuilder.append("::\"").append(decoded).append('"');
            }
        } else {
            decodedValueBuilder.append("N::").append(nestedMessage);
        }
        return decodedValueBuilder.toString();
    }

    private static String tryFormatNestedMessage(byte[] bytes) {
        try {
            UnknownFieldSet nested = UnknownFieldSet.parseFrom(bytes);
            if (nested.asMap().containsKey(0)) {
                return "";
            }
            if (!Arrays.equals(bytes, nested.toByteArray())) {
                return "";
            }
            String nestedBody = format(nested).stripTrailing();
            if (nestedBody.isEmpty()) {
                return "{\n}";
            }
            return "{\n" + nestedBody + "\n}";
        } catch (InvalidProtocolBufferException e) {
            return "";
        }
    }
}
