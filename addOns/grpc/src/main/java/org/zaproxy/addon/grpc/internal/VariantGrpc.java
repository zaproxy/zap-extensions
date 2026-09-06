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

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.core.scanner.NameValuePair;
import org.parosproxy.paros.core.scanner.Variant;
import org.parosproxy.paros.network.HttpBody;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;

public class VariantGrpc implements Variant {
    private static final Logger LOGGER = LogManager.getLogger(VariantGrpc.class);
    private final List<NameValuePair> params = new ArrayList<>();
    private final ProtoBufMessageEncoder protoBufMessageEncoder = new ProtoBufMessageEncoder();
    private final ProtoBufMessageDecoder protoBufMessageDecoder = new ProtoBufMessageDecoder();

    // TODO - This must be define in NameValuePair class
    public static final int TYPE_GRPC_WEB_TEXT = 39;
    private String requestDecodedBody = null;

    @Override
    public void setMessage(HttpMessage msg) {
        params.clear();
        requestDecodedBody = null;
        if (isValidGrpcMessage(msg.getRequestHeader(), msg.getRequestBody())) {
            try {
                byte[] body = msg.getRequestBody().getBytes();
                if (isBase64EncodedGrpc(msg.getRequestHeader())) {
                    body = Base64.getDecoder().decode(body);
                }
                byte[] payload = DecoderUtils.extractPayload(body);
                protoBufMessageDecoder.decode(payload);
                parseContent(protoBufMessageDecoder.getDecodedToList(), "");
                requestDecodedBody = protoBufMessageDecoder.getDecodedOutput();
            } catch (InvalidProtobufFormatException | IllegalArgumentException e) {
                LOGGER.error("Parsing message body failed: {}", e.getMessage());
            }
        }
    }

    private void parseContent(List<String> decodedList, String commonPrefixForNestedMessage)
            throws InvalidProtobufFormatException {
        for (String pair : decodedList) {
            String[] nameValuePair = pair.split("::", 2);
            if (nameValuePair.length != 2) {
                continue;
            }

            String fullName =
                    commonPrefixForNestedMessage.isEmpty()
                            ? nameValuePair[0]
                            : commonPrefixForNestedMessage + '.' + nameValuePair[0];
            String[] fieldNumAndWireType = nameValuePair[0].split(":", 2);
            if (fieldNumAndWireType.length != 2) {
                continue;
            }

            String fieldType = fieldNumAndWireType[1];
            if (isNestedMessageField(fieldType)) {
                String nestedMessage =
                        EncoderUtils.removeFirstAndLastCurlyBraces(nameValuePair[1]);
                List<String> nestedMessagePairList = EncoderUtils.parseIntoList(nestedMessage);
                parseContent(nestedMessagePairList, fullName);
            } else if (isInjectableField(fieldType)) {
                params.add(
                        new NameValuePair(
                                TYPE_GRPC_WEB_TEXT,
                                fullName,
                                nameValuePair[1],
                                params.size()));
            }
        }
    }

    private static boolean isNestedMessageField(String fieldType) {
        return "2N".equals(fieldType);
    }

    private static boolean isInjectableField(String fieldType) {
        // Generic ZAP active-scan payloads are strings. Numeric/fixed/enum protobuf fields cannot
        // contain those payloads, and nested-message containers are not scalar attack parameters.
        return "2".equals(fieldType);
    }

    private static boolean isValidGrpcMessage(HttpHeader header, HttpBody body) {
        return header.hasContentType("application/grpc") && body.getBytes().length > 0;
    }

    private static boolean isBase64EncodedGrpc(HttpHeader header) {
        return header.hasContentType("application/grpc-web-text");
    }

    @Override
    public String getLeafName(String nodeName, HttpMessage msg) {
        if (!isValidGrpcMessage(msg.getRequestHeader(), msg.getRequestBody())) {
            return null;
        }
        return msg.getRequestHeader().getMethod() + ":" + nodeName;
    }

    @Override
    public List<NameValuePair> getParamList() {
        return params;
    }

    @Override
    public String setParameter(
            HttpMessage msg, NameValuePair originalPair, String param, String value) {
        try {
            List<String> decodedList = EncoderUtils.parseIntoList(requestDecodedBody);
            String newContent = buildNewBodyContent(decodedList, originalPair, value);
            setEncodedReqBodyMessage(msg, newContent);
            return newContent;
        } catch (InvalidProtobufFormatException | IOException | IllegalArgumentException e) {
            LOGGER.warn("Failed to set parameter in gRPC message: {}", e.getMessage());
            return null;
        }
    }

    private String buildNewBodyContent(
            List<String> decodedList, NameValuePair originalPair, String value)
            throws InvalidProtobufFormatException {
        int[] currentPosition = {0};
        boolean[] replaced = {false};
        String result =
                findParamAndPutPayload(
                        decodedList,
                        originalPair.getPosition(),
                        value,
                        currentPosition,
                        replaced);
        if (!replaced[0]) {
            throw new IllegalArgumentException(
                    "Unable to locate gRPC parameter at position " + originalPair.getPosition());
        }
        return result;
    }

    private void setEncodedReqBodyMessage(HttpMessage msg, String newContent)
            throws InvalidProtobufFormatException, IOException {
        protoBufMessageEncoder.encode(EncoderUtils.parseIntoList(newContent));
        byte[] encodedMessage = protoBufMessageEncoder.getOutputEncodedMessage();
        if (isBase64EncodedGrpc(msg.getRequestHeader())) {
            encodedMessage = Base64.getEncoder().encode(encodedMessage);
        }
        msg.getRequestBody().setBody(encodedMessage);
    }

    private String findParamAndPutPayload(
            List<String> decodedList,
            int targetPosition,
            String value,
            int[] currentPosition,
            boolean[] replaced)
            throws InvalidProtobufFormatException {
        StringBuilder newContent = new StringBuilder();
        for (String val : decodedList) {
            String[] nameValuePair = val.split("::", 2);
            if (nameValuePair.length != 2) {
                newContent.append(val).append('\n');
                continue;
            }

            String[] fieldNumAndWireType = nameValuePair[0].split(":", 2);
            String fieldType = fieldNumAndWireType.length == 2 ? fieldNumAndWireType[1] : "";

            if (isNestedMessageField(fieldType)) {
                List<String> nestedMessageList =
                        EncoderUtils.parseIntoList(
                                EncoderUtils.removeFirstAndLastCurlyBraces(nameValuePair[1]));
                newContent
                        .append(nameValuePair[0])
                        .append("::{\n")
                        .append(
                                findParamAndPutPayload(
                                        nestedMessageList,
                                        targetPosition,
                                        value,
                                        currentPosition,
                                        replaced))
                        .append('}');
            } else if (isInjectableField(fieldType)) {
                boolean isTarget = !replaced[0] && currentPosition[0] == targetPosition;
                currentPosition[0]++;
                if (isTarget) {
                    replaced[0] = true;
                    // ZAP uses null/null to request removal of the parameter.
                    if (value == null) {
                        continue;
                    }
                    newContent
                            .append(nameValuePair[0])
                            .append("::\"")
                            .append(EncoderUtils.escapeString(value))
                            .append('"');
                } else {
                    newContent.append(val);
                }
            } else {
                newContent.append(val);
            }
            newContent.append('\n');
        }
        return newContent.toString();
    }

    /** Calls {@link #setParameter(HttpMessage, NameValuePair, String, String)}. */
    @Override
    public String setEscapedParameter(
            HttpMessage msg, NameValuePair originalPair, String param, String value) {
        return setParameter(msg, originalPair, param, value);
    }

    @Override
    public void decodeResponseBody(HttpMessage msg) {
        if (!isValidGrpcMessage(msg.getResponseHeader(), msg.getResponseBody())) {
            return;
        }

        try {
            byte[] body = msg.getResponseBody().getBytes();
            if (isBase64EncodedGrpc(msg.getResponseHeader())) {
                body = DecoderUtils.splitMessageBodyAndStatusCode(body);
                body = Base64.getDecoder().decode(body);
            }
            byte[] payload = DecoderUtils.extractPayload(body);
            protoBufMessageDecoder.decode(payload);
            msg.getResponseBody().setBody(protoBufMessageDecoder.getDecodedOutput());
        } catch (UnsupportedEncodingException | IllegalArgumentException e) {
            LOGGER.warn("Error decoding the Response Body: {}", e.getMessage());
        }
    }
}
