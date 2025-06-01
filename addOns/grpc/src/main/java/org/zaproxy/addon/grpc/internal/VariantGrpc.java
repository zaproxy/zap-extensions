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
        if (isValidGrpcMessage(msg.getRequestHeader(), msg.getRequestBody())) {
            try {
                byte[] body = Base64.getDecoder().decode(msg.getRequestBody().getBytes());
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
            if (commonPrefixForNestedMessage.isEmpty()) {
                params.add(
                        new NameValuePair(
                                TYPE_GRPC_WEB_TEXT,
                                nameValuePair[0],
                                nameValuePair[1],
                                params.size()));

            } else {
                params.add(
                        new NameValuePair(
                                TYPE_GRPC_WEB_TEXT,
                                commonPrefixForNestedMessage + '.' + nameValuePair[0],
                                nameValuePair[1],
                                params.size()));
            }
            String[] fieldNumAndWireType = nameValuePair[0].split(":", 2);
            if (fieldNumAndWireType[1].length() > 1 && fieldNumAndWireType[1].charAt(1) == 'N') {
                String nestedMessage = EncoderUtils.removeFirstAndLastCurlyBraces(nameValuePair[1]);
                List<String> nestedMessagePairList = EncoderUtils.parseIntoList(nestedMessage);
                if (commonPrefixForNestedMessage.isEmpty()) {
                    parseContent(nestedMessagePairList, nameValuePair[0]);
                } else {
                    parseContent(
                            nestedMessagePairList,
                            commonPrefixForNestedMessage + '.' + nameValuePair[0]);
                }
            }
        }
    }

    private static boolean isValidGrpcMessage(HttpHeader header, HttpBody body) {
        return header.hasContentType("application/grpc") && !body.toString().isEmpty();
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
            String newContent = buildNewBodyContent(decodedList, originalPair, param, value);
            setEncodedReqBodyMessage(msg, newContent);
            return newContent;
        } catch (InvalidProtobufFormatException | IOException | NumberFormatException e) {
            LOGGER.warn("Failed to set parameter in gRPC message: {}", e.getMessage());
            return null;
        }
    }

    private String buildNewBodyContent(
            List<String> decodedList, NameValuePair originalPair, String param, String value)
            throws InvalidProtobufFormatException {
        String currentPairName = originalPair.getName();
        String[] nestedMessageParams = currentPairName.split("\\.");
        return findParamAndPutPayload(decodedList, nestedMessageParams, param, value);
    }

    private void setEncodedReqBodyMessage(HttpMessage msg, String newContent)
            throws InvalidProtobufFormatException, IOException {
        protoBufMessageEncoder.encode(EncoderUtils.parseIntoList(newContent));
        byte[] encodedMessage = protoBufMessageEncoder.getOutputEncodedMessage();
        encodedMessage = Base64.getEncoder().encode(encodedMessage);
        msg.getRequestBody().setBody(encodedMessage);
    }

    private String findParamAndPutPayload(
            List<String> decodedList, String[] nestedMessageParam, String param, String value)
            throws InvalidProtobufFormatException {
        StringBuilder newContent = new StringBuilder();
        for (String val : decodedList) {
            String[] nameValuePair = val.split("::", 2);
            if (nestedMessageParam.length > 0
                    && Objects.equals(nestedMessageParam[0], nameValuePair[0])) {
                newContent.append(nameValuePair[0]);
                newContent.append("::");
                nestedMessageParam =
                        Arrays.copyOfRange(nestedMessageParam, 1, nestedMessageParam.length);
                if (nestedMessageParam.length == 0) {
                    if (Objects.equals(nameValuePair[0].split(":", 2)[1], "2")) {
                        newContent.append("\"").append(value).append("\"");
                    } else {
                        newContent.append(value);
                    }
                } else {
                    List<String> nestedMessageList =
                            EncoderUtils.parseIntoList(
                                    EncoderUtils.removeFirstAndLastCurlyBraces(nameValuePair[1]));

                    String s =
                            "{\n"
                                    + findParamAndPutPayload(
                                            nestedMessageList, nestedMessageParam, param, value)
                                    + "}";
                    newContent.append(s);
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
            byte[] body =
                    DecoderUtils.splitMessageBodyAndStatusCode(msg.getResponseBody().getBytes());
            body = Base64.getDecoder().decode(body);
            byte[] payload = DecoderUtils.extractPayload(body);
            protoBufMessageDecoder.decode(payload);
            msg.getResponseBody().setBody(protoBufMessageDecoder.getDecodedOutput());
        } catch (UnsupportedEncodingException | IllegalArgumentException e) {
            LOGGER.warn("Error decoding the Response Body: {}", e.getMessage());
        }
    }
}
