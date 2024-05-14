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
import java.util.Base64;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.core.scanner.NameValuePair;
import org.parosproxy.paros.core.scanner.Variant;
import org.parosproxy.paros.network.HttpMessage;

public class VariantGrpc implements Variant {
    private static final Logger LOGGER = LogManager.getLogger(VariantGrpc.class);
    private final List<NameValuePair> params = new ArrayList<>();
    private final ProtoBufMessageEncoder protoBufMessageEncoder = new ProtoBufMessageEncoder();
    private final ProtoBufMessageDecoder protoBufMessageDecoder = new ProtoBufMessageDecoder();

    @Override
    public void setMessage(HttpMessage msg) {
        String contentType = msg.getRequestHeader().getHeader("content-type");
        if (contentType != null && isValidContentType(contentType)) {
            try {
                byte[] body = Base64.getDecoder().decode(msg.getRequestBody().getBytes());
                byte[] payload = DecoderUtils.extractPayload(body);
                this.protoBufMessageDecoder.decode(payload);
                this.parseContent(protoBufMessageDecoder.getDecodedToList());
            } catch (Exception e) {
                LOGGER.error("Parsing message body failed: {}", e.getMessage());
            }
        }
    }

    public void parseContent(List<String> decodedList) {
        for (String pair : decodedList) {
            String[] nameValuePair = pair.split("::", 2);
            params.add(
                    new NameValuePair(
                            NameValuePair.TYPE_JSON,
                            nameValuePair[0],
                            nameValuePair[1],
                            params.size()));
        }
    }

    public boolean isValidContentType(String contentType) {
        return contentType.startsWith("application/grpc-web-text");
    }

    @Override
    public List<NameValuePair> getParamList() {
        return params;
    }

    @Override
    public String setParameter(
            HttpMessage msg, NameValuePair originalPair, String param, String value) {
        NameValuePair currentPair = params.get(originalPair.getPosition());
        String reqBody = buildNewBodyContent(currentPair, param, value);
        try {
            setEncodedReqBodyMessage(msg, reqBody);
            return value;
        } catch (Exception e) {
            LOGGER.warn("Failed to set parameter in GraphQL message: {}", e.getMessage());
            return null;
        }
    }

    private void setEncodedReqBodyMessage(HttpMessage msg, String newContent) throws Exception {
        protoBufMessageEncoder.encode(EncoderUtils.parseIntoList(newContent));
        byte[] encodedMessage = protoBufMessageEncoder.getOutputEncodedMessage();
        encodedMessage = Base64.getEncoder().encode(encodedMessage);
        msg.getRequestBody().setBody(encodedMessage);
    }

    private String buildNewBodyContent(NameValuePair currentPair, String param, String value) {
        StringBuilder sb = new StringBuilder();

        for (NameValuePair pair : params) {
            sb.append(pair.getName());
            sb.append("::");
            if (pair == currentPair) {
                String curPairName = currentPair.getName();
                String[] nameType = curPairName.split(":", 2);
                if (nameType[1].charAt(0) == '2') sb.append('"').append(value).append('"');
                else sb.append(value);
            } else {
                sb.append(pair.getValue());
            }
            sb.append("\n");
        }

        return sb.toString();
    }

    @Override
    public String setEscapedParameter(
            HttpMessage msg, NameValuePair originalPair, String param, String value) {
        return "";
    }

    @Override
    public void decodeResponseBody(HttpMessage msg) {
        try {
            byte[] body =
                    DecoderUtils.splitMessageBodyAndStatusCode(msg.getResponseBody().getBytes());
            body = Base64.getDecoder().decode(body);
            byte[] payload = DecoderUtils.extractPayload(body);
            protoBufMessageDecoder.decode(payload);
            msg.getResponseBody().setBody(protoBufMessageDecoder.getDecodedOutput());
        } catch (Exception e) {
            LOGGER.error("Error decoding the Response Body: {}", e.getMessage());
        }
    }
}
