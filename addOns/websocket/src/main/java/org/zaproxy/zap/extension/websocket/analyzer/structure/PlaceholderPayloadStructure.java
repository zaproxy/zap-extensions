/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.zap.extension.websocket.analyzer.structure;

import java.util.ArrayList;
import java.util.List;
import org.apache.log4j.Logger;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.analyzer.structural.SimpleNameValuePair;
import org.zaproxy.zap.extension.websocket.analyzer.structural.WebSocketNameValuePair;
import org.zaproxy.zap.extension.websocket.utility.InvalidUtf8Exception;

public class PlaceholderPayloadStructure implements PayloadStructure {

    private static final Logger LOGGER = Logger.getLogger(PlaceholderPayloadStructure.class);
    private List<WebSocketNameValuePair> parameters;
    private WebSocketMessageDTO message = null;
    private String placeholdedString = null;

    private PlaceholderPayloadStructure(
            List<WebSocketNameValuePair> parameters,
            WebSocketMessageDTO message,
            String placeholderString) {
        this.parameters = parameters;
        this.message = message;
        this.placeholdedString = placeholderString;
    }

    @Override
    public List<WebSocketNameValuePair> getList() {
        return parameters;
    }

    //    @Override
    //    public boolean setParameter(WebSocketNameValuePair originalPair, String name, String
    // value) {
    //        if (originalPair.getPosition() > getList().size()) {
    //            return false;
    //        }
    //        SimpleNameValuePair.Builder builder =
    //                new SimpleNameValuePair.Builder(getList().get(originalPair.getPosition()));
    //
    //        builder.setValue(value, originalPair.getType());
    //        getList().set(originalPair.getPosition(), builder.build());
    //        return true;
    //    }

    @Override
    public WebSocketMessageDTO getOriginalMessage() {
        return message;
    }

    public String getPlaceholdedString() {
        return placeholdedString;
    }

    @Override
    public String getName() {
        return null;
    }

    @Override
    public WebSocketMessageDTO execute() {
        if (this.parameters.isEmpty()) {
            return this.message;
        }

        WebSocketMessageDTO newMessage = this.message.clone();

        StringBuilder newPayload = new StringBuilder();

        int currentPosition = 0;
        for (WebSocketNameValuePair parameter : parameters) {
            newPayload
                    .append(placeholdedString, currentPosition, parameter.getPosition())
                    .append(parameter.getValue());
            currentPosition = parameter.getPosition() + parameter.getName().length();
        }
        if (currentPosition < placeholdedString.length()) {
            newPayload.append(placeholdedString, currentPosition, placeholdedString.length());
        }
        newMessage.payload = newPayload.toString();
        return newMessage;
    }

    @Override
    public String toString() {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append(placeholdedString).append(" {\n");
        for (WebSocketNameValuePair valuePair : parameters) {
            stringBuilder.append(valuePair.toString()).append("\n");
        }
        stringBuilder.append("}\n");
        return stringBuilder.toString();
    }

    public static class Builder {

        private WebSocketMessageDTO message;
        private List<SimpleNameValuePair> parameters;
        private String originalPayload;

        public Builder(WebSocketMessageDTO message) throws InvalidUtf8Exception {
            this.message = message;
            parameters = new ArrayList<>();
            originalPayload = message.getReadablePayload();
        }

        public Builder setOriginalMessage(WebSocketMessageDTO originalMessage) {
            message = originalMessage;
            return this;
        }

        public Builder add(SimpleNameValuePair pair) {
            if (pair.getPosition() >= 0 && pair.getPosition() < originalPayload.length()) {
                parameters.add(pair);
            }
            return this;
        }

        public PlaceholderPayloadStructure build() {
            StringBuilder newPayload = new StringBuilder();
            List<WebSocketNameValuePair> placeholderParameters = new ArrayList<>();

            int currentPosition = 0;

            for (SimpleNameValuePair parameter : parameters) {
                newPayload.append(originalPayload, currentPosition, parameter.getPosition());
                placeholderParameters.add(
                        new PlaceholderNameValuePair(
                                parameter, newPayload.length() - parameter.getPosition()));
                newPayload.append(parameter.getName());

                currentPosition = parameter.getPosition() + parameter.getValue().length();
            }
            if (currentPosition < originalPayload.length()) {
                newPayload.append(originalPayload, currentPosition, originalPayload.length());
            }

            return new PlaceholderPayloadStructure(
                    placeholderParameters, message, newPayload.toString());
        }
    }

    private static class PlaceholderNameValuePair implements WebSocketNameValuePair {
        private int offset;
        private WebSocketNameValuePair pair;

        PlaceholderNameValuePair(WebSocketNameValuePair pair, int offset) {
            this.pair = pair;
            this.offset = offset;
        }

        @Override
        public String getName() {
            return pair.getName();
        }

        @Override
        public String getValue() {
            return pair.getValue();
        }

        @Override
        public Type getType() {
            return pair.getType();
        }

        @Override
        public int getPosition() {
            return pair.getPosition() + offset;
        }

        @Override
        public void setValue(String value) {
            pair.setValue(value);
        }
    }
}
