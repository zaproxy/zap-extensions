/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.websocket.fuzz.messagelocations;

import java.util.SortedSet;
import org.zaproxy.zap.extension.fuzz.messagelocations.MessageLocationReplacement;
import org.zaproxy.zap.extension.fuzz.messagelocations.MessageLocationReplacer;
import org.zaproxy.zap.extension.websocket.WebSocketFuzzMessageDTO;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.messagelocations.TextWebSocketMessageLocation;
import org.zaproxy.zap.model.InvalidMessageException;
import org.zaproxy.zap.model.MessageLocation;

public class TextWebSocketMessageLocationReplacer
        implements MessageLocationReplacer<WebSocketMessageDTO> {

    private WebSocketMessageDTO message;

    @Override
    public boolean supports(MessageLocation location) {
        return supports(location.getClass());
    }

    @Override
    public boolean supports(Class<? extends MessageLocation> classLocation) {
        return TextWebSocketMessageLocation.class.isAssignableFrom(classLocation);
    }

    @Override
    public void init(WebSocketMessageDTO message) {
        this.message = copyMessage(message);
    }

    @Override
    public WebSocketFuzzMessageDTO replace(
            SortedSet<? extends MessageLocationReplacement<?>> replacements)
            throws InvalidMessageException {
        if (message == null) {
            throw new IllegalStateException("Replacer not initialised.");
        }

        if (!(message.getPayload() instanceof String)) {
            // TODO: Exclude popup menu or support fuzzing binary payloads - why not?
            return copyMessage(message);
        }

        Replacer replacer = new Replacer((String) message.getPayload());
        for (MessageLocationReplacement<?> replacement : replacements) {
            MessageLocation location = replacement.getMessageLocation();
            if (!(location instanceof TextWebSocketMessageLocation)) {
                continue;
            }

            TextWebSocketMessageLocation textLocation = (TextWebSocketMessageLocation) location;
            replacer.replace(
                    textLocation.getStart(),
                    textLocation.getEnd(),
                    replacement.getReplacement().toString());
        }

        WebSocketFuzzMessageDTO replacedMessage = copyMessage(message);
        replacedMessage.setPayload(replacer.toString());
        replacedMessage.setPayloadLength(Integer.valueOf(replacer.length()));

        return replacedMessage;
    }

    private WebSocketFuzzMessageDTO copyMessage(WebSocketMessageDTO msg) {
        WebSocketFuzzMessageDTO fuzzMessage = new WebSocketFuzzMessageDTO();
        msg.copyInto(fuzzMessage);
        return fuzzMessage;
    }

    private static class Replacer {

        private StringBuilder value;
        private int offset;

        private Replacer(String originalValue) {
            value = new StringBuilder(originalValue);
        }

        public void replace(int start, int end, String value) {
            this.value.replace(offset + start, offset + end, value);
            offset += value.length() - (end - start);
        }

        public int length() {
            return value.length();
        }

        @Override
        public String toString() {
            return value.toString();
        }
    }
}
