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
package org.zaproxy.zap.extension.fuzz.httpfuzzer.messagelocations;

import java.util.SortedSet;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.fuzz.messagelocations.MessageLocationReplacement;
import org.zaproxy.zap.extension.fuzz.messagelocations.MessageLocationReplacer;
import org.zaproxy.zap.model.InvalidMessageException;
import org.zaproxy.zap.model.MessageLocation;
import org.zaproxy.zap.model.TextHttpMessageLocation;

public class TextHttpMessageLocationReplacer implements MessageLocationReplacer<HttpMessage> {

    private HttpMessage message;

    @Override
    public boolean supports(MessageLocation location) {
        return supports(location.getClass());
    }

    @Override
    public boolean supports(Class<? extends MessageLocation> classLocation) {
        return TextHttpMessageLocation.class.isAssignableFrom(classLocation);
    }

    @Override
    public void init(HttpMessage message) {
        this.message = message.cloneAll();
    }

    @Override
    public HttpMessage replace(SortedSet<? extends MessageLocationReplacement<?>> replacements)
            throws InvalidMessageException {
        if (message == null) {
            throw new IllegalStateException("Replacer not initialised.");
        }

        Replacer requestHeaderReplacement = null;
        Replacer requestBodyReplacement = null;
        Replacer responseHeaderReplacement = null;
        Replacer responseBodyReplacement = null;

        Replacer currentReplacement = null;
        for (MessageLocationReplacement<?> replacement : replacements) {
            MessageLocation location = replacement.getMessageLocation();
            if (!(location instanceof TextHttpMessageLocation)) {
                continue;
            }

            TextHttpMessageLocation textLocation = (TextHttpMessageLocation) location;
            switch (textLocation.getLocation()) {
                case REQUEST_HEADER:
                    if (requestHeaderReplacement == null) {
                        requestHeaderReplacement =
                                new Replacer(message.getRequestHeader().toString());
                    }
                    currentReplacement = requestHeaderReplacement;
                    break;
                case REQUEST_BODY:
                    if (requestBodyReplacement == null) {
                        requestBodyReplacement = new Replacer(message.getRequestBody().toString());
                    }
                    currentReplacement = requestBodyReplacement;
                    break;
                case RESPONSE_HEADER:
                    if (responseHeaderReplacement == null) {
                        responseHeaderReplacement =
                                new Replacer(message.getResponseHeader().toString());
                    }
                    currentReplacement = responseHeaderReplacement;
                    break;
                case RESPONSE_BODY:
                    if (responseBodyReplacement == null) {
                        responseBodyReplacement =
                                new Replacer(message.getResponseBody().toString());
                    }
                    currentReplacement = responseBodyReplacement;
                    break;
                default:
                    currentReplacement = null;
            }

            if (currentReplacement != null) {
                currentReplacement.replace(
                        textLocation.getStart(),
                        textLocation.getEnd(),
                        replacement.getReplacement().toString());
            }
        }

        HttpMessage replacedMessage = message.cloneAll();
        if (requestHeaderReplacement != null) {
            try {
                replacedMessage.setRequestHeader(requestHeaderReplacement.toString());
            } catch (HttpMalformedHeaderException e) {
                throw new InvalidMessageException(e);
            }
        }

        if (requestBodyReplacement != null) {
            replacedMessage.setRequestBody(requestBodyReplacement.toString());
        }

        if (responseHeaderReplacement != null) {
            try {
                replacedMessage.setResponseHeader(responseHeaderReplacement.toString());
            } catch (HttpMalformedHeaderException e) {
                throw new InvalidMessageException(e);
            }
        }

        if (responseBodyReplacement != null) {
            replacedMessage.setResponseBody(responseBodyReplacement.toString());
        }

        return replacedMessage;
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

        @Override
        public String toString() {
            return value.toString();
        }
    }
}
