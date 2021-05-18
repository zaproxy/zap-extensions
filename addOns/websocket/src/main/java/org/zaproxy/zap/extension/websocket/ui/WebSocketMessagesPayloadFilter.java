/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.websocket.ui;

import java.util.regex.Pattern;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;

/**
 * Value object of the payload filter for the {@link WebSocketMessagesView}. Used as filter for the
 * {@link WebSocketPanel} restricting payloads of messages shown in WebSockets tab.
 */
public class WebSocketMessagesPayloadFilter {
    private String stringPayloadPattern;
    /**
     * Defines the expression used to filter the websocket messages in the {@link
     * WebSocketMessagesView} by their payload. This expression is either an regular expression or a
     * simple search string.
     */
    private Pattern payloadPattern;

    /** Determines if the expression of the filter is a regular expression. */
    private boolean regularExpression;

    /** Determines if the filter should be case sensitive. */
    private boolean ignoreCase;

    /** Determines if the matches of the filter should be inverted. */
    private boolean inverted;

    public Pattern getPayloadPattern() {
        return payloadPattern;
    }

    public void setPattern(Pattern pattern) {
        this.payloadPattern = pattern;
    }

    public boolean isRegularExpression() {
        return regularExpression;
    }

    public boolean isIgnoreCase() {
        return ignoreCase;
    }

    public boolean isInverted() {
        return inverted;
    }

    public void setInverted(boolean inverted) {
        this.inverted = inverted;
    }

    public String getStringPayloadPattern() {
        return stringPayloadPattern;
    }

    private void compilePattern() {
        if (ignoreCase) {
            this.payloadPattern =
                    Pattern.compile(
                            !regularExpression
                                    ? Pattern.quote(stringPayloadPattern)
                                    : stringPayloadPattern,
                            Pattern.MULTILINE | Pattern.CASE_INSENSITIVE);
        } else {
            this.payloadPattern =
                    Pattern.compile(
                            !regularExpression
                                    ? Pattern.quote(stringPayloadPattern)
                                    : stringPayloadPattern,
                            Pattern.MULTILINE);
        }
    }

    /** Construct and compile payload filter */
    public WebSocketMessagesPayloadFilter(
            String stringPayloadPattern,
            boolean regularExpression,
            boolean ignoreCase,
            boolean inverted) {
        this.stringPayloadPattern = stringPayloadPattern;
        this.regularExpression = regularExpression;
        this.ignoreCase = ignoreCase;
        this.inverted = inverted;
        compilePattern();
    }

    /** Reset the filter in the empty state */
    public void reset() {
        stringPayloadPattern = null;
        regularExpression = true;
        ignoreCase = false;
        inverted = false;
        payloadPattern = null;
    }

    /**
     * Checks if a Message is valid according to payload filter
     *
     * @param webSocketMessageDTO message is going to be checked
     * @return false if message must filtered out and true if it is valid according to
     *     payloadFilter.
     */
    public boolean isMessageValidWithPattern(WebSocketMessageDTO webSocketMessageDTO) {
        return inverted
                ? !payloadPattern.matcher((String) webSocketMessageDTO.getPayload()).find()
                : payloadPattern.matcher((String) webSocketMessageDTO.getPayload()).find();
    }

    /**
     * Checks if a String is valid according to payload filter
     *
     * @param payload string is going to be checked
     * @return false if message must filtered out and true if it is valid according to
     *     payloadFilter.
     */
    public boolean isStringValidWithPattern(String payload) {
        return inverted
                ? !payloadPattern.matcher(payload).find()
                : payloadPattern.matcher(payload).find();
    }
}
