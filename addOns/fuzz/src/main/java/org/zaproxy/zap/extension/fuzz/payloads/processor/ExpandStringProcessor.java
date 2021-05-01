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
package org.zaproxy.zap.extension.fuzz.payloads.processor;

import org.zaproxy.zap.extension.fuzz.payloads.DefaultPayload;

/**
 * A {@code DefaultPayloadProcessor} that allows to expand the payload up to a given length
 * appending a given value to begin or end of the payload.
 */
public class ExpandStringProcessor implements DefaultPayloadProcessor {

    public enum Position {
        BEGIN,
        END
    }

    private final Position position;
    private final String value;
    private final int length;

    public ExpandStringProcessor(String value, int length) {
        this(Position.BEGIN, value, length);
    }

    public ExpandStringProcessor(Position position, String value, int length) {
        if (position == null) {
            throw new IllegalArgumentException("Parameter position must not be null.");
        }
        if (value == null) {
            throw new IllegalArgumentException("Parameter value must not be null.");
        }

        if (length <= 0) {
            throw new IllegalArgumentException("Parameter length must be greater than zero.");
        }

        this.position = position;
        this.value = value;
        this.length = length;
    }

    @Override
    public DefaultPayload process(DefaultPayload payload) {
        String valuePayload = payload.getValue();
        if (valuePayload.length() >= length) {
            return payload;
        }

        int expansionLength = length - valuePayload.length();
        StringBuilder expandedValue = new StringBuilder(length);
        for (int i = 0; i < expansionLength; i++) {
            expandedValue.append(value);
        }

        switch (position) {
            case END:
                expandedValue.insert(0, valuePayload);
                break;
            case BEGIN:
            default:
                expandedValue.append(valuePayload);
        }

        payload.setValue(expandedValue.toString());
        return payload;
    }

    @Override
    public ExpandStringProcessor copy() {
        return this;
    }
}
