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

public class TrimStringProcessor implements DefaultPayloadProcessor {

    private int length;

    public TrimStringProcessor(int length) {
        if (length <= 0) {
            throw new IllegalArgumentException("Parameter length must be greater than zero.");
        }

        this.length = length;
    }

    @Override
    public DefaultPayload process(DefaultPayload payload) {
        String value = payload.getValue();
        if (value.length() > length) {
            payload.setValue(value.substring(0, length));
        }
        return payload;
    }

    @Override
    public TrimStringProcessor copy() {
        return this;
    }
}
