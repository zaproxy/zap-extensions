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
package org.zaproxy.zap.extension.fuzz.payloads.generator;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import org.zaproxy.zap.extension.fuzz.payloads.DefaultPayload;
import org.zaproxy.zap.extension.fuzz.payloads.PayloadCollectionIterator;
import org.zaproxy.zap.utils.ResettableAutoCloseableIterator;

/**
 * A {@code PayloadGenerator} that returns {@code DefaultPayload} created from a {@code List} of
 * {@code String}s.
 */
public class DefaultStringPayloadGenerator implements StringPayloadGenerator {

    private final List<DefaultPayload> payloads;

    public DefaultStringPayloadGenerator(String value) {
        if (value == null) {
            throw new IllegalArgumentException("Parameter value must not be null.");
        }
        List<DefaultPayload> tempPayloads = new ArrayList<>(1);
        tempPayloads.add(new DefaultPayload(value));

        payloads = tempPayloads;
    }

    public DefaultStringPayloadGenerator(List<String> values) {
        if (values == null || values.isEmpty()) {
            throw new IllegalArgumentException("Parameter values must not be null nor empty.");
        }
        List<DefaultPayload> tempPayloads = new ArrayList<>(values.size());
        for (String value : values) {
            tempPayloads.add(new DefaultPayload(value));
        }

        payloads = tempPayloads;
    }

    private DefaultStringPayloadGenerator(Collection<DefaultPayload> payloads) {
        List<DefaultPayload> tempPayloads = new ArrayList<>(payloads.size());
        for (DefaultPayload payload : payloads) {
            tempPayloads.add(payload);
        }
        this.payloads = tempPayloads;
    }

    @Override
    public long getNumberOfPayloads() {
        return payloads.size();
    }

    @Override
    public ResettableAutoCloseableIterator<DefaultPayload> iterator() {
        return new PayloadCollectionIterator<>(payloads);
    }

    @Override
    public DefaultStringPayloadGenerator copy() {
        return new DefaultStringPayloadGenerator(payloads);
    }
}
