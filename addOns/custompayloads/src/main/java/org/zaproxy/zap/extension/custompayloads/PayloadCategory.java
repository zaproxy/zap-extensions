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
package org.zaproxy.zap.extension.custompayloads;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public final class PayloadCategory {

    private final String name;
    private final List<CustomPayload> defaultPayloads;
    private List<CustomPayload> payloads;

    public PayloadCategory(String name, List<String> defaultPayloads) {
        this(name, defaultPayloads, List.of());
    }

    /**
     * @since 0.15.0
     */
    public PayloadCategory(
            List<String> defaultPayloads, List<String> disabledPayloads, String name) {
        this(name, defaultPayloads);
        this.defaultPayloads.addAll(createDisabledPayloads(name, disabledPayloads));
        this.payloads = this.defaultPayloads;
    }

    PayloadCategory(String name, List<String> defaultPayloads, List<CustomPayload> payloads) {
        this.name = Objects.requireNonNull(name);
        this.defaultPayloads = createEnabledPayloads(name, defaultPayloads);
        this.payloads = Objects.requireNonNull(payloads);
    }

    public String getName() {
        return name;
    }

    public PayloadIterator getPayloadsIterator() {
        return new PayloadIterator(this);
    }

    List<CustomPayload> getPayloads() {
        return payloads;
    }

    void setPayloads(List<CustomPayload> payloads) {
        this.payloads = payloads;
    }

    List<CustomPayload> getDefaultPayloads() {
        return defaultPayloads;
    }

    private static List<CustomPayload> createEnabledPayloads(String name, List<String> payloads) {
        return createPayloads(name, payloads, true);
    }

    private static List<CustomPayload> createDisabledPayloads(String name, List<String> payloads) {
        return createPayloads(name, payloads, false);
    }

    private static List<CustomPayload> createPayloads(
            String name, List<String> payloads, boolean enabled) {
        Objects.requireNonNull(payloads);

        if (payloads.isEmpty()) {
            return new ArrayList<>();
        }

        List<CustomPayload> defaultPayloads = new ArrayList<>(payloads.size());
        for (String payload : payloads) {
            defaultPayloads.add(new CustomPayload(enabled, name, payload));
        }
        return defaultPayloads;
    }
}
