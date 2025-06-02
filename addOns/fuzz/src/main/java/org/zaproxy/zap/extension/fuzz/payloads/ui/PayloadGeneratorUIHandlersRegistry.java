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
package org.zaproxy.zap.extension.fuzz.payloads.ui;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.zaproxy.zap.extension.fuzz.payloads.Payload;
import org.zaproxy.zap.extension.fuzz.payloads.generator.PayloadGenerator;

public final class PayloadGeneratorUIHandlersRegistry {

    private static PayloadGeneratorUIHandlersRegistry instance;

    private Map<Class<?>, PayloadGeneratorUIHandler<?, ?, ?>> payloadUIHandlers;
    private String nameDefaultPayloadGenerator;

    public static PayloadGeneratorUIHandlersRegistry getInstance() {
        if (instance == null) {
            createInstance();
        }
        return instance;
    }

    private static synchronized void createInstance() {
        if (instance == null) {
            instance = new PayloadGeneratorUIHandlersRegistry();
        }
    }

    private PayloadGeneratorUIHandlersRegistry() {
        payloadUIHandlers = new HashMap<>();
    }

    public <
                    T2 extends Payload,
                    T3 extends PayloadGenerator<T2>,
                    T4 extends PayloadGeneratorUI<T2, T3>,
                    T5 extends PayloadGeneratorUIHandler<T2, T3, T4>>
            void registerPayloadUI(Class<T3> payloadGeneratorClass, T5 uiHandler) {
        payloadUIHandlers.put(payloadGeneratorClass, uiHandler);
    }

    public <
                    T2 extends Payload,
                    T3 extends PayloadGenerator<T2>,
                    T4 extends PayloadGeneratorUI<T2, T3>,
                    T5 extends PayloadGeneratorUIHandler<T2, T3, T4>>
            T5 getPayloadGeneratorUIHandler(Class<T3> payloadGeneratorClass) {
        Object object = payloadUIHandlers.get(payloadGeneratorClass);
        if (object == null) {
            return null;
        }
        @SuppressWarnings("unchecked")
        T5 handler = (T5) object;
        return handler;
    }

    public Collection<PayloadGeneratorUIHandler<?, ?, ?>> getPayloadGeneratorUIHandlers() {
        return Collections.unmodifiableCollection(payloadUIHandlers.values());
    }

    public <
                    T2 extends Payload,
                    T3 extends PayloadGenerator<T2>,
                    T4 extends PayloadGeneratorUI<T2, T3>,
                    T5 extends PayloadGeneratorUIHandler<T2, T3, T4>>
            void removePayloadGeneratorUIHandler(Class<T3> payloadClass) {
        payloadUIHandlers.remove(payloadClass);
    }

    public <
                    T2 extends Payload,
                    T3 extends PayloadGenerator<T2>,
                    T4 extends PayloadGeneratorUI<T2, T3>,
                    T5 extends PayloadGeneratorUIHandler<T2, T3, T4>>
            void setDefaultPayloadGenerator(T5 uiHandler) {
        if (payloadUIHandlers.containsValue(uiHandler)) {
            nameDefaultPayloadGenerator = uiHandler.getName();
        }
    }

    public String getNameDefaultPayloadGenerator() {
        return nameDefaultPayloadGenerator;
    }
}
