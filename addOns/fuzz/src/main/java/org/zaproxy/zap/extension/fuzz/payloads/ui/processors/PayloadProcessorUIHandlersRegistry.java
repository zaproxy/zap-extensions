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
package org.zaproxy.zap.extension.fuzz.payloads.ui.processors;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import org.zaproxy.zap.extension.fuzz.payloads.processor.PayloadProcessor;

public final class PayloadProcessorUIHandlersRegistry {

    private static PayloadProcessorUIHandlersRegistry instance;

    private Map<Class<?>, PayloadProcessorUIHandler> processorUIHandlers;
    private String nameDefaultPayloadProcessor;

    public static PayloadProcessorUIHandlersRegistry getInstance() {
        if (instance == null) {
            createInstance();
        }
        return instance;
    }

    private static synchronized void createInstance() {
        if (instance == null) {
            instance = new PayloadProcessorUIHandlersRegistry();
        }
    }

    private PayloadProcessorUIHandlersRegistry() {
        processorUIHandlers = new HashMap<>();
    }

    public void registerProcessorUIHandler(
            Class<? extends PayloadProcessor> processorClass,
            PayloadProcessorUIHandler processorHandler) {
        processorUIHandlers.put(processorClass, processorHandler);
    }

    public Collection<PayloadProcessorUIHandler> getProcessorUIHandlers() {
        return processorUIHandlers.values();
    }

    public void setDefaultPayloadProcessor(PayloadProcessorUIHandler uiHandler) {
        if (processorUIHandlers.containsValue(uiHandler)) {
            nameDefaultPayloadProcessor = uiHandler.getName();
        }
    }

    public String getNameDefaultPayloadProcessor() {
        return nameDefaultPayloadProcessor;
    }
}
