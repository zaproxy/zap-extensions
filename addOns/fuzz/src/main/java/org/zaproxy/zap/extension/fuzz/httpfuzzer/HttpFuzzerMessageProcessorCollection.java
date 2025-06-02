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
package org.zaproxy.zap.extension.fuzz.httpfuzzer;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.fuzz.FuzzerMessageProcessorUI;
import org.zaproxy.zap.extension.fuzz.FuzzerMessageProcessorUIPanel;
import org.zaproxy.zap.extension.fuzz.impl.FuzzerMessageProcessors;

public class HttpFuzzerMessageProcessorCollection
        implements FuzzerMessageProcessors<HttpMessage, HttpFuzzerMessageProcessor> {

    private final String defaultPanelName;
    private List<HttpFuzzerMessageProcessorUIHandler<?, ?>> handlers;
    private Map<String, HttpFuzzerMessageProcessorUIHandler<HttpFuzzerMessageProcessor, ?>>
            handlersMap;
    private Map<String, HttpFuzzerMessageProcessorUIPanel<HttpFuzzerMessageProcessor, ?>> panelsMap;
    private List<FuzzerMessageProcessorUI<HttpMessage, HttpFuzzerMessageProcessor>>
            defaultProcessors;

    public HttpFuzzerMessageProcessorCollection(
            HttpMessage message,
            Collection<HttpFuzzerMessageProcessorUIHandler<HttpFuzzerMessageProcessor, ?>>
                    uiHandlers) {
        handlers = new ArrayList<>();
        handlersMap = new HashMap<>();
        panelsMap = new HashMap<>();
        defaultProcessors = new ArrayList<>();

        for (HttpFuzzerMessageProcessorUIHandler<HttpFuzzerMessageProcessor, ?> uiHandler :
                uiHandlers) {
            if (uiHandler.isEnabled(message)) {
                handlers.add(uiHandler);
                handlersMap.put(uiHandler.getName(), uiHandler);
                panelsMap.put(uiHandler.getName(), uiHandler.createPanel());

                if (uiHandler.isDefault()) {
                    defaultProcessors.add(uiHandler.createDefault());
                }
            }
        }

        if (!isEmpty()) {
            defaultPanelName = handlers.get(0).getName();
        } else {
            defaultPanelName = null;
        }
    }

    @Override
    public boolean isEmpty() {
        return handlers.isEmpty();
    }

    @Override
    public FuzzerMessageProcessorUIPanel<HttpMessage, HttpFuzzerMessageProcessor, ?> getPanel(
            String name) {
        return panelsMap.get(name);
    }

    @Override
    public <T3 extends FuzzerMessageProcessorUI<HttpMessage, HttpFuzzerMessageProcessor>>
            FuzzerMessageProcessorUIPanel<HttpMessage, HttpFuzzerMessageProcessor, T3> getPanel(
                    T3 fuzzerMessageProcessorUI) {
        for (HttpFuzzerMessageProcessorUIHandler<?, ?> handler : handlers) {
            if (handler.getFuzzerMessageProcessorUIType()
                    .equals(fuzzerMessageProcessorUI.getClass())) {
                @SuppressWarnings("unchecked")
                FuzzerMessageProcessorUIPanel<HttpMessage, HttpFuzzerMessageProcessor, T3> panel =
                        (FuzzerMessageProcessorUIPanel<HttpMessage, HttpFuzzerMessageProcessor, T3>)
                                panelsMap.get(handler.getName());
                return panel;
            }
        }
        return null;
    }

    @Override
    public FuzzerMessageProcessorUIPanel<HttpMessage, HttpFuzzerMessageProcessor, ?>
            getDefaultPanel() {
        return panelsMap.get(defaultPanelName);
    }

    @Override
    public List<? extends FuzzerMessageProcessorUI<HttpMessage, HttpFuzzerMessageProcessor>>
            getDefaultProcessors() {
        return defaultProcessors;
    }

    @Override
    public String getDefaultPanelName() {
        return defaultPanelName;
    }

    @Override
    public Collection<String> getFuzzerMessageProcessorUIHandlersNames() {
        return handlersMap.keySet();
    }

    @Override
    public Collection<HttpFuzzerMessageProcessorUIPanel<HttpFuzzerMessageProcessor, ?>>
            getPanels() {
        return panelsMap.values();
    }
}
