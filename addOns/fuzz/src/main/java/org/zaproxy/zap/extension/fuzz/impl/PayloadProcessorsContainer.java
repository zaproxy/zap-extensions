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
package org.zaproxy.zap.extension.fuzz.impl;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.PayloadProcessorUI;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.PayloadProcessorUIHandler;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.PayloadProcessorUIPanel;

public class PayloadProcessorsContainer {

    private final String defaultPanelName;
    private Map<String, PayloadProcessorUIPanel> panels;
    private Map<Class<?>, PayloadProcessorUIPanel> panelsMap;

    public PayloadProcessorsContainer(
            Collection<PayloadProcessorUIHandler> payloadUIHandlers, String defaultPanelName) {
        this.panels = new HashMap<>();
        this.panelsMap = new HashMap<>();

        String panelName = defaultPanelName;
        for (PayloadProcessorUIHandler payloadUIHandler : payloadUIHandlers) {
            addHelper(payloadUIHandler);
            panels.put(
                    payloadUIHandler.getName(),
                    panelsMap.get(payloadUIHandler.getPayloadProcessorUIClass()));
        }

        if (!panels.containsKey(panelName)) {
            panelName = panels.keySet().iterator().next();
        }
        this.defaultPanelName = panelName;
    }

    private void addHelper(PayloadProcessorUIHandler payloadUIHandler) {
        panelsMap.put(
                payloadUIHandler.getPayloadProcessorUIClass(),
                payloadUIHandler
                        .getPayloadProcessorUIPanelClass()
                        .cast(payloadUIHandler.createPanel()));
    }

    public Set<String> getPayloadUIHandlersNames() {
        return panels.keySet();
    }

    public String getDefaultPanelName() {
        return defaultPanelName;
    }

    public PayloadProcessorUIPanel getPanel(String name) {
        return panels.get(name);
    }

    @SuppressWarnings("unchecked")
    public <T extends PayloadProcessorUIPanel> T getPanel(PayloadProcessorUI payloadProcessorUI) {
        PayloadProcessorUIPanel panel = panelsMap.get(payloadProcessorUI.getClass());
        if (panel != null) {
            return (T) panel;
        }
        return null;
    }

    public Collection<PayloadProcessorUIPanel> getPanels() {
        return panels.values();
    }
}
