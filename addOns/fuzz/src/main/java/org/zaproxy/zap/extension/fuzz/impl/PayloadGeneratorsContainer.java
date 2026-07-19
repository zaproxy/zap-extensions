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
import org.zaproxy.zap.extension.fuzz.payloads.ui.PayloadGeneratorUI;
import org.zaproxy.zap.extension.fuzz.payloads.ui.PayloadGeneratorUIHandler;
import org.zaproxy.zap.extension.fuzz.payloads.ui.PayloadGeneratorUIPanel;

public class PayloadGeneratorsContainer {

    private final String defaultPanelName;
    private Map<String, PayloadGeneratorUIPanel> panels;
    private Map<Class<?>, PayloadGeneratorUIPanel> panelsMap;

    public PayloadGeneratorsContainer(
            Collection<PayloadGeneratorUIHandler> payloadUIHandlers, String defaultPanelName) {
        this.panels = new HashMap<>();
        this.panelsMap = new HashMap<>();

        String panelName = defaultPanelName;
        for (PayloadGeneratorUIHandler payloadUIHandler : payloadUIHandlers) {
            addHelper(payloadUIHandler);
            panels.put(
                    payloadUIHandler.getName(),
                    panelsMap.get(payloadUIHandler.getPayloadGeneratorUIClass()));
        }

        if (!panels.containsKey(panelName)) {
            panelName = panels.keySet().iterator().next();
        }
        this.defaultPanelName = panelName;
    }

    private void addHelper(PayloadGeneratorUIHandler payloadUIHandler) {
        panelsMap.put(
                payloadUIHandler.getPayloadGeneratorUIClass(),
                payloadUIHandler
                        .getPayloadGeneratorUIPanelClass()
                        .cast(payloadUIHandler.createPanel()));
    }

    public Set<String> getPayloadUIHandlersNames() {
        return panels.keySet();
    }

    public String getDefaultPanelName() {
        return defaultPanelName;
    }

    public PayloadGeneratorUIPanel getPanel(String name) {
        return panels.get(name);
    }

    @SuppressWarnings("unchecked")
    public <T extends PayloadGeneratorUIPanel> T getPanel(PayloadGeneratorUI payloadGeneratorUI) {
        PayloadGeneratorUIPanel panel = panelsMap.get(payloadGeneratorUI.getClass());
        if (panel != null) {
            return (T) panel;
        }
        return null;
    }

    public Collection<PayloadGeneratorUIPanel> getPanels() {
        return panels.values();
    }
}
