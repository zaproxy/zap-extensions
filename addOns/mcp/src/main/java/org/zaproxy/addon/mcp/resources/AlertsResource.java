/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.mcp.resources;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.addon.mcp.McpResource;
import org.zaproxy.zap.extension.alert.ExtensionAlert;

/**
 * MCP resource that provides a summary of ZAP security alerts (name, risk, alertRef,
 * instanceCount).
 */
public class AlertsResource implements McpResource {

    private static final String URI = "zap://alerts";

    @Override
    public String getUri() {
        return URI;
    }

    @Override
    public String getName() {
        return "alerts";
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("mcp.resource.alerts.desc");
    }

    @Override
    public ObjectNode toListEntry() {
        ObjectNode node = OBJECT_MAPPER.createObjectNode();
        node.put("uri", getUri());
        node.put("name", getName());
        node.put("description", getDescription());
        node.put("mimeType", getMimeType());
        return node;
    }

    @Override
    public String readContent() {
        ExtensionAlert extAlert =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionAlert.class);
        if (extAlert == null) {
            return "[]";
        }

        List<Alert> alerts = extAlert.getAllAlerts();
        Map<String, SummaryEntry> summaryByAlertRef = new LinkedHashMap<>();

        for (Alert alert : alerts) {
            String alertRef =
                    alert.getAlertRef() != null
                            ? alert.getAlertRef()
                            : String.valueOf(alert.getPluginId());
            summaryByAlertRef.compute(
                    alertRef,
                    (k, existing) -> {
                        if (existing == null) {
                            return new SummaryEntry(
                                    alert.getName(),
                                    alert.getRisk(),
                                    alert.getConfidence(),
                                    alert.getPluginId(),
                                    alertRef,
                                    alert.isSystemic());
                        }
                        existing.incrementCount();
                        return existing;
                    });
        }

        List<SummaryEntry> entries = new ArrayList<>(summaryByAlertRef.values());
        entries.sort(Comparator.comparingInt((SummaryEntry e) -> e.risk).reversed());

        ArrayNode array = OBJECT_MAPPER.createArrayNode();
        for (SummaryEntry entry : entries) {
            ObjectNode node = OBJECT_MAPPER.createObjectNode();
            node.put("name", entry.name);
            node.put("risk", Alert.MSG_RISK[entry.risk]);
            node.put("pluginId", entry.pluginId);
            node.put("alertRef", entry.alertRef);
            node.put("systemic", entry.systemic);
            node.put("instanceCount", entry.instanceCount);
            node.put("instancesUri", "zap://alerts/" + entry.alertRef);
            array.add(node);
        }
        return array.toString();
    }

    private static class SummaryEntry {
        final String name;
        final int risk;
        final int pluginId;
        final String alertRef;
        final boolean systemic;
        int instanceCount;

        SummaryEntry(
                String name,
                int risk,
                int confidence,
                int pluginId,
                String alertRef,
                boolean systemic) {
            this.name = name;
            this.risk = risk;
            this.pluginId = pluginId;
            this.alertRef = alertRef;
            this.systemic = systemic;
            this.instanceCount = 1;
        }

        void incrementCount() {
            instanceCount++;
        }
    }
}
