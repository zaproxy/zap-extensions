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
import java.util.Vector;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.db.RecordAlert;
import org.parosproxy.paros.db.TableAlert;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.mcp.McpResource;

/**
 * MCP resource that provides a summary of ZAP security alerts (name, risk, alertRef,
 * instanceCount).
 */
public class AlertsResource implements McpResource {

    private static final Logger LOGGER = LogManager.getLogger(AlertsResource.class);

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
    public String readContent() {
        try {
            // This is nasty, but there are no better options in the 2.17 core :(
            TableAlert tableAlert = Model.getSingleton().getDb().getTableAlert();
            Vector<Integer> alertIds = tableAlert.getAlertList();
            Map<String, SummaryEntry> summaryByAlertRef = new LinkedHashMap<>();

            for (Integer alertId : alertIds) {

                RecordAlert recAlert = tableAlert.read(alertId);
                Alert alert = new Alert(recAlert);
                summaryByAlertRef.compute(
                        alert.getAlertRef(),
                        (k, existing) -> {
                            if (existing == null) {
                                return new SummaryEntry(
                                        alert.getName(),
                                        alert.getRisk(),
                                        alert.getPluginId(),
                                        alert.getAlertRef(),
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
        } catch (DatabaseException e) {
            LOGGER.error(e.getMessage(), e);
            return McpResource.errorJson(
                    Constant.messages.getString("mcp.resource.error.internal"));
        }
    }

    private static class SummaryEntry {
        final String name;
        final int risk;
        final int pluginId;
        final String alertRef;
        final boolean systemic;
        int instanceCount;

        SummaryEntry(String name, int risk, int pluginId, String alertRef, boolean systemic) {
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
