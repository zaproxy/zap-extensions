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
import java.util.Vector;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.db.RecordAlert;
import org.parosproxy.paros.db.TableAlert;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.mcp.McpResource;
import org.zaproxy.zap.extension.alert.ExtensionAlert;

/**
 * MCP resource that returns all instances for a given alert (by alertRef). Use {@code
 * zap://alerts/{alertRef}} where alertRef comes from the zap://alerts summary.
 */
public class AlertInstancesResource implements McpResource {

    private static final String URI_PREFIX = "zap://alerts/";

    private static final Logger LOGGER = LogManager.getLogger(AlertInstancesResource.class);

    @Override
    public String getUri() {
        return URI_PREFIX;
    }

    @Override
    public String getName() {
        return "alert-instances";
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("mcp.resource.alertinstances.desc");
    }

    @Override
    public String getUriTemplate() {
        return URI_PREFIX + "{alertRef}";
    }

    @Override
    public String readContent() {
        return "[]";
    }

    @Override
    public String readContent(String uri) {
        if (!uri.startsWith(URI_PREFIX)) {
            return McpResource.errorJson(
                    Constant.messages.getString("mcp.resource.alertinstances.error.invaliduri"));
        }
        String alertRef = uri.substring(URI_PREFIX.length()).trim();
        if (alertRef.isEmpty()) {
            return McpResource.errorJson(
                    Constant.messages.getString(
                            "mcp.resource.alertinstances.error.missingalertref"));
        }

        ExtensionAlert extAlert =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionAlert.class);
        if (extAlert == null) {
            return "[]";
        }
        ExtensionHistory extensionHistory =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionHistory.class);

        try {
            // This is nasty, but there are no better options in the 2.17 core :(
            TableAlert tableAlert = Model.getSingleton().getDb().getTableAlert();
            Vector<Integer> alertIds = tableAlert.getAlertList();

            ArrayNode array = OBJECT_MAPPER.createArrayNode();
            for (Integer alertId : alertIds) {

                RecordAlert recAlert = tableAlert.read(alertId);
                Alert alert = new Alert(recAlert);

                String alertRefValue =
                        alert.getAlertRef() != null
                                ? alert.getAlertRef()
                                : String.valueOf(alert.getPluginId());
                if (!alertRef.equals(alertRefValue)) {
                    continue;
                }
                ObjectNode node = OBJECT_MAPPER.createObjectNode();
                node.put("name", alert.getName());
                node.put("description", alert.getDescription());
                node.put("solution", alert.getSolution());
                node.put("risk", Alert.MSG_RISK[alert.getRisk()]);
                node.put("confidence", Alert.MSG_CONFIDENCE[alert.getConfidence()]);
                node.put("uri", alert.getUri());
                node.put("param", alert.getParam());
                node.put("attack", alert.getAttack());
                node.put("evidence", alert.getEvidence());
                node.put("other", alert.getOtherInfo());
                node.put("pluginId", alert.getPluginId());
                node.put("alertRef", alert.getAlertRef());
                node.put("systemic", alert.isSystemic());
                HistoryReference historyReference =
                        extensionHistory != null
                                ? extensionHistory.getHistoryReference(recAlert.getHistoryId())
                                : null;
                if (historyReference != null) {
                    node.put("historyRef", "zap://history/" + historyReference.getHistoryId());
                }
                array.add(node);
            }
            return array.toString();
        } catch (DatabaseException e) {
            LOGGER.error(e.getMessage(), e);
            return McpResource.errorJson(
                    Constant.messages.getString("mcp.resource.error.internal"));
        }
    }
}
