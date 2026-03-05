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
import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.addon.mcp.McpResource;
import org.zaproxy.zap.extension.alert.ExtensionAlert;

/**
 * MCP resource that returns all instances for a given alert (by alertRef). Use {@code
 * zap://alerts/{alertRef}} where alertRef comes from the zap://alerts summary.
 */
public class AlertInstancesResource implements McpResource {

    private static final String URI_PREFIX = "zap://alerts/";

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
    public ObjectNode toListEntry() {
        ObjectNode node = OBJECT_MAPPER.createObjectNode();
        node.put("uri", getUri() + "{alertRef}");
        node.put("name", getName());
        node.put("description", getDescription());
        node.put("mimeType", getMimeType());
        return node;
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

        // This is not very efficient, but its the only method available in the 2.17 core :(
        List<Alert> alerts = extAlert.getAllAlerts();
        ArrayNode array = OBJECT_MAPPER.createArrayNode();
        for (Alert alert : alerts) {
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
            if (alert.getHistoryRef() != null) {
                node.put("historyRef", "zap://history/" + alert.getHistoryRef().getHistoryId());
            }
            array.add(node);
        }
        return array.toString();
    }
}
