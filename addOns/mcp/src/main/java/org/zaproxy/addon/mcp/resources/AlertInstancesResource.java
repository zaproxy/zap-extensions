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
 * MCP resource that returns instances for a given alert (by alertRef). Use {@code
 * zap://alerts/{alertRef}} where alertRef comes from the zap://alerts summary.
 *
 * <h3>Pagination</h3>
 *
 * <p>Append {@code ?start=N&count=M} query parameters to page through results:
 *
 * <pre>
 *   zap://alerts/10038           -- first page (up to DEFAULT_PAGE_SIZE instances)
 *   zap://alerts/10038?start=0&amp;count=50   -- instances 0 to 49
 *   zap://alerts/10038?start=50&amp;count=50  -- instances 50 to 99
 * </pre>
 *
 * <p>The response always includes {@code totalCount}, {@code returnedCount}, {@code start}, {@code
 * truncated}, and a ready-made {@code nextPageUri} when more results exist.
 *
 * <p>The page size is capped at {@value #MAX_PAGE_SIZE} regardless of the requested {@code count}
 * to keep individual responses within MCP client message-size limits.
 */
public class AlertInstancesResource implements McpResource {

    private static final String URI_PREFIX = "zap://alerts/";

    /**
     * Default number of instances returned when no {@code count} parameter is supplied.
     */
    static final int DEFAULT_PAGE_SIZE = 100;

    /**
     * Hard ceiling on page size. Callers cannot request more than this in one response.
     */
    static final int MAX_PAGE_SIZE = 200;

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

        // Split path from optional query string: zap://alerts/10038?start=0&count=50
        String remainder = uri.substring(URI_PREFIX.length());
        String alertRef;
        int start = 0;
        int requestedCount = -1; // -1 means "use default"

        int qIdx = remainder.indexOf('?');
        if (qIdx >= 0) {
            alertRef = remainder.substring(0, qIdx).trim();
            String query = remainder.substring(qIdx + 1);
            for (String param : query.split("&")) {
                int eqIdx = param.indexOf('=');
                if (eqIdx < 0) {
                    continue;
                }
                String key = param.substring(0, eqIdx).trim();
                String value = param.substring(eqIdx + 1).trim();
                switch (key) {
                    case "start":
                        try {
                            start = Integer.parseInt(value);
                        } catch (NumberFormatException e) {
                            return McpResource.errorJson(
                                    Constant.messages.getString(
                                            "mcp.resource.alertinstances.error.invalidstart"));
                        }
                        break;
                    case "count":
                        try {
                            requestedCount = Integer.parseInt(value);
                        } catch (NumberFormatException e) {
                            return McpResource.errorJson(
                                    Constant.messages.getString(
                                            "mcp.resource.alertinstances.error.invalidcount"));
                        }
                        break;
                    default:
                        break;
                }
            }
        } else {
            alertRef = remainder.trim();
        }

        if (alertRef.isEmpty()) {
            return McpResource.errorJson(
                    Constant.messages.getString(
                            "mcp.resource.alertinstances.error.missingalertref"));
        }
        if (start < 0) {
            return McpResource.errorJson(
                    Constant.messages.getString(
                            "mcp.resource.alertinstances.error.negativestart"));
        }

        ExtensionAlert extAlert =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionAlert.class);
        if (extAlert == null) {
            return "[]";
        }

        // Resolve effective page size, honouring AlertParam.getMaximumInstances() when tighter.
        int configuredMax = extAlert.getAlertParam().getMaximumInstances(); // 0 = unlimited
        int effectivePageSize;
        if (requestedCount <= 0) {
            effectivePageSize =
                    (configuredMax > 0 && configuredMax < DEFAULT_PAGE_SIZE)
                            ? configuredMax
                            : DEFAULT_PAGE_SIZE;
        } else {
            effectivePageSize = Math.min(requestedCount, MAX_PAGE_SIZE);
            if (configuredMax > 0) {
                effectivePageSize = Math.min(effectivePageSize, configuredMax);
            }
        }

        ExtensionHistory extensionHistory =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionHistory.class);

        try {
            // This is nasty, but there are no better options in the 2.17 core :(
            TableAlert tableAlert = Model.getSingleton().getDb().getTableAlert();
            Vector<Integer> alertIds = tableAlert.getAlertList();

            ArrayNode instances = OBJECT_MAPPER.createArrayNode();
            int totalCount = 0; // full match count across all pages
            int collected = 0;  // items added to this page

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

                int matchIndex = totalCount;
                totalCount++;

                // Skip items before the requested start offset.
                if (matchIndex < start) {
                    continue;
                }

                // Collect up to effectivePageSize items for this page.
                if (collected < effectivePageSize) {
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
                                    ? extensionHistory.getHistoryReference(
                                            recAlert.getHistoryId())
                                    : null;
                    if (historyReference != null) {
                        node.put(
                                "historyRef",
                                "zap://history/" + historyReference.getHistoryId());
                    }
                    instances.add(node);
                    collected++;
                }
                // Keep scanning past page window to get accurate totalCount.
            }

            int nextStart = start + collected;
            boolean hasMore = nextStart < totalCount;

            ObjectNode response = OBJECT_MAPPER.createObjectNode();
            response.put("alertRef", alertRef);
            response.put("totalCount", totalCount);
            response.put("start", start);
            response.put("returnedCount", collected);
            response.put("truncated", hasMore);
            if (hasMore) {
                response.put(
                        "nextPageUri",
                        URI_PREFIX
                                + alertRef
                                + "?start="
                                + nextStart
                                + "&count="
                                + effectivePageSize);
                response.put(
                        "note",
                        Constant.messages.getString(
                                "mcp.resource.alertinstances.truncated.note",
                                collected,
                                totalCount));
            }
            response.set("instances", instances);
            return response.toString();

        } catch (DatabaseException e) {
            LOGGER.error(e.getMessage(), e);
            return McpResource.errorJson(
                    Constant.messages.getString("mcp.resource.error.internal"));
        }
    }
}
