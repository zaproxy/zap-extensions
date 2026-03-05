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
package org.zaproxy.addon.mcp.tools;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.addon.mcp.McpTool;
import org.zaproxy.addon.mcp.McpToolException;
import org.zaproxy.addon.mcp.McpToolResult;

/** MCP tool that stops the AJAX spider plan if it is running. */
public class ZapStopAjaxSpiderTool implements McpTool {

    @Override
    public String getName() {
        return "zap_stop_ajax_spider";
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("mcp.tool.stopajaxspider.desc");
    }

    @Override
    public ObjectNode getInputSchema() {
        ObjectNode schema = OBJECT_MAPPER.createObjectNode();
        schema.put("type", "object");
        ObjectNode properties = schema.putObject("properties");
        properties
                .putObject("scan_id")
                .put("type", "string")
                .put(
                        "description",
                        Constant.messages.getString("mcp.tool.stopajaxspider.param.scanid"));
        schema.putArray("required").add("scan_id");
        return schema;
    }

    @Override
    public McpToolResult execute(JsonNode arguments) throws McpToolException {
        JsonNode scanIdNode = arguments != null ? arguments.get("scan_id") : null;
        if (scanIdNode == null || scanIdNode.isNull() || !scanIdNode.isTextual()) {
            throw new McpToolException(
                    Constant.messages.getString("mcp.tool.stopajaxspider.error.missingscanid"));
        }
        String scanId = scanIdNode.asText().trim();
        if (scanId.isEmpty()) {
            throw new McpToolException(
                    Constant.messages.getString("mcp.tool.stopajaxspider.error.missingscanid"));
        }

        ExtensionAutomation extAutomation =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionAutomation.class);

        if (extAutomation.getScanProgress(scanId) < 0) {
            throw new McpToolException(
                    Constant.messages.getString(
                            "mcp.tool.stopajaxspider.error.scanidnotfound", scanId));
        }

        extAutomation.stopLongRunningJob(scanId);

        return McpToolResult.success(
                Constant.messages.getString("mcp.tool.stopajaxspider.success"));
    }
}
