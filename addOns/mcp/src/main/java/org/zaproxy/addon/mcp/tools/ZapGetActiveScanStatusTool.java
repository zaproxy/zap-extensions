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

/** MCP tool that returns the active scan plan status. */
public class ZapGetActiveScanStatusTool implements McpTool {

    @Override
    public String getName() {
        return "zap_get_active_scan_status";
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("mcp.tool.getactivescanstatus.desc");
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
                        Constant.messages.getString("mcp.tool.getactivescanstatus.param.scanid"));
        schema.putArray("required").add("scan_id");
        return schema;
    }

    @Override
    public McpToolResult execute(JsonNode arguments) throws McpToolException {
        JsonNode scanIdNode = arguments != null ? arguments.get("scan_id") : null;
        if (scanIdNode == null || scanIdNode.isNull() || !scanIdNode.isTextual()) {
            throw new McpToolException(
                    Constant.messages.getString(
                            "mcp.tool.getactivescanstatus.error.missingscanid"));
        }
        String scanId = scanIdNode.asText().trim();
        if (scanId.isEmpty()) {
            throw new McpToolException(
                    Constant.messages.getString(
                            "mcp.tool.getactivescanstatus.error.missingscanid"));
        }

        ExtensionAutomation extAutomation =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionAutomation.class);

        int progress = extAutomation.getScanProgress(scanId);
        if (progress < 0) {
            throw new McpToolException(
                    Constant.messages.getString(
                            "mcp.tool.getactivescanstatus.error.scanidnotfound", scanId));
        }

        String status =
                progress >= 100
                        ? Constant.messages.getString("mcp.tool.getactivescanstatus.stopped")
                        : Constant.messages.getString("mcp.tool.getactivescanstatus.running");
        String result =
                Constant.messages.getString("mcp.tool.getactivescanstatus.status", scanId, status)
                        + "\n"
                        + Constant.messages.getString(
                                "mcp.tool.getactivescanstatus.progress", progress);

        return McpToolResult.success(result);
    }
}
