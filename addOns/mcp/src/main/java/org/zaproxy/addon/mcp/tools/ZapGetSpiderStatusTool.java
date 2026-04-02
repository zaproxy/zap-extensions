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

import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.addon.mcp.McpTool;
import org.zaproxy.addon.mcp.McpToolException;
import org.zaproxy.addon.mcp.McpToolResult;

/** MCP tool that returns the spider plan status. */
public class ZapGetSpiderStatusTool implements McpTool {

    private static final Logger LOGGER = LogManager.getLogger(ZapGetSpiderStatusTool.class);

    @Override
    public String getName() {
        return "zap_get_spider_status";
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("mcp.tool.getspiderstatus.desc");
    }

    @Override
    public InputSchema getInputSchema() {
        return new InputSchema(
                Map.of(
                        "scan_id",
                        InputSchema.PropertyDef.ofString(
                                Constant.messages.getString(
                                        "mcp.tool.getspiderstatus.param.scanid"))),
                List.of("scan_id"));
    }

    @Override
    public McpToolResult execute(ToolArguments arguments) throws McpToolException {
        String scanId = arguments.getString("scan_id");
        if (scanId == null || scanId.isBlank()) {
            throw new McpToolException(
                    Constant.messages.getString("mcp.tool.getspiderstatus.error.missingscanid"));
        }
        scanId = scanId.trim();

        StringBuilder result = new StringBuilder();

        try {
            ExtensionAutomation extAutomation =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionAutomation.class);

            int progress = extAutomation.getLongRunningJobProgress(scanId);
            if (progress < 0) {
                throw new McpToolException(
                        Constant.messages.getString(
                                "mcp.tool.getspiderstatus.error.scanidnotfound", scanId));
            }

            String status =
                    progress >= 100
                            ? Constant.messages.getString("mcp.tool.getspiderstatus.stopped")
                            : Constant.messages.getString("mcp.tool.getspiderstatus.running");
            result.append(
                    Constant.messages.getString("mcp.tool.getspiderstatus.status", scanId, status));
            result.append("\n")
                    .append(
                            Constant.messages.getString(
                                    "mcp.tool.getspiderstatus.progress", progress));
        } catch (McpToolException e) {
            throw e;
        } catch (Exception e) {
            LOGGER.warn("Failed to get spider status", e);
            throw new McpToolException(
                    Constant.messages.getString(
                            "mcp.tool.getspiderstatus.error.failed",
                            Constant.messages.getString("mcp.tool.error.unknown")));
        }

        return McpToolResult.success(result.toString());
    }
}
