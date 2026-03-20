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
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.addon.mcp.McpTool;
import org.zaproxy.addon.mcp.McpToolException;
import org.zaproxy.addon.mcp.McpToolResult;

/** MCP tool that returns the AJAX spider plan status. */
public class ZapGetAjaxSpiderStatusTool implements McpTool {

    @Override
    public String getName() {
        return "zap_get_ajax_spider_status";
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("mcp.tool.getajaxspiderstatus.desc");
    }

    @Override
    public InputSchema getInputSchema() {
        return new InputSchema(
                Map.of(
                        "scan_id",
                        InputSchema.PropertyDef.ofString(
                                Constant.messages.getString(
                                        "mcp.tool.getajaxspiderstatus.param.scanid"))),
                List.of("scan_id"));
    }

    @Override
    public McpToolResult execute(ToolArguments arguments) throws McpToolException {
        String scanId = arguments.getString("scan_id");
        if (scanId == null || scanId.isBlank()) {
            throw new McpToolException(
                    Constant.messages.getString(
                            "mcp.tool.getajaxspiderstatus.error.missingscanid"));
        }
        scanId = scanId.trim();

        ExtensionAutomation extAutomation =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionAutomation.class);

        int progress = extAutomation.getLongRunningJobProgress(scanId);
        if (progress < 0) {
            throw new McpToolException(
                    Constant.messages.getString(
                            "mcp.tool.getajaxspiderstatus.error.scanidnotfound", scanId));
        }

        String status =
                progress >= 100
                        ? Constant.messages.getString("mcp.tool.getajaxspiderstatus.stopped")
                        : Constant.messages.getString("mcp.tool.getajaxspiderstatus.running");
        String result =
                Constant.messages.getString("mcp.tool.getajaxspiderstatus.status", scanId, status)
                        + "\n"
                        + Constant.messages.getString(
                                "mcp.tool.getajaxspiderstatus.progress", progress);

        return McpToolResult.success(result);
    }
}
