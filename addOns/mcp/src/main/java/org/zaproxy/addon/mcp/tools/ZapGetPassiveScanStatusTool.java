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
import org.zaproxy.addon.mcp.McpTool;
import org.zaproxy.addon.mcp.McpToolException;
import org.zaproxy.addon.mcp.McpToolResult;
import org.zaproxy.addon.pscan.ExtensionPassiveScan2;

/** MCP tool that returns the passive scan queue status. */
public class ZapGetPassiveScanStatusTool implements McpTool {

    @Override
    public String getName() {
        return "zap_get_passive_scan_status";
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("mcp.tool.getpassivescanstatus.desc");
    }

    @Override
    public InputSchema getInputSchema() {
        return new InputSchema(Map.of(), List.of());
    }

    @Override
    public McpToolResult execute(ToolArguments arguments) throws McpToolException {
        ExtensionPassiveScan2 extPscan =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionPassiveScan2.class);
        int recordsToScan = extPscan.getRecordsToScan();
        String status =
                recordsToScan == 0
                        ? Constant.messages.getString("mcp.tool.getpassivescanstatus.idle")
                        : Constant.messages.getString("mcp.tool.getpassivescanstatus.running");
        String result =
                Constant.messages.getString("mcp.tool.getpassivescanstatus.status", status)
                        + "\n"
                        + Constant.messages.getString(
                                "mcp.tool.getpassivescanstatus.records", recordsToScan);
        return McpToolResult.success(result);
    }
}
