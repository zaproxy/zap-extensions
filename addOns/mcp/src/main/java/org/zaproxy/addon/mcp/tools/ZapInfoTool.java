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
import org.zaproxy.addon.mcp.McpTool;
import org.zaproxy.addon.mcp.McpToolException;
import org.zaproxy.addon.mcp.McpToolResult;

/** MCP tool that returns basic ZAP information. */
public class ZapInfoTool implements McpTool {

    @Override
    public String getName() {
        return "zap_info";
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("mcp.tool.info.desc");
    }

    @Override
    public InputSchema getInputSchema() {
        return new InputSchema(Map.of(), List.of());
    }

    @Override
    public McpToolResult execute(ToolArguments arguments) throws McpToolException {
        return McpToolResult.success(Constant.PROGRAM_NAME + " - " + Constant.PROGRAM_VERSION);
    }
}
