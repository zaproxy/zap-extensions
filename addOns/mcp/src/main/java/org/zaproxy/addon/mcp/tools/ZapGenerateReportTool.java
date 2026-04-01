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

import java.io.File;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.addon.mcp.McpTool;
import org.zaproxy.addon.mcp.McpToolException;
import org.zaproxy.addon.mcp.McpToolResult;
import org.zaproxy.addon.reports.ExtensionReports;

/** MCP tool that generates a ZAP report. */
public class ZapGenerateReportTool implements McpTool {

    private static final Logger LOGGER = LogManager.getLogger(ZapGenerateReportTool.class);

    @Override
    public String getName() {
        return "zap_generate_report";
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("mcp.tool.generatereport.desc");
    }

    @Override
    public InputSchema getInputSchema() {
        Map<String, InputSchema.PropertyDef> properties = new LinkedHashMap<>();
        properties.put(
                "file_path",
                InputSchema.PropertyDef.ofString(
                        Constant.messages.getString("mcp.tool.generatereport.param.filepath")));
        properties.put(
                "template",
                InputSchema.PropertyDef.ofString(
                        Constant.messages.getString("mcp.tool.generatereport.param.template")));
        properties.put(
                "title",
                InputSchema.PropertyDef.ofString(
                        Constant.messages.getString("mcp.tool.generatereport.param.title")));
        return new InputSchema(properties, List.of("file_path", "template"));
    }

    @Override
    public McpToolResult execute(ToolArguments arguments) throws McpToolException {
        ExtensionReports extReports =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionReports.class);

        String filePath = arguments.getString("file_path");
        if (filePath == null || filePath.isBlank()) {
            throw new McpToolException(
                    Constant.messages.getString("mcp.tool.generatereport.error.missingfilepath"));
        }
        filePath = filePath.trim();

        String template = arguments.getString("template");
        if (template == null || template.isBlank()) {
            throw new McpToolException(
                    Constant.messages.getString("mcp.tool.generatereport.error.missingtemplate"));
        }
        template = template.trim();

        String title = arguments.getString("title");
        if (title == null) {
            title = "";
        } else {
            title = title.trim();
        }

        try {
            File report = extReports.generateReport(template, filePath, title, "", false);
            return McpToolResult.success(
                    Constant.messages.getString(
                            "mcp.tool.generatereport.success", report.getAbsolutePath()));
        } catch (IllegalArgumentException e) {
            throw new McpToolException(
                    Constant.messages.getString(
                            "mcp.tool.generatereport.error.unknowntemplate", template));
        } catch (Exception e) {
            LOGGER.error("Failed to generate report", e);
            throw new McpToolException(
                    Constant.messages.getString("mcp.tool.generatereport.error.failed"));
        }
    }
}
