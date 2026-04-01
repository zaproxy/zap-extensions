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

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.zaproxy.addon.mcp.McpTool;
import org.zaproxy.addon.mcp.McpToolException;
import org.zaproxy.addon.mcp.McpToolResult;
import org.zaproxy.zap.model.Context;

/**
 * MCP tool that creates a ZAP context with the given name, URL and optional include/exclude
 * regexes.
 */
public class ZapCreateContextTool implements McpTool {

    private static final Logger LOGGER = LogManager.getLogger(ZapCreateContextTool.class);

    @Override
    public String getName() {
        return "zap_create_context";
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("mcp.tool.createcontext.desc");
    }

    @Override
    public InputSchema getInputSchema() {
        Map<String, InputSchema.PropertyDef> properties = new LinkedHashMap<>();
        properties.put(
                "name",
                InputSchema.PropertyDef.ofString(
                        Constant.messages.getString("mcp.tool.createcontext.param.name")));
        properties.put(
                "url",
                InputSchema.PropertyDef.ofString(
                        Constant.messages.getString("mcp.tool.createcontext.param.url")));
        properties.put(
                "include_regexes",
                InputSchema.PropertyDef.ofStringArray(
                        Constant.messages.getString(
                                "mcp.tool.createcontext.param.includeregexes")));
        properties.put(
                "exclude_regexes",
                InputSchema.PropertyDef.ofStringArray(
                        Constant.messages.getString(
                                "mcp.tool.createcontext.param.excluderegexes")));
        return new InputSchema(properties, List.of("name", "url"));
    }

    @Override
    public McpToolResult execute(ToolArguments arguments) throws McpToolException {
        String name = arguments.getString("name");
        if (name == null || name.isBlank()) {
            throw new McpToolException(
                    Constant.messages.getString("mcp.tool.createcontext.error.missingname"));
        }
        name = name.trim();

        String url = arguments.getString("url");
        if (url == null || url.isBlank()) {
            throw new McpToolException(
                    Constant.messages.getString("mcp.tool.createcontext.error.missingurl"));
        }
        url = url.trim();

        try {
            new URI(url);
        } catch (Exception e) {
            throw new McpToolException(
                    Constant.messages.getString("mcp.tool.createcontext.error.invalidurl", url), e);
        }

        List<String> includeRegexes = arguments.getList("include_regexes");
        List<String> excludeRegexes = arguments.getList("exclude_regexes");

        String nameFinal = name;
        String urlFinal = url;

        try {
            Session session = Model.getSingleton().getSession();
            Context existing = session.getContext(nameFinal);
            if (existing != null) {
                session.deleteContext(existing);
            }
            Context context = session.getNewContext(nameFinal);

            context.addIncludeInContextRegex(urlFinal + ".*");
            for (String regex : includeRegexes) {
                if (regex != null && !regex.isBlank()) {
                    context.addIncludeInContextRegex(regex.trim());
                }
            }
            for (String regex : excludeRegexes) {
                if (regex != null && !regex.isBlank()) {
                    context.addExcludeFromContextRegex(regex.trim());
                }
            }
            session.saveContext(context);
        } catch (Exception e) {
            LOGGER.warn("Failed to create context", e);
            throw new McpToolException(
                    Constant.messages.getString("mcp.tool.createcontext.error.failed"));
        }

        return McpToolResult.success(
                Constant.messages.getString("mcp.tool.createcontext.success", name));
    }
}
