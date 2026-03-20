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
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.addon.mcp.McpResource;
import org.zaproxy.addon.reports.ExtensionReports;
import org.zaproxy.addon.reports.Template;

/** MCP resource that lists the available report templates. */
public class ReportTemplatesResource implements McpResource {

    private static final String URI = "zap://report-templates";

    @Override
    public String getUri() {
        return URI;
    }

    @Override
    public String getName() {
        return "report-templates";
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("mcp.resource.reporttemplates.desc");
    }

    @Override
    public String readContent() {
        ExtensionReports extReports =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionReports.class);
        ArrayNode array = OBJECT_MAPPER.createArrayNode();
        for (Template template : extReports.getTemplates()) {
            ObjectNode node = OBJECT_MAPPER.createObjectNode();
            node.put("configName", template.getConfigName());
            node.put("displayName", template.getDisplayName());
            node.put("extension", template.getExtension());
            array.add(node);
        }
        return array.toString();
    }
}
