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
import java.util.Map;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.addon.mcp.McpResource;

/** MCP resource that provides scan progress for all long-running automation jobs. */
public class ScanStatusResource implements McpResource {

    private static final String URI = "zap://scan-status";

    @Override
    public String getUri() {
        return URI;
    }

    @Override
    public String getName() {
        return "scan-status";
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("mcp.resource.scanstatus.desc");
    }

    @Override
    public ObjectNode toListEntry() {
        ObjectNode node = OBJECT_MAPPER.createObjectNode();
        node.put("uri", getUri());
        node.put("name", getName());
        node.put("description", getDescription());
        node.put("mimeType", getMimeType());
        return node;
    }

    @Override
    public String readContent() {
        ExtensionAutomation extAutomation =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionAutomation.class);
        Map<String, Integer> allProgress = extAutomation.getAllScanProgress();

        ArrayNode array = OBJECT_MAPPER.createArrayNode();
        for (Map.Entry<String, Integer> entry : allProgress.entrySet()) {
            ObjectNode node = OBJECT_MAPPER.createObjectNode();
            node.put("id", entry.getKey());
            node.put("progress", entry.getValue());
            array.add(node);
        }
        return array.toString();
    }
}
