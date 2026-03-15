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

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.zaproxy.addon.mcp.McpResource;

/** MCP resource that provides ZAP proxy history. */
public class HistoryResource implements McpResource {

    private static final String URI = "zap://history";

    @Override
    public String getUri() {
        return URI;
    }

    @Override
    public String getName() {
        return "history";
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("mcp.resource.history.desc");
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
        ExtensionHistory extHistory =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionHistory.class);
        ObjectNode summary = OBJECT_MAPPER.createObjectNode();
        summary.put("count", extHistory.getLastHistoryId());
        summary.put("note", Constant.messages.getString("mcp.resource.history.summary.note"));
        return summary.toString();
    }
}
