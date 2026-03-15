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
import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.mcp.McpResource;
import org.zaproxy.zap.model.Context;

/** MCP resource that lists all configured ZAP contexts. */
public class ContextsResource implements McpResource {

    private static final String URI = "zap://contexts";

    @Override
    public String getUri() {
        return URI;
    }

    @Override
    public String getName() {
        return "contexts";
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("mcp.resource.contexts.desc");
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
        List<Context> contexts = Model.getSingleton().getSession().getContexts();
        ArrayNode array = OBJECT_MAPPER.createArrayNode();
        for (Context context : contexts) {
            ObjectNode node = OBJECT_MAPPER.createObjectNode();
            node.put("id", context.getId());
            node.put("name", context.getName());
            ArrayNode includeArray = OBJECT_MAPPER.createArrayNode();
            for (String regex : context.getIncludeInContextRegexs()) {
                includeArray.add(regex);
            }
            node.set("includeRegexes", includeArray);
            ArrayNode excludeArray = OBJECT_MAPPER.createArrayNode();
            for (String regex : context.getExcludeFromContextRegexs()) {
                excludeArray.add(regex);
            }
            node.set("excludeRegexes", excludeArray);
            array.add(node);
        }
        return array.toString();
    }
}
