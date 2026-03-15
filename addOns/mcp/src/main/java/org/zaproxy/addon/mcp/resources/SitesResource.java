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
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteMap;
import org.parosproxy.paros.model.SiteNode;
import org.zaproxy.addon.mcp.McpResource;

/** MCP resource that provides the ZAP sites tree (top-level nodes). */
public class SitesResource implements McpResource {

    private static final String URI = "zap://sites";

    @Override
    public String getUri() {
        return URI;
    }

    @Override
    public String getName() {
        return "sites";
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("mcp.resource.sites.desc");
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
        SiteMap siteMap = Model.getSingleton().getSession().getSiteTree();
        SiteNode root = siteMap.getRoot();
        ArrayNode array = OBJECT_MAPPER.createArrayNode();

        if (root != null && root.getChildCount() > 0) {
            SiteNode child = (SiteNode) root.getFirstChild();
            while (child != null) {
                array.add(child.getHierarchicNodeName());
                child = (SiteNode) child.getNextSibling();
            }
        }
        return array.toString();
    }
}
