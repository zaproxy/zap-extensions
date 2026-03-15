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
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Enumeration;
import java.util.List;
import javax.swing.tree.TreeNode;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.VariantMultipartFormParameters;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteMap;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.mcp.McpResource;
import org.zaproxy.zap.model.NameValuePair;

/**
 * MCP resource that provides the ZAP sites tree in the format defined at
 * https://www.zaproxy.org/docs/desktop/addons/import-export/sitestreeformat/
 */
public class SitesTreeResource implements McpResource {

    private static final String ROOT_NODE_NAME = "Sites";
    private static final String URI = "zap://sites-tree";

    @Override
    public String getUri() {
        return URI;
    }

    @Override
    public String getName() {
        return "sites-tree";
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("mcp.resource.sitestree.desc");
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
        if (root == null) {
            return "[]";
        }
        ArrayNode array = OBJECT_MAPPER.createArrayNode();
        array.add(toJsonNode(root));
        return array.toString();
    }

    private ObjectNode toJsonNode(SiteNode siteNode) {
        ObjectNode node = OBJECT_MAPPER.createObjectNode();
        node.put("node", siteNode.getParent() == null ? ROOT_NODE_NAME : siteNode.toString());

        HistoryReference href = siteNode.getHistoryReference();
        if (href != null) {
            node.put("url", href.getURI().toString());
            node.put("method", href.getMethod());

            if (href.getStatusCode() > 0) {
                node.put(
                        "responseLength",
                        href.getResponseHeaderLength() + href.getResponseBodyLength() + 2);
                node.put("statusCode", href.getStatusCode());
            }

            if (HttpRequestHeader.POST.equals(href.getMethod())) {
                try {
                    var msg = href.getHttpMessage();
                    if (msg.getRequestHeader()
                            .hasContentType(HttpHeader.FORM_MULTIPART_CONTENT_TYPE)) {
                        VariantMultipartFormParameters mfp = new VariantMultipartFormParameters();
                        mfp.setMessage(msg);
                        StringBuilder sb = new StringBuilder();
                        mfp.getParamList().stream()
                                .filter(p -> isRelevantMultipartParam(p.getType()))
                                .map(org.parosproxy.paros.core.scanner.NameValuePair::getName)
                                .forEach(
                                        name -> {
                                            if (!sb.isEmpty()) {
                                                sb.append('&');
                                            }
                                            sb.append(
                                                    URLEncoder.encode(
                                                            name, StandardCharsets.UTF_8));
                                        });
                        node.put("data", sb.toString());
                    } else {
                        List<NameValuePair> params =
                                Model.getSingleton()
                                        .getSession()
                                        .getParameters(msg, HtmlParameter.Type.form);
                        StringBuilder sb = new StringBuilder();
                        params.forEach(
                                nvp -> {
                                    if (!sb.isEmpty()) {
                                        sb.append('&');
                                    }
                                    sb.append(
                                            URLEncoder.encode(
                                                    nvp.getName(), StandardCharsets.UTF_8));
                                    sb.append('=');
                                });
                        node.put("data", sb.toString());
                    }
                } catch (DatabaseException | HttpMalformedHeaderException e) {
                    // Omit data on error
                }
            }
        }

        if (siteNode.getChildCount() > 0) {
            ArrayNode children = OBJECT_MAPPER.createArrayNode();
            for (Enumeration<TreeNode> e = siteNode.children(); e.hasMoreElements(); ) {
                children.add(toJsonNode((SiteNode) e.nextElement()));
            }
            node.set("children", children);
        }

        return node;
    }

    private static boolean isRelevantMultipartParam(int type) {
        return type == org.parosproxy.paros.core.scanner.NameValuePair.TYPE_MULTIPART_DATA_FILE_NAME
                || type
                        == org.parosproxy.paros.core.scanner.NameValuePair
                                .TYPE_MULTIPART_DATA_PARAM;
    }
}
