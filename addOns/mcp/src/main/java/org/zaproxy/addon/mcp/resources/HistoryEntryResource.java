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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.mcp.McpResource;

/** MCP resource that returns the full HTTP request and response for a given history ID. */
public class HistoryEntryResource implements McpResource {

    private static final Logger LOGGER = LogManager.getLogger(HistoryEntryResource.class);
    private static final String URI_PREFIX = "zap://history/";

    @Override
    public String getUri() {
        return URI_PREFIX;
    }

    @Override
    public String getName() {
        return "history-entry";
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("mcp.resource.historyentry.desc");
    }

    @Override
    public String getUriTemplate() {
        return URI_PREFIX + "{id}";
    }

    @Override
    public String readContent() {
        return "{}";
    }

    @Override
    public String readContent(String uri) {
        if (!uri.startsWith(URI_PREFIX)) {
            return McpResource.errorJson(
                    Constant.messages.getString("mcp.resource.historyentry.error.invaliduri"));
        }
        String idPart = uri.substring(URI_PREFIX.length()).trim();
        if (idPart.isEmpty()) {
            return McpResource.errorJson(
                    Constant.messages.getString("mcp.resource.historyentry.error.missingid"));
        }
        int id;
        try {
            id = Integer.parseInt(idPart);
        } catch (NumberFormatException e) {
            return McpResource.errorJson(
                    Constant.messages.getString("mcp.resource.historyentry.error.invalidid"));
        }

        try {
            ExtensionHistory extHist =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionHistory.class);

            HistoryReference href = extHist.getHistoryReference(id);
            if (href == null) {
                return McpResource.errorJson(
                        Constant.messages.getString(
                                "mcp.resource.historyentry.error.notfound", id));
            }
            HttpMessage msg = href.getHttpMessage();
            ObjectNode result = OBJECT_MAPPER.createObjectNode();
            result.put("requestHeader", msg.getRequestHeader().toString());
            result.put("requestBody", msg.getRequestBody().toString());
            result.put("responseHeader", msg.getResponseHeader().toString());
            result.put("responseBody", msg.getResponseBody().toString());
            return result.toString();
        } catch (HttpMalformedHeaderException | DatabaseException e) {
            LOGGER.debug("Could not read history id {}: {}", id, e.getMessage());
            return McpResource.errorJson(
                    Constant.messages.getString("mcp.resource.historyentry.error.readfailed", id));
        }
    }
}
