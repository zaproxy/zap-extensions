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
package org.zaproxy.addon.mcp.spider;

import java.util.Locale;
import java.util.function.Supplier;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.mcp.importer.McpImporter;
import org.zaproxy.addon.mcp.importer.McpImporter.ImportConfig;
import org.zaproxy.addon.mcp.importer.McpImporter.ImportResults;
import org.zaproxy.addon.spider.parser.ParseContext;
import org.zaproxy.addon.spider.parser.SpiderParser;

/**
 * Spider parser that recognises responses indicative of an MCP endpoint and runs the {@link
 * McpImporter} against the same URL.
 */
public class McpSpider extends SpiderParser {

    private static final Logger LOGGER = LogManager.getLogger(McpSpider.class);

    private final Supplier<McpImporter> importerSupplier;

    public McpSpider() {
        this(() -> new McpImporter(HttpSender.SPIDER_INITIATOR));
    }

    McpSpider(Supplier<McpImporter> importerSupplier) {
        this.importerSupplier = importerSupplier;
    }

    @Override
    public boolean canParseResource(ParseContext ctx, boolean wasAlreadyConsumed) {
        HttpMessage message = ctx.getHttpMessage();
        try {
            if (message.getResponseHeader().getHeader("MCP-Protocol-Version") != null) {
                return true;
            }
            String contentType = message.getResponseHeader().getHeader(HttpHeader.CONTENT_TYPE);
            if (contentType == null) {
                return false;
            }
            contentType = contentType.toLowerCase(Locale.ROOT);
            String body =
                    StringUtils.left(message.getResponseBody().toString(), 500)
                            .toLowerCase(Locale.ROOT);

            if (contentType.contains("text/event-stream")) {
                return body.contains("jsonrpc")
                        || body.contains("endpoint")
                        || body.contains("mcp");
            }
            if (contentType.contains("json")) {
                return body.contains("\"protocolversion\"")
                        || (body.contains("\"jsonrpc\"")
                                && (body.contains("tools/list")
                                        || body.contains("resources/list")
                                        || body.contains("prompts/list")
                                        || body.contains("mcp")));
            }
        } catch (Exception e) {
            LOGGER.warn(
                    "Failed to parse {}: {}",
                    message.getRequestHeader().getURI(),
                    e.getMessage(),
                    e);
            return false;
        }
        LOGGER.debug("Can't parse {}", message.getRequestHeader().getURI());
        return false;
    }

    @Override
    public boolean parseResource(ParseContext ctx) {
        HttpMessage message = ctx.getHttpMessage();
        String url = message.getRequestHeader().getURI().toString();
        try {
            ImportResults results =
                    importerSupplier.get().importServer(new ImportConfig(url, null));
            if (results.errors().isEmpty() && results.requestCount() > 1) {
                LOGGER.info(
                        "Imported MCP server at {} ({} requests imported)",
                        url,
                        results.requestCount());
            }
        } catch (Exception e) {
            LOGGER.warn("MCP import at {} failed: {}", url, e.getMessage());
        }
        return false;
    }
}
