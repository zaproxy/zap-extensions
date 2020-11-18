/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.zap.extension.soap;

import net.htmlparser.jericho.Source;
import org.apache.log4j.Logger;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.spider.parser.SpiderParser;

public class WSDLSpider extends SpiderParser {

    private final WSDLCustomParser parser;

    private static final Logger LOG = Logger.getLogger(WSDLSpider.class);

    public WSDLSpider(WSDLCustomParser parser) {
        this.parser = parser;
    }

    @Override
    public boolean parseResource(HttpMessage message, Source source, int depth) {
        return parseResourceWSDL(message, true);
    }

    public boolean parseResourceWSDL(HttpMessage message, boolean sendRequests) {
        if (message == null) return false;
        /* Only applied to wsdl files. */
        LOG.debug("WSDL custom spider called.");
        if (!canParseResource(message)) return false;

        /* New WSDL detected. */
        LOG.info("WSDL spider has detected a new resource");
        String content = getContentFromMessage(message);
        /* Calls extension to parse it and to fill the sites tree. */
        parser.extContentWSDLImport(content, sendRequests);
        return true;
    }

    public boolean canParseResource(final HttpMessage message) {
        try {
            // Get the context (base url)
            String baseURL = getURIfromMessage(message);
            String contentType = message.getResponseHeader().getHeader(HttpHeader.CONTENT_TYPE);
            if (baseURL.endsWith(".wsdl")
                    || contentType.equals("text/xml")
                    || contentType.equals("application/wsdl+xml")) {
                String content = message.getResponseBody().toString();
                if (parser.canBeWSDLparsed(content)) return true;
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Content is not wsdl: " + content);
                }
            }
        } catch (Exception e) {
            return false;
        }
        return false;
    }

    private String getURIfromMessage(final HttpMessage message) {
        if (message == null) {
            return "";
        } else {
            try {
                return message.getRequestHeader().getURI().toString();
            } catch (Exception e) {
                return "";
            }
        }
    }

    private String getContentFromMessage(final HttpMessage message) {
        if (message == null) {
            return "";
        } else {
            return message.getResponseBody().toString().trim();
        }
    }

    @Override
    public boolean canParseResource(HttpMessage message, String path, boolean wasAlreadyConsumed) {
        // Get the context (base url)
        String baseURL = getURIfromMessage(message);
        return baseURL.endsWith(".wsdl");
    }
}
