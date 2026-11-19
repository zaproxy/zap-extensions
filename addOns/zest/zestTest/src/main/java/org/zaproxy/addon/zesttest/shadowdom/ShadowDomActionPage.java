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
package org.zaproxy.addon.zesttest.shadowdom;

import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.dev.TestPage;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

/** The target of an element in the shadow roots, reached when the element is acted on. */
public class ShadowDomActionPage extends TestPage {

    static final String VALUE_PARAM = "value";

    private final ShadowDomAction action;

    public ShadowDomActionPage(TestProxyServer server, ShadowDomAction action) {
        super(server, action.getPageName());
        this.action = action;
    }

    @Override
    public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
        String value =
                msg.getUrlParams().stream()
                        .filter(p -> VALUE_PARAM.equals(p.getName()))
                        .findFirst()
                        .map(HtmlParameter::getValue)
                        .orElse(null);
        ShadowDomDir.setHtmlResponse(
                msg, createBody(getParent().getShadowDomCase(), action, value));
    }

    static String createBody(ShadowDomCase shadowDomCase, ShadowDomAction action, String value) {
        StringBuilder sb = new StringBuilder();
        sb.append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n")
                .append("<title>ZAP Test Server - Shadow DOM</title>\n")
                .append("<link href=\"/tutorial.css\" rel=\"stylesheet\" type=\"text/css\" />\n")
                .append("</head>\n<body>\n<div class=\"roundContainer\">\n<h1>Shadow DOM</h1>\n")
                .append("<p id=\"result\">")
                .append(shadowDomCase.getDirName())
                .append(' ')
                .append(action.getPageName())
                .append(" OK</p>\n");
        if (value != null) {
            sb.append("<p id=\"value\">").append(escapeHtml(value)).append("</p>\n");
        }
        sb.append("<p><a href=\"./\">Back</a></p>\n</div>\n</body>\n</html>\n");
        return sb.toString();
    }

    private static String escapeHtml(String value) {
        return value.replace("&", "&amp;")
                .replace("\"", "&quot;")
                .replace("<", "&lt;")
                .replace(">", "&gt;");
    }

    @Override
    public ShadowDomDir getParent() {
        return (ShadowDomDir) super.getParent();
    }
}
