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

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.dev.TestDirectory;
import org.zaproxy.addon.dev.TestPage;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

/**
 * The page of a {@link ShadowDomCase}, the shared template with the configuration of the case,
 * which the script uses to create the shadow roots.
 */
public class ShadowDomPage extends TestPage {

    static final String TEMPLATE = "page.html";

    public ShadowDomPage(TestProxyServer server) {
        super(server, TestDirectory.INDEX_PAGE);
    }

    @Override
    public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
        ShadowDomDir dir = getParent();
        ShadowDomDir.setHtmlResponse(
                msg,
                createBody(
                        getServer().getTextFile(dir.getParent(), TEMPLATE),
                        dir.getShadowDomCase()));
    }

    static String createBody(String template, ShadowDomCase shadowDomCase) {
        return template.replace("<!-- CASE -->", shadowDomCase.getDirName())
                .replace("<!-- CASE_CONFIG -->", shadowDomCase.toJson());
    }

    @Override
    public ShadowDomDir getParent() {
        return (ShadowDomDir) super.getParent();
    }
}
