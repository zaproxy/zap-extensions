/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.dev.auth.passwordNewPage;

import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.dev.TestPage;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

public class PasswordNewPageNextPage extends TestPage {

    private static final Logger LOGGER = LogManager.getLogger(PasswordNewPageNextPage.class);

    public PasswordNewPageNextPage(TestProxyServer server) {
        super(server, "next");
    }

    @Override
    public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
        String user = "INVALID";
        Optional<HtmlParameter> userParam =
                msg.getFormParams().stream().filter(p -> p.getName().equals("user")).findFirst();
        if (userParam.isPresent()) {
            user = userParam.get().getValue();
        }
        String body = this.getServer().getTextFile(this.getParent(), "next.html");
        body = body.replace("<!-- USER -->", user);
        msg.setResponseBody(body);
        try {
            msg.setResponseHeader(
                    TestProxyServer.getDefaultResponseHeader(
                            "text/html", msg.getResponseBody().length()));
        } catch (HttpMalformedHeaderException e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    @Override
    public PasswordNewPageDir getParent() {
        return (PasswordNewPageDir) super.getParent();
    }
}
