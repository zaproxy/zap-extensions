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
package org.zaproxy.addon.dev.auth.simpleJson;

import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.dev.TestPage;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

public class SimpleJsonLoginPage extends TestPage {

    public SimpleJsonLoginPage(TestProxyServer server) {
        super(server, "login");
    }

    @Override
    public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
        String username = null;
        String password = null;

        for (HtmlParameter p : msg.getFormParams()) {
            if (p.getName().equals("user")) {
                username = p.getValue();
            } else if (p.getName().equals("password")) {
                password = p.getValue();
            }
        }

        if ("test@test.com".equals(username) && "password123".equals(password)) {
            this.getServer().handleFile(getParent(), "home.html", msg);
        } else {
            this.getServer().handleFile(getParent(), "fail.html", msg);
        }
    }

    @Override
    public SimpleJsonDir getParent() {
        return (SimpleJsonDir) super.getParent();
    }
}
