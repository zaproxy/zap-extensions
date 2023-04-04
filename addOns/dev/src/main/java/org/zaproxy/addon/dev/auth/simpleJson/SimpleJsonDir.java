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

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.dev.TestDirectory;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

/**
 * A login page which uses one JSON request to login endpoint. TODO actually make a JSON request
 * rather than posting directly to the endpoint.'
 */
public class SimpleJsonDir extends TestDirectory {

    public SimpleJsonDir(TestProxyServer server) {
        super(server, "simple-json");
        this.addPage(new SimpleJsonLoginPage(server));
    }

    @Override
    public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
        String name = getPageName(msg);

        switch (name) {
            case INDEX_PAGE:
            case "login":
                super.handleMessage(ctx, msg);
                break;
            default:
                this.getServer().handleFile(this, "fail.html", msg);
                break;
        }
    }
}
