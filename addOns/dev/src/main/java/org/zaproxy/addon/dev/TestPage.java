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
package org.zaproxy.addon.dev;

import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.network.server.HttpMessageHandler;

public abstract class TestPage implements HttpMessageHandler {

    private String name;
    private TestDirectory parent;
    private TestProxyServer server;

    public TestPage(TestProxyServer server, String name) {
        this.name = name;
        this.server = server;
    }

    public String getName() {
        return this.name;
    }

    public TestDirectory getParent() {
        return parent;
    }

    public void setParent(TestDirectory parent) {
        this.parent = parent;
    }

    public TestProxyServer getServer() {
        return server;
    }

    public String getFormParameter(HttpMessage msg, String name) {
        return msg.getFormParams().stream()
                .filter(p -> p.getName().equals(name))
                .findFirst()
                .map(HtmlParameter::getValue)
                .orElse(null);
    }
}
