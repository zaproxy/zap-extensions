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
package org.zaproxy.addon.dev.full.basicVulnAuth;

import org.zaproxy.addon.dev.TestAuthDirectory;
import org.zaproxy.addon.dev.TestProxyServer;

/**
 * A simple form-based authenticated app containing intentional vulnerabilities (reflected XSS, DOM
 * XSS, SQL injection) for testing ZAP scanning of authenticated pages.
 */
public class BasicVulnAuthDir extends TestAuthDirectory {

    public BasicVulnAuthDir(TestProxyServer server, String name) {
        super(server, name);
        this.addPage(new BasicVulnAuthIndexPage(server));
        this.addPage(new BasicVulnAuthLoginPage(server));
        this.addPage(new BasicVulnAuthProtectedPage(server, "home.html"));
        this.addPage(new BasicVulnAuthProtectedPage(server, "dom-xss.html"));
        this.addPage(new BasicVulnAuthReflectedXssPage(server));
        this.addPage(new BasicVulnAuthSqliPage(server));
    }
}
