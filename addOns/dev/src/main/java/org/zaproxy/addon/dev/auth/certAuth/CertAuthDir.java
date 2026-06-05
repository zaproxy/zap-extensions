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
package org.zaproxy.addon.dev.auth.certAuth;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.dev.TestAuthDirectory;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

/**
 * A test app served over HTTPS with mutual TLS (mTLS), requiring both a client certificate and
 * username/password authentication.
 *
 * <p>Accessed at {@code https://127.0.0.1:9443/}. Configure ZAP with:
 *
 * <ul>
 *   <li>Client cert: {@code <ZAP home>/dev-add-on/auth/cert-auth/test-client.p12} (password:
 *       {@value #CERT_PASSWORD})
 * </ul>
 */
public class CertAuthDir extends TestAuthDirectory {

    public static final int DEFAULT_PORT = 9443;

    /** Password for the test client keystore (test-client.p12). */
    public static final String CERT_PASSWORD = "zapdev";

    public CertAuthDir(TestProxyServer server, String name) {
        super(server, name);
        this.addPage(new CertAuthIndexPage(server));
        this.addPage(new CertAuthLoginPage(server));
        this.addPage(new CertAuthHomePage(server, "home.html"));
    }

    @Override
    public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
        String name = getPageName(msg);
        if ("tutorial.css".equals(name)) {
            getServer().handleFile("tutorial.css", msg);
            return;
        }
        super.handleMessage(ctx, msg);
    }
}
