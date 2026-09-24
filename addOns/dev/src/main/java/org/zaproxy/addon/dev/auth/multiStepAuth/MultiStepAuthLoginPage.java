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
package org.zaproxy.addon.dev.auth.multiStepAuth;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.dev.DevUtils;
import org.zaproxy.addon.dev.TestPage;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

/** Validates credentials and domain selection, then issues a session token on success. */
public class MultiStepAuthLoginPage extends TestPage {

    private static final Logger LOGGER = LogManager.getLogger(MultiStepAuthLoginPage.class);

    public MultiStepAuthLoginPage(TestProxyServer server) {
        super(server, "login");
    }

    @Override
    public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
        String user = null;
        String password = null;
        String domain = null;
        String department = null;

        for (HtmlParameter p : msg.getFormParams()) {
            switch (p.getName()) {
                case "user":
                    user = p.getValue();
                    break;
                case "password":
                    password = p.getValue();
                    break;
                case "domain":
                    domain = p.getValue();
                    break;
                case "department":
                    department = p.getValue();
                    break;
                default:
                    // Ignore
            }
        }

        boolean credentialsValid = getParent().isValid(user, password);
        boolean domainValid = MultiStepAuthDir.REQUIRED_DOMAIN.equals(domain);
        boolean departmentValid = department != null && !department.isEmpty();

        LOGGER.debug(
                "Login attempt: user={} domain={} dept={} credOk={} domainOk={} deptOk={}",
                user,
                domain,
                department,
                credentialsValid,
                domainValid,
                departmentValid);

        if (credentialsValid && domainValid && departmentValid) {
            String token = getParent().getToken(user);
            DevUtils.setRedirect(msg, "home");
            msg.getResponseHeader().setHeader(HttpHeader.SET_COOKIE, "session=" + token);
        } else {
            DevUtils.setRedirect(msg, "index.html");
        }
    }

    @Override
    public MultiStepAuthDir getParent() {
        return (MultiStepAuthDir) super.getParent();
    }
}
