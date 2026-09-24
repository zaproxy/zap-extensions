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

import org.zaproxy.addon.dev.TestAuthDirectory;
import org.zaproxy.addon.dev.TestProxyServer;

/**
 * A multi-step login flow where the user must select a domain on the first page, a department on
 * the second page, and enter their password on the third page. Login only succeeds when the correct
 * domain ("Project1") is selected, making it a good test case for AI-assisted authentication where
 * ZAP needs a user-supplied hint to know which domain to choose.
 */
public class MultiStepAuthDir extends TestAuthDirectory {

    public static final String REQUIRED_DOMAIN = "Project1";

    public MultiStepAuthDir(TestProxyServer server, String name) {
        super(server, name);
        this.addPage(new MultiStepAuthStep2Page(server));
        this.addPage(new MultiStepAuthPasswordPage(server));
        this.addPage(new MultiStepAuthLoginPage(server));
        this.addPage(new MultiStepAuthHomePage(server));
        this.addPage(new MultiStepAuthVerificationPage(server));
    }
}
