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
package org.zaproxy.addon.client;

import org.openqa.selenium.JavascriptExecutor;
import org.zaproxy.zap.extension.selenium.BrowserHook;
import org.zaproxy.zap.extension.selenium.SeleniumScriptUtils;

public class RedirectScript implements BrowserHook {

    static final int ZEST_CLIENT_RECORDER_INITIATOR = -73;

    private ClientIntegrationAPI api;

    public RedirectScript(ClientIntegrationAPI api) {
        this.api = api;
    }

    @Override
    public void browserLaunched(SeleniumScriptUtils ssutils) {
        String zapurl = api.getCallbackUrl();
        ssutils.getWebDriver().get(zapurl);
        JavascriptExecutor jsExecutor = (JavascriptExecutor) ssutils.getWebDriver();
        jsExecutor.executeScript("localStorage.setItem('localzapurl', '" + zapurl + "')");
        if (ssutils.getRequester() == ZEST_CLIENT_RECORDER_INITIATOR) {
            jsExecutor.executeScript("localStorage.setItem('localzapenable',false)");
        }

        // This statement make sure that the ZAP browser extension is configured properly
        ssutils.getWebDriver().get(zapurl);
    }
}
