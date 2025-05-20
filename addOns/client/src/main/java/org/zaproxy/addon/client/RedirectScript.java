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
        StringBuilder sb = new StringBuilder();
        String apiurl = api.getCallbackUrl();
        sb.append(apiurl);
        if (apiurl.contains("?")) {
            sb.append('&');
        } else {
            sb.append('?');
        }
        sb.append("zapenable=true");
        if (ssutils.getRequester() == ZEST_CLIENT_RECORDER_INITIATOR) {
            sb.append("&zaprecord=true");
        }
        String zapurl = sb.toString();
        ssutils.getWebDriver().get(zapurl);
        JavascriptExecutor jsExecutor = (JavascriptExecutor) ssutils.getWebDriver();
        jsExecutor.executeScript("localStorage.setItem('localzapurl', '" + apiurl + "')");
        // The second refresh seems to be needed sometimes - could be a browser timing issue?
        ssutils.getWebDriver().get(zapurl);
    }
}
