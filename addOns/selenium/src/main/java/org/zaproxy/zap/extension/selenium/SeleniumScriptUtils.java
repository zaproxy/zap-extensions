/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.zap.extension.selenium;

import java.util.Locale;
import org.openqa.selenium.WebDriver;

public class SeleniumScriptUtils {
    private WebDriver wd;
    private int requester;
    private String browserId;
    private String proxyAddress;
    private int proxyPort;

    public SeleniumScriptUtils(
            WebDriver wd, int requester, String browserId, String proxyAddress, int proxyPort) {
        super();
        this.wd = wd;
        this.requester = requester;
        this.browserId = browserId;
        this.proxyAddress = proxyAddress;
        this.proxyPort = proxyPort;
    }

    public WebDriver getWebDriver() {
        return wd;
    }

    public int getRequester() {
        return requester;
    }

    public String getBrowserId() {
        return browserId;
    }

    public String getProxyAddress() {
        return proxyAddress;
    }

    public int getProxyPort() {
        return proxyPort;
    }

    public String waitForURL(int timeoutInMsecs) {
        String url = "";
        int time = 0;
        while (time < timeoutInMsecs
                && !(url = this.wd.getCurrentUrl()).toLowerCase(Locale.ROOT).startsWith("http")) {
            try {
                Thread.sleep(200);
                time += 200;
            } catch (InterruptedException e) {
                // Ignore
            }
        }
        return url;
    }
}
