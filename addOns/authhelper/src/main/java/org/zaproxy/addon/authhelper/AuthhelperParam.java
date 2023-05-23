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
package org.zaproxy.addon.authhelper;

import org.parosproxy.paros.common.AbstractParam;
import org.zaproxy.zap.extension.selenium.Browser;

public class AuthhelperParam extends AbstractParam {

    private static final String AUTO_KEY = "authhelper";

    private static final String LOGIN_URL_KEY = AUTO_KEY + ".loginurl";
    private static final String USERNAME_KEY = AUTO_KEY + ".username";
    private static final String BROWSER_KEY = AUTO_KEY + ".browser";
    private static final String WAIT_KEY = AUTO_KEY + ".wait";
    private static final String DEMO_MODE_KEY = AUTO_KEY + ".demo";

    private String loginUrl;
    private String username;
    private String browser;
    private int wait = 2;
    private boolean demoMode;

    public AuthhelperParam() {}

    @Override
    protected void parse() {
        this.loginUrl = this.getString(LOGIN_URL_KEY, "");
        this.username = this.getString(USERNAME_KEY, null);
        this.browser = this.getString(BROWSER_KEY, Browser.FIREFOX.getId());
        this.wait = getInteger(WAIT_KEY, 2);
        this.demoMode = getBoolean(DEMO_MODE_KEY, false);
    }

    public String getLoginUrl() {
        return loginUrl;
    }

    public void setLoginUrl(String loginUrl) {
        this.loginUrl = loginUrl;
        getConfig().setProperty(LOGIN_URL_KEY, loginUrl);
    }

    public boolean isDemoMode() {
        return demoMode;
    }

    public void setDemoMode(boolean demoMode) {
        this.demoMode = demoMode;
        getConfig().setProperty(DEMO_MODE_KEY, demoMode);
    }

    public String getBrowser() {
        return browser;
    }

    public void setBrowser(String browser) {
        this.browser = browser;
        getConfig().setProperty(BROWSER_KEY, browser);
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
        getConfig().setProperty(USERNAME_KEY, username);
    }

    public int getWait() {
        return wait;
    }

    public void setWait(int wait) {
        this.wait = wait;
        getConfig().setProperty(WAIT_KEY, wait);
    }
}
