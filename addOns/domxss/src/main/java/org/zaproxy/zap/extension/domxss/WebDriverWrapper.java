/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.domxss;

import java.util.Date;
import org.openqa.selenium.WebDriver;
import org.zaproxy.zap.extension.selenium.Browser;

public class WebDriverWrapper {
    private WebDriver driver;
    private Browser browser;
    private Date lastAccessed;

    public WebDriverWrapper(WebDriver driver, Browser browser) {
        super();
        this.driver = driver;
        this.browser = browser;
        lastAccessed = new Date();
    }

    public WebDriver getDriver() {
        lastAccessed = new Date();
        return driver;
    }

    public Browser getBrowser() {
        return browser;
    }

    public void setDriver(WebDriver driver) {
        lastAccessed = new Date();
        this.driver = driver;
    }

    public Date getLastAccessed() {
        return lastAccessed;
    }
}
