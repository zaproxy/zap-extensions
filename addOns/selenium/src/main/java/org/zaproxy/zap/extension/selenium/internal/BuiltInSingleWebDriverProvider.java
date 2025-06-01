/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.selenium.internal;

import org.openqa.selenium.WebDriver;
import org.zaproxy.zap.extension.selenium.Browser;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.extension.selenium.ProvidedBrowser;
import org.zaproxy.zap.extension.selenium.SingleWebDriverProvider;

/**
 * A {@link SingleWebDriverProvider} for built-in supported browsers.
 *
 * <p><strong>Note:</strong> Does not belong to the public API.
 */
public class BuiltInSingleWebDriverProvider implements SingleWebDriverProvider {

    private final String name;
    private final Browser browser;
    private final ProvidedBrowser providedBrowser;

    public BuiltInSingleWebDriverProvider(String name, Browser browser) {
        this.name = name;
        this.browser = browser;
        this.providedBrowser = new ProvidedBrowserImpl();
    }

    @Override
    public String getId() {
        return browser.getId();
    }

    @Override
    public ProvidedBrowser getProvidedBrowser() {
        return providedBrowser;
    }

    @Override
    public WebDriver getWebDriver(int requester) {
        return ExtensionSelenium.getWebDriver(requester, browser);
    }

    @Override
    public WebDriver getWebDriver(
            int requester, String proxyAddress, int proxyPort, boolean enableExtensions) {
        return ExtensionSelenium.getWebDriver(
                requester, browser, proxyAddress, proxyPort, enableExtensions);
    }

    @Override
    public String getWarnMessageFailedToStart(Throwable e) {
        // No custom warning message, use the ones provided by Selenium extension.
        return null;
    }

    @Override
    public boolean isConfigured() {
        return ExtensionSelenium.isConfigured(browser);
    }

    private class ProvidedBrowserImpl implements ProvidedBrowser {

        @Override
        public String getProviderId() {
            return browser.getId();
        }

        @Override
        public String getId() {
            return browser.getId();
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public boolean isHeadless() {
            return browser.isHeadless();
        }

        @Override
        public boolean isConfigured() {
            Browser b = Browser.getBrowserWithIdNoFailSafe(browser.getId());
            return b != null && ExtensionSelenium.isConfigured(b);
        }
    }
}
