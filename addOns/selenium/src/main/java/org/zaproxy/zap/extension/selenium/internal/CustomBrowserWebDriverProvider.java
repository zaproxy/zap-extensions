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
package org.zaproxy.zap.extension.selenium.internal;

import java.text.MessageFormat;
import org.openqa.selenium.WebDriver;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.extension.selenium.ProvidedBrowser;
import org.zaproxy.zap.extension.selenium.SingleWebDriverProvider;

/**
 * A {@link SingleWebDriverProvider} for custom browsers.
 *
 * <p><strong>Note:</strong> Does not belong to the public API.
 */
public class CustomBrowserWebDriverProvider implements SingleWebDriverProvider {

    private final CustomBrowserImpl customBrowser;
    private final ProvidedBrowser providedBrowser;
    private final boolean headless;

    public CustomBrowserWebDriverProvider(CustomBrowserImpl customBrowser) {
        this(customBrowser, false);
    }

    public CustomBrowserWebDriverProvider(CustomBrowserImpl customBrowser, boolean headless) {
        this.customBrowser = customBrowser;
        this.headless = headless;
        this.providedBrowser = new ProvidedBrowserImpl();
    }

    @Override
    public String getId() {
        if (headless) {
            return "custom." + customBrowser.getName() + "-headless";
        }
        return "custom." + customBrowser.getName();
    }

    @Override
    public ProvidedBrowser getProvidedBrowser() {
        return providedBrowser;
    }

    @Override
    public WebDriver getWebDriver(int requester) {
        return ExtensionSelenium.getWebDriver(requester, customBrowser, headless);
    }

    @Override
    public WebDriver getWebDriver(
            int requester, String proxyAddress, int proxyPort, boolean enableExtensions) {
        return ExtensionSelenium.getWebDriver(
                requester, customBrowser, proxyAddress, proxyPort, enableExtensions, headless);
    }

    @Override
    public String getWarnMessageFailedToStart(Throwable e) {
        // No custom warning message, use the ones provided by Selenium extension.
        return null;
    }

    @Override
    public boolean isConfigured() {
        return customBrowser.isConfigured();
    }

    public CustomBrowserImpl getCustomBrowser() {
        return customBrowser;
    }

    private class ProvidedBrowserImpl implements ProvidedBrowser {

        @Override
        public String getProviderId() {
            return getId();
        }

        @Override
        public String getId() {
            return CustomBrowserWebDriverProvider.this.getId();
        }

        @Override
        public String getName() {
            if (headless) {
                return MessageFormat.format(
                        Constant.messages.getString("selenium.browser.headless.name"),
                        customBrowser.getName(),
                        Constant.messages.getString("selenium.browser.headless"));
            }
            return customBrowser.getName();
        }

        @Override
        public boolean isHeadless() {
            return headless;
        }

        @Override
        public boolean isConfigured() {
            return CustomBrowserWebDriverProvider.this.isConfigured();
        }
    }
}
