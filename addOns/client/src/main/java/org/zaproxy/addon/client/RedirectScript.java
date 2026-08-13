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

import java.time.Duration;
import java.util.UUID;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.zaproxy.zap.extension.selenium.BrowserHook;
import org.zaproxy.zap.extension.selenium.SeleniumScriptUtils;
import org.zaproxy.zap.utils.Stats;

public class RedirectScript implements BrowserHook {

    static final int ZEST_CLIENT_RECORDER_INITIATOR = -73;

    private static final Logger LOGGER = LogManager.getLogger(RedirectScript.class);

    /**
     * The zapconfigured localStorage item will be set by the ZAP browser extension when it has been
     * successfully configured.
     */
    static final String EXTENSION_CONFIGURED_SCRIPT =
            "return localStorage.getItem('localzapconfigured')";

    static Duration extensionConfigureTimeout = Duration.ofSeconds(5);
    static Duration extensionConfigurePollInterval = Duration.ofMillis(200);

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
        sb.append("&zapid=");
        UUID uuid = UUID.randomUUID();
        sb.append(uuid);
        String zapurl = sb.toString();
        ssutils.getWebDriver().get(zapurl);
        JavascriptExecutor jsExecutor = (JavascriptExecutor) ssutils.getWebDriver();
        jsExecutor.executeScript("localStorage.setItem('localzapurl', '" + apiurl + "')");
        String browserName = ClientUtils.getBrowserName(ssutils.getWebDriver());
        if (!waitForExtensionConfigured(ssutils.getWebDriver())) {
            // Content script did not run on first navigation — retry
            ssutils.getWebDriver().get(zapurl);
            if (!waitForExtensionConfigured(ssutils.getWebDriver())) {
                LOGGER.warn("Failed to configure ZAP extension on browser launch");
                Stats.incCounter("stats.client.launch.fail." + browserName);
                return;
            }
            Stats.incCounter("stats.client.launch.retry." + browserName);
        } else {
            Stats.incCounter("stats.client.launch.pass." + browserName);
        }
        api.browserLaunched(new ClientCallBackUtils(ssutils, uuid));
    }

    private static boolean waitForExtensionConfigured(WebDriver driver) {
        try {
            new WebDriverWait(driver, extensionConfigureTimeout)
                    .pollingEvery(extensionConfigurePollInterval)
                    .until(
                            d ->
                                    "true"
                                            .equals(
                                                    ((JavascriptExecutor) d)
                                                            .executeScript(
                                                                    EXTENSION_CONFIGURED_SCRIPT)));
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
