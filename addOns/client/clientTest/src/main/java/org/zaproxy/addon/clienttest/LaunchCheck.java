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
package org.zaproxy.addon.clienttest;

import java.io.IOException;
import java.util.function.Consumer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.MutableCapabilities;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebDriverException;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.addon.network.server.HttpServerConfig;
import org.zaproxy.addon.network.server.Server;
import org.zaproxy.zap.extension.selenium.DriverConfiguration;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;

/**
 * Launches a browser the way the Client Spider does, but with a given page load strategy, and
 * checks that the ZAP browser extension was configured by the launch.
 *
 * <p>The Client Spider launches its browsers through a proxy which serves the ZAP API, which the
 * Client add-on uses to configure the browser extension. When the browser does not wait for the
 * navigation to the ZAP API to finish, for example with the {@code none} page load strategy, it can
 * still be on {@code about:blank} when it is asked to configure the extension.
 *
 * <p>It is meant to be called from a script, for example in an Automation Framework plan, as:
 * {@code Java.type("org.zaproxy.addon.clienttest.LaunchCheck").check("firefox-headless", "none",
 * null)}
 */
public final class LaunchCheck {

    static final String EXTENSION_CONFIGURED_SCRIPT =
            "return localStorage.getItem('localzapconfigured')";

    private static final Logger LOGGER = LogManager.getLogger(LaunchCheck.class);

    private static final String LOCAL_PROXY_IP = "127.0.0.1";

    private LaunchCheck() {}

    /**
     * Launches the browser and checks that the ZAP browser extension was configured.
     *
     * @param browserId the ID of the browser, for example {@code firefox-headless}.
     * @param pageLoadStrategy the page load strategy to launch the browser with, for example {@code
     *     none}, or {@code null} to use the default.
     * @param slowPageUrl the URL of a slow loading page, see {@link
     *     org.zaproxy.addon.clienttest.slowload.SlowLoadPage}, to load after the launch to show
     *     what the browser sees until the page has loaded, or {@code null} to not load a page.
     * @return a report of what was found.
     * @throws IllegalStateException if the ZAP browser extension was not configured by the launch.
     */
    public static String check(String browserId, String pageLoadStrategy, String slowPageUrl)
            throws IOException {
        ExtensionSelenium extSelenium =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionSelenium.class);
        ExtensionNetwork extNetwork =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionNetwork.class);
        ExtensionClientIntegration extClient =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionClientIntegration.class);
        if (extSelenium == null || extNetwork == null || extClient == null) {
            throw new IllegalStateException(
                    "The Selenium, Network and Client add-ons are needed to launch a browser.");
        }

        int initiator = HttpSender.MANUAL_REQUEST_INITIATOR;
        Server proxy =
                extNetwork.createHttpServer(
                        HttpServerConfig.builder()
                                .setHttpMessageHandler((ctx, msg) -> {})
                                .setHttpSender(new HttpSender(initiator))
                                .setServeZapApi(true)
                                .build());
        int proxyPort;
        try {
            proxyPort = proxy.start(Server.ANY_PORT);
        } catch (IOException e) {
            closeQuietly(proxy);
            throw e;
        }
        extClient.registerPortInitiator(proxyPort, initiator);
        WebDriver driver = null;
        try {
            Consumer<MutableCapabilities> capabilities =
                    caps -> {
                        if (pageLoadStrategy != null && !pageLoadStrategy.isBlank()) {
                            caps.setCapability("pageLoadStrategy", pageLoadStrategy);
                        }
                    };
            driver =
                    extSelenium.getWebDriver(
                            browserId,
                            DriverConfiguration.builder()
                                    .requester(initiator)
                                    .proxyAddress(LOCAL_PROXY_IP)
                                    .proxyPort(proxyPort)
                                    .enableExtensions(true)
                                    .syncScriptExecution(true)
                                    .consumer(capabilities)
                                    .build());
            StringBuilder report = new StringBuilder();
            report.append("Browser: ").append(browserId);
            report.append(", page load strategy: ")
                    .append(pageLoadStrategy == null ? "default" : pageLoadStrategy);
            String configured = isExtensionConfigured(driver);
            report.append("\nExtension configured by launch: ").append(configured);
            if (slowPageUrl != null && !slowPageUrl.isBlank()) {
                report.append("\n").append(loadSlowPage(driver, slowPageUrl));
            }
            if (!"true".equals(configured)) {
                throw new IllegalStateException(
                        "The ZAP browser extension was not configured by the launch.\n" + report);
            }
            return report.toString();
        } finally {
            if (driver != null) {
                try {
                    driver.quit();
                } catch (WebDriverException e) {
                    // Already closed.
                }
            }
            extClient.unregisterPortInitiator(proxyPort);
            closeQuietly(proxy);
        }
    }

    private static void closeQuietly(Server proxy) {
        try {
            proxy.close();
        } catch (IOException e) {
            LOGGER.debug("An error occurred while stopping the proxy.", e);
        }
    }

    /**
     * Gets the state of the extension configuration, which is the value of {@code
     * localzapconfigured} in the {@code localStorage} of the page the browser is on, or the error
     * if it could not be read.
     */
    static String isExtensionConfigured(WebDriver driver) {
        try {
            Object value = ((JavascriptExecutor) driver).executeScript(EXTENSION_CONFIGURED_SCRIPT);
            return String.valueOf(value);
        } catch (WebDriverException e) {
            return "error: " + firstLine(e.getMessage());
        }
    }

    private static String loadSlowPage(WebDriver driver, String url) {
        StringBuilder sb = new StringBuilder();
        try {
            driver.get(url);
            sb.append("Slow page ").append(url);
            sb.append("\n  URL after navigation returned: ").append(driver.getCurrentUrl());
            sb.append("\n  localStorage right after navigation returned: ")
                    .append(isExtensionConfigured(driver));
        } catch (WebDriverException e) {
            sb.append("Failed to load the slow page: ").append(firstLine(e.getMessage()));
        }
        return sb.toString();
    }

    private static String firstLine(String message) {
        if (message == null) {
            return "";
        }
        int idx = message.indexOf('\n');
        return idx < 0 ? message : message.substring(0, idx);
    }
}
