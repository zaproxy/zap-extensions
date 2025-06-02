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
package org.zaproxy.zap.extension.selenium;

import org.openqa.selenium.WebDriver;

/**
 * A provider of a single browser (configuration).
 *
 * @since 1.1.0
 */
public interface SingleWebDriverProvider {

    /**
     * The ID of the WebDriver provider.
     *
     * @return the ID of the WebDriver provider.
     */
    String getId();

    /**
     * The browser provided by the implementation.
     *
     * @return the provided browser.
     */
    ProvidedBrowser getProvidedBrowser();

    /**
     * Gets a {@code WebDriver} to the provided browser for the given requester.
     *
     * @param requesterId the ID of the (ZAP) component that's requesting the {@code WebDriver}.
     * @return the {@code WebDriver} to the provided browser.
     */
    WebDriver getWebDriver(int requesterId);

    /**
     * Gets a {@code WebDriver} to the provided browser for the given requester, proxying through
     * the given address and port.
     *
     * @param requesterId the ID of the (ZAP) component that's requesting the {@code WebDriver}.
     * @param proxyAddress the address of the proxy.
     * @param proxyPort the port of the proxy.
     * @param enableExtensions if true then optional browser extensions will be enabled
     * @return the {@code WebDriver} to the provided browser, proxying through the given address and
     *     port.
     * @throws IllegalArgumentException if {@code proxyAddress} is {@code null} or empty, or if
     *     {@code proxyPort} is not a valid port number (between 1 and 65535).
     */
    WebDriver getWebDriver(
            int requesterId, String proxyAddress, int proxyPort, boolean enableExtensions);

    /**
     * Gets a warning message that indicates the possible cause of the failure that prevented the
     * WebDriver/browser from starting.
     *
     * <p>The message will be shown in UI components.
     *
     * @param e the error/exception that was thrown while obtaining/starting the WebDriver/browser.
     * @return the warning message that indicates the possible cause of the failure, might be {@code
     *     null} if there's no custom warning message (Selenium extension will provide a generic
     *     warning message in those cases).
     */
    String getWarnMessageFailedToStart(Throwable e);

    /**
     * Returns true if the provided browser is configured to run on the current platform
     *
     * @return
     */
    boolean isConfigured();
}
