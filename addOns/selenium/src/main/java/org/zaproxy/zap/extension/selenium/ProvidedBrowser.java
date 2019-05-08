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

/**
 * A provided browser, either by Selenium add-on or other add-ons.
 *
 * @since 1.1.0
 */
public interface ProvidedBrowser {

    /**
     * Gets the ID of the WebDriver provider.
     *
     * @return the ID of the WebDriver provider.
     */
    String getProviderId();

    /**
     * Gets the ID of the browser.
     *
     * @return the ID of the browser.
     */
    String getId();

    /**
     * The name of the browser.
     *
     * <p>The name will be shown in UI components.
     *
     * @return the name of the browser.
     */
    String getName();

    /**
     * Returns true if the browser is headless
     *
     * @return true if the browser is headless
     */
    boolean isHeadless();

    /**
     * Returns true if the browser is suitably configured for the current system
     *
     * @return true if the browser is suitably configured for the current system
     */
    boolean isConfigured();
}
