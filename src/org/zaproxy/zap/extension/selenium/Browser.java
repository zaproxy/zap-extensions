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
package org.zaproxy.zap.extension.selenium;

import org.apache.commons.lang.Validate;

/**
 * Defines the browsers supported by the add-on.
 */
public enum Browser {

    CHROME("chrome"),
    FIREFOX("firefox"),
    /**
     * Headless browser, guaranteed to be always available.
     * 
     * @see #getFailSafeBrowser()
     */
    HTML_UNIT("htmlunit"),
    INTERNET_EXPLORER("ie"),
    OPERA("opera"),
    PHANTOM_JS("phantomjs"),
    SAFARI("safari");

    private final String id;

    private Browser(String id) {
        this.id = id;
    }

    /**
     * Gets the ID of this browser.
     * <p>
     * The ID can be used for persistence and later creation, using the method {@code getBrowserWithId(String)}.
     *
     * @return the ID of the browser
     * @see #getBrowserWithId(String)
     */
    public String getId() {
        return id;
    }

    /**
     * Gets the browser that has the given {@code id}.
     * <p>
     * If no match is found returns the browser guaranteed to be always available, as returned by {@code getFailSafeBrowser()}.
     * 
     * @param id the ID of the browser
     * @return the browser that matches the given {@code id}, or if not found the browser returned by
     *         {@code getFailSafeBrowser()}
     * @throws IllegalArgumentException if the given {@code id} is {@code null} or empty.
     * @see #getId()
     * @see #getFailSafeBrowser()
     */
    public static Browser getBrowserWithId(String id) {
        Validate.notEmpty(id, "Parameter id must not be null or empty.");

        if (CHROME.id.equals(id)) {
            return CHROME;
        } else if (FIREFOX.id.equals(id)) {
            return FIREFOX;
        } else if (HTML_UNIT.id.equals(id)) {
            return HTML_UNIT;
        } else if (INTERNET_EXPLORER.id.equals(id)) {
            return INTERNET_EXPLORER;
        } else if (OPERA.id.equals(id)) {
            return OPERA;
        } else if (PHANTOM_JS.id.equals(id)) {
            return PHANTOM_JS;
        } else if (SAFARI.id.equals(id)) {
            return SAFARI;
        }

        return getFailSafeBrowser();
    }

    /**
     * Gets the browser that is guaranteed to be always available.
     *
     * @return the {@code Browser} that is guaranteed to be always available.
     * @see #HTML_UNIT
     */
    public static Browser getFailSafeBrowser() {
        return HTML_UNIT;
    }

}
