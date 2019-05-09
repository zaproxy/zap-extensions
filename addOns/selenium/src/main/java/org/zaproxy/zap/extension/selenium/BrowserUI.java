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

import java.text.Collator;
import org.apache.commons.lang.Validate;

/**
 * A representation of a {@code Browser} for UI components.
 *
 * <p>The method {@code toString()} returns the name of the browser.
 *
 * @see Browser
 */
public class BrowserUI implements Comparable<BrowserUI> {

    private final String name;
    private final Browser browser;

    /**
     * Constructs a {@code BrowserUI} with with the given {@code name} and {@code browser}.
     *
     * @param name the name that will be shown for the browser
     * @param browser the browser
     * @throws IllegalArgumentException if the {@code name} is {@code null} or empty and if the
     *     {@code browser} is {@code null}
     */
    public BrowserUI(String name, Browser browser) {
        Validate.notEmpty(name, "Parameter name must not be null");
        Validate.notNull(browser, "Parameter browser must not be null");

        this.name = name;
        this.browser = browser;
    }

    /**
     * Gets the name of the browser, never {@code null}.
     *
     * @return the name of the browser
     */
    public final String getName() {
        return name;
    }

    /**
     * Gets the browser, never {@code null}.
     *
     * @return the browser
     */
    public final Browser getBrowser() {
        return browser;
    }

    /**
     * Returns the name for the browser.
     *
     * @see #getName()
     */
    @Override
    public String toString() {
        return name;
    }

    @Override
    public int hashCode() {
        return 31 + ((name == null) ? 0 : name.hashCode());
    }

    /**
     * Two {@code BrowserUI} are considered equal if both have the same name.
     *
     * @see #getName()
     */
    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        BrowserUI other = (BrowserUI) obj;
        if (name == null) {
            if (other.name != null) {
                return false;
            }
        } else if (!name.equals(other.name)) {
            return false;
        }
        return true;
    }

    /**
     * Compares the names of browsers, using a {@code Collator} of the default {@code Locale}.
     *
     * @see #getName()
     * @see Collator
     */
    @Override
    public int compareTo(BrowserUI other) {
        if (other == null) {
            return 1;
        }

        return Collator.getInstance().compare(name, other.name);
    }
}
