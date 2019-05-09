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

import java.text.Collator;
import org.apache.commons.lang.Validate;

/**
 * A representation of a {@link ProvidedBrowser} for UI components.
 *
 * <p>The method {@code toString()} returns the name of the browser.
 *
 * @since 1.1.0
 */
public class ProvidedBrowserUI implements Comparable<ProvidedBrowserUI> {

    private final ProvidedBrowser browser;

    /**
     * Constructs a {@code ProvidedBrowserUI} with the given {@code browser}.
     *
     * @param browser the browser.
     * @throws IllegalArgumentException if the {@code browser} is {@code null} or its name {@code
     *     null} or empty.
     */
    public ProvidedBrowserUI(ProvidedBrowser browser) {
        Validate.notNull(browser, "Parameter browser must not be null");
        Validate.notEmpty(browser.getName(), "Parameter name must not be null");

        this.browser = browser;
    }

    /**
     * Gets the name of the browser, never {@code null}.
     *
     * @return the name of the browser
     */
    public final String getName() {
        return browser.getName();
    }

    /**
     * Gets the browser, never {@code null}.
     *
     * @return the browser
     */
    public final ProvidedBrowser getBrowser() {
        return browser;
    }

    /**
     * Returns the name for the browser.
     *
     * @see #getName()
     */
    @Override
    public String toString() {
        return browser.getName();
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + browser.getId().hashCode();
        result = prime * result + browser.getProviderId().hashCode();
        return result;
    }

    /**
     * Two {@code ProvidedBrowserUI} are considered equal if both have the same ID and provider.
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
        ProvidedBrowserUI other = (ProvidedBrowserUI) obj;
        if (!browser.getId().equals(other.browser.getId())) {
            return false;
        }
        if (!browser.getProviderId().equals(other.browser.getProviderId())) {
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
    public int compareTo(ProvidedBrowserUI other) {
        if (other == null) {
            return 1;
        }

        int result = Collator.getInstance().compare(getName(), other.getName());
        if (result != 0) {
            return result;
        }
        return Collator.getInstance()
                .compare(browser.getProviderId(), other.browser.getProviderId());
    }
}
