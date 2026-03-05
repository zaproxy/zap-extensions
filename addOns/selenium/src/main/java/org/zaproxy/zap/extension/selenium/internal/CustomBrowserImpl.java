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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import lombok.Getter;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.selenium.CustomBrowser;

@Getter
public class CustomBrowserImpl {

    public enum BrowserType {
        CHROMIUM,
        FIREFOX;

        @Override
        public String toString() {
            return Constant.messages.getString(
                    "selenium.options.custom.browsers.type." + this.name().toLowerCase());
        }
    }

    private String name;
    private String driverPath;
    private String binaryPath;
    private List<BrowserArgument> arguments;
    private List<BrowserPreference> preferences;
    private BrowserType browserType;
    private boolean builtIn;

    public CustomBrowserImpl() {
        this("", "", "", BrowserType.CHROMIUM, List.of(), List.of());
    }

    public CustomBrowserImpl(
            String name,
            String driverPath,
            String binaryPath,
            BrowserType browserType,
            List<BrowserArgument> arguments) {
        this(name, driverPath, binaryPath, browserType, arguments, List.of());
    }

    public CustomBrowserImpl(
            String name,
            String driverPath,
            String binaryPath,
            BrowserType browserType,
            List<BrowserArgument> arguments,
            List<BrowserPreference> preferences) {
        this.name = Objects.requireNonNull(name);
        this.driverPath = driverPath;
        this.binaryPath = binaryPath;
        this.browserType = Objects.requireNonNull(browserType);
        this.arguments = new ArrayList<>(arguments);
        this.preferences = preferences != null ? new ArrayList<>(preferences) : new ArrayList<>();
    }

    public CustomBrowserImpl(CustomBrowserImpl other) {
        this(
                other.name,
                other.driverPath,
                other.binaryPath,
                other.browserType,
                other.arguments,
                other.preferences);
        this.builtIn = other.builtIn;
    }

    public CustomBrowserImpl(CustomBrowser browser) {
        this(
                browser.getName(),
                browser.getDriverPath(),
                browser.getBinaryPath(),
                BrowserType.valueOf(browser.getBrowserType().toUpperCase()),
                stringsToArgs(browser.getArguments()),
                stringsToPrefs(browser.getPreferences())
                );
    }

    private static List<BrowserPreference> stringsToPrefs(Map<String, String> map) {
        if (map == null) {
            return new ArrayList<>();
        }
        return map.keySet().stream().map(key -> new BrowserPreference(key, map.get(key), true)).toList();
    }

    private static List<BrowserArgument> stringsToArgs(List<String> strs) {
        if (strs == null) {
            return new ArrayList<>();
        }
        return strs.stream().map(str -> new BrowserArgument(str, true)).toList();
    }

    public List<BrowserArgument> getArguments() {
        return Collections.unmodifiableList(arguments);
    }

    public List<BrowserPreference> getPreferences() {
        return Collections.unmodifiableList(preferences);
    }

    public void setName(String name) {
        this.name = Objects.requireNonNull(name).trim();
    }

    public void setDriverPath(String driverPath) {
        this.driverPath = driverPath;
    }

    public void setBinaryPath(String binaryPath) {
        this.binaryPath = binaryPath;
    }

    public void setArguments(List<BrowserArgument> arguments) {
        this.arguments = new ArrayList<>(arguments);
    }

    public void setPreferences(List<BrowserPreference> preferences) {
        this.preferences = preferences != null ? new ArrayList<>(preferences) : new ArrayList<>();
    }

    public void setBrowserType(BrowserType browserType) {
        this.browserType = Objects.requireNonNull(browserType);
    }

    public boolean isBuiltIn() {
        return builtIn;
    }

    public void setBuiltIn(boolean builtIn) {
        this.builtIn = builtIn;
    }

    @Override
    public int hashCode() {
        return Objects.hash(name);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof CustomBrowserImpl other) {
            return Objects.equals(name, other.name);
        }
        return false;
    }

    public boolean allFieldsEqual(CustomBrowserImpl browser) {
        return browser != null
                && browser.getName().equals(this.getName())
                && browser.getDriverPath().equals(this.getDriverPath())
                && browser.getBinaryPath().equals(this.getBinaryPath())
                && browser.getBrowserType().equals(this.getBrowserType())
                && equals(browser.getArguments(), this.getArguments())
                && equalsPreferences(browser.getPreferences(), this.getPreferences());
    }

    private static boolean equalsPreferences(
            List<BrowserPreference> p1, List<BrowserPreference> p2) {
        if (p1 == null && p2 == null) {
            return true;
        }
        if (p1 == null || p2 == null || p1.size() != p2.size()) {
            return false;
        }
        for (int i = 0; i < p1.size(); i++) {
            if (!p1.get(i).equals(p2.get(i))) {
                return false;
            }
        }
        return true;
    }

    private static boolean equals(List<BrowserArgument> args1, List<BrowserArgument> args2) {
        if (args1 == null && args2 == null) {
            return true;
        }
        if (args1 == null || args2 == null) {
            return false;
        }
        if (args1.size() != args2.size()) {
            return false;
        }
        for (int i = 0; i < args1.size(); i++) {
            if (!args1.get(i).equals(args2.get(i))) {
                return false;
            }
        }
        return true;
    }
}
