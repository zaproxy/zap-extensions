/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.zap.extension.foxhound.config;

import java.io.File;
import java.nio.charset.Charset;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.WebDriver;
import org.parosproxy.paros.control.Control;
import org.zaproxy.zap.extension.selenium.Browser;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.extension.selenium.ProfileManager;
import org.zaproxy.zap.extension.selenium.SeleniumOptions;

public class FoxhoundSeleniumProfile {

    private static final Logger LOGGER = LogManager.getLogger(FoxhoundSeleniumProfile.class);

    private static final String FOXHOUND_PROFILE_NAME = "foxhound-profile";
    private FoxhoundOptions options;
    private ExtensionSelenium extensionSelenium;

    public FoxhoundSeleniumProfile(FoxhoundOptions options) {
        this.options = options;
    }

    public FoxhoundSeleniumProfile() {}

    public void setOptions(FoxhoundOptions options) {
        this.options = options;
    }

    private static final String PREF_PREFIX = "user_pref(";
    private static final String PREF_SUFFIX = ");";
    private static final String PREF_TAINTING_KEY = "tainting.";
    private static final String PREF_SOURCE_KEY_PREFIX = PREF_TAINTING_KEY + "source.";
    private static final String PREF_SINK_KEY_PREFIX = PREF_TAINTING_KEY + "sink.";
    private static final String PREF_EXPORT_KEY = PREF_TAINTING_KEY + "export.url";

    private String getPreferenceLine(String key, String value) {
        return PREF_PREFIX
                + "\""
                + key
                + "\""
                + ", "
                + value
                + PREF_SUFFIX
                + System.lineSeparator();
    }

    private StringBuilder getPreferencesFromMap(List<Map.Entry<String, String>> tupleList) {
        StringBuilder sb = new StringBuilder();
        for (var entry : tupleList) {
            sb.append(getPreferenceLine(entry.getKey(), entry.getValue()));
        }
        return sb;
    }

    private static String getString(String s) {
        return "\"" + s + "\"";
    }

    private static String getInt(int i) {
        return String.valueOf(i);
    }

    private static String getBool(boolean b) {
        return b ? "true" : "false";
    }

    private static java.util.AbstractMap.SimpleEntry<String, String> getEntry(
            String key, String value) {
        return new java.util.AbstractMap.SimpleEntry<>(key, value);
    }

    private String getProfileContentsFromOptions() {
        List<Map.Entry<String, String>> prefs = new ArrayList<>();

        // First the export server address
        prefs.add(
                getEntry(
                        PREF_EXPORT_KEY, getString("http://localhost:" + options.getServerPort())));

        // Sources
        List<String> disabledSources = options.getSourcesDisabled();
        for (String source : FoxhoundConstants.ALL_SOURCE_NAMES) {
            prefs.add(
                    getEntry(
                            PREF_SOURCE_KEY_PREFIX + source,
                            getBool(!disabledSources.contains(source))));
        }

        // Sinks
        List<String> disabledSinks = options.getSinksDisabled();
        for (String sink : FoxhoundConstants.ALL_SINK_NAMES) {
            prefs.add(
                    getEntry(PREF_SINK_KEY_PREFIX + sink, getBool(!disabledSinks.contains(sink))));
        }

        return getPreferencesFromMap(prefs).toString();
    }

    public void writeOptionsToProfile() {
        // Create Foxhound specific preferences
        ExtensionSelenium extSelenium = getExtensionSelenium();

        // Check that the custom Firefox profile is available
        ProfileManager pm = extSelenium.getProfileManager(Browser.FIREFOX);
        try {
            Path profileDir = pm.getOrCreateProfile(FOXHOUND_PROFILE_NAME);
            if (profileDir != null) {
                File prefFile = profileDir.resolve("user.js").toFile();
                // Write the user profile all the time
                FileUtils.writeStringToFile(
                        prefFile, getProfileContentsFromOptions(), Charset.defaultCharset());
                extSelenium.setDefaultFirefoxProfile(FOXHOUND_PROFILE_NAME);
            } else {
                LOGGER.error("Failed to get or create Firefox profile {}", FOXHOUND_PROFILE_NAME);
            }
        } catch (Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    private ExtensionSelenium getExtensionSelenium() {
        if (extensionSelenium == null) {
            extensionSelenium =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionSelenium.class);
        }
        return extensionSelenium;
    }

    public boolean launchFoxhound() {
        writeOptionsToProfile();
        String binaryPath = System.getProperty(SeleniumOptions.FIREFOX_BINARY_SYSTEM_PROPERTY);
        if ((binaryPath != null) && (binaryPath.contains("foxhound"))) {
            WebDriver webDriver =
                    getExtensionSelenium()
                            .getWebDriverProxyingViaZAP(1234, Browser.FIREFOX.getId());
            return true;
        } else {
            LOGGER.warn("Firefox binary doesn't appear to point to Foxhound: " + binaryPath);
            return false;
        }
    }
}
