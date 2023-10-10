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
package org.zaproxy.zap.extension.selenium.internal.stealth;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.chromium.ChromiumDriver;
import org.openqa.selenium.devtools.DevTools;
import org.yaml.snakeyaml.Yaml;
import org.zaproxy.zap.extension.selenium.SeleniumScriptUtils;

/**
 * Manages modifications to the browser and web driver to look to the website like a user is in
 * control. Check for chrome headless:
 *
 * <ul>
 *   <li>https://arh.antoinevastel.com/bots/areyouheadless
 *   <li>https://bot.sannysoft.com/
 * </ul>
 */
public class StealthManager {
    private static final Logger LOGGER = LogManager.getLogger(StealthManager.class);
    private static final String EVASIONS_DIR =
            "/org/zaproxy/zap/extension/selenium/resources/stealth";
    private static final Pattern ANDROID_MODEL = Pattern.compile("Android.*?;\\s([^)]+)");
    private static final Pattern WINDOWS_VERSION = Pattern.compile("Windows .*?([0-9.]+);?");
    private static final Pattern ANDROID_VERSION = Pattern.compile("Android ([^;]+)");
    private static final Pattern MACOS_VERSION = Pattern.compile("Mac OS X ([0-9.]+)");
    private static final Pattern CHROME_VERSION = Pattern.compile("Chrome/([0-9.]+)");
    private static final Pattern PLATFORM_SPEC = Pattern.compile("\\(([^)]+)\\)");
    static final String PLATFORM_MAC_OS_X = "Mac OS X";
    static final String PLATFORM_ANDROID = "Android";
    static final String PLATFORM_LINUX = "Linux";
    static final String PLATFORM_WINDOWS = "Windows";

    /**
     * List of all evasions. A value of null means not loaded, an empty list means loading failed.
     */
    private List<Evasion> evasions;

    /**
     * The utility code used by evasions. Might require special handling depending on the browser.
     */
    private String utilCode;

    /** Load evasions if not already attempted. */
    @SuppressWarnings("unchecked")
    void loadEvasions() throws IOException {
        if (evasions != null) {
            return;
        }
        evasions = new ArrayList<>();
        utilCode = loadResourceAsString(EVASIONS_DIR + "/utils.js");
        try (InputStream is = getClass().getResourceAsStream(EVASIONS_DIR + "/catalog.yaml")) {
            Map<String, Map<String, Object>> catalog = new Yaml().load(is);
            for (Map.Entry<String, Map<String, Object>> e : catalog.entrySet()) {
                String name = e.getKey();
                Map<String, Object> attributes = e.getValue();
                EvasionType type = EvasionType.valueOf(String.valueOf(attributes.get("type")));
                String file = String.valueOf(attributes.get("file"));
                Collection<String> browsers = Collections.emptyList();
                if (attributes.containsKey("browsers")) {
                    Object browsersValue = attributes.get("browsers");
                    browsers = (Collection<String>) browsersValue;
                }
                try {
                    evasions.add(
                            new Evasion(
                                    name,
                                    type,
                                    loadResourceAsString(EVASIONS_DIR + "/" + file),
                                    browsers));
                } catch (IOException e2) {
                    LOGGER.error("loading {}", file, e2);
                }
            }
        }
    }

    String getUtilCode() {
        return utilCode;
    }

    List<Evasion> getEvasions() {
        return Collections.unmodifiableList(evasions);
    }

    /** Loads a class path resource into a string. */
    private String loadResourceAsString(String path) throws IOException {
        try (InputStream is = getClass().getResourceAsStream(path)) {
            if (is == null) {
                throw new FileNotFoundException(path);
            }
            BufferedReader rd =
                    new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
            StringBuilder content = new StringBuilder(16384);
            rd.lines().forEach(line -> content.append(line).append('\n'));
            return content.toString();
        }
    }

    List<Evasion> filterEvasionsByBrowser(String browserId) throws IOException {
        loadEvasions();
        List<Evasion> result = new ArrayList<>(evasions.size());
        for (Evasion evasion : evasions) {
            if (evasion.getBrowsers().isEmpty() || evasion.getBrowsers().contains(browserId)) {
                result.add(evasion);
            }
        }
        return result;
    }

    public void browserLaunched(SeleniumScriptUtils ssutils) {
        if (!(ssutils.getWebDriver() instanceof ChromiumDriver)) {
            LOGGER.info("stealth requested for {} but not supported", ssutils.getBrowserId());
            return;
        }

        LOGGER.info("applying stealth to {}", ssutils.getBrowserId());
        ChromiumDriver wd = (ChromiumDriver) ssutils.getWebDriver();
        DevTools devTools = wd.getDevTools();
        devTools.createSession();

        String userAgent = wd.executeScript("return navigator.userAgent").toString();
        Map<String, Object> userAgentOverrides = buildUserAgentOverrides(userAgent);
        if (userAgentOverrides != null && !userAgentOverrides.isEmpty()) {
            LOGGER.info("UserAgent override {} => {}", userAgent, userAgentOverrides);
            wd.executeCdpCommand("Network.setUserAgentOverride", userAgentOverrides);
        } else {
            LOGGER.info("UserAgent '{}' not overriden", userAgent);
        }

        List<Evasion> evasions = Collections.emptyList();
        try {
            evasions = filterEvasionsByBrowser(ssutils.getBrowserId());
        } catch (IOException e) {
            LOGGER.error("Failure loading stealth evasions", e);
        }
        if (evasions.isEmpty()) {
            LOGGER.info("No evasions available for {}", ssutils.getBrowserId());
            return;
        }

        StringBuilder newDocumentCode = new StringBuilder(65536);

        newDocumentCode.append(utilCode).append('\n');

        for (Evasion evasion : evasions) {
            if (evasion.getType() == EvasionType.evaluateOnNewDocument) {
                // append newlines to ensure we don't get syntax errors due to lack of newlines
                newDocumentCode.append('\n').append(evasion.getCode()).append('\n');
            }
        }

        if (newDocumentCode.length() > 0) {
            addScriptToEvaluateOnNewDocument(wd, newDocumentCode.toString());
        }
    }

    void addScriptToEvaluateOnNewDocument(ChromiumDriver wd, String code) {
        wd.executeCdpCommand(
                "Page.addScriptToEvaluateOnNewDocument", Collections.singletonMap("source", code));
    }

    // https://github.com/berstend/puppeteer-extra/blob/master/packages/puppeteer-extra-plugin-stealth/evasions/user-agent-override/index.js

    Map<String, Object> buildUserAgentOverrides(String userAgent) {
        if (userAgent == null || userAgent.isEmpty()) {
            return null;
        }

        Map<String, Object> override = new HashMap<>();
        override.put("userAgent", userAgent);

        if (userAgent.contains("Headless")) {
            userAgent = userAgent.replace("Headless", "");
            override.put("acceptLanguage", "en-US,en");
        }

        if (userAgent.contains("Linux") && !userAgent.contains("Android")) {
            // Replace the first part in parentheses with Windows data
            userAgent =
                    PLATFORM_SPEC.matcher(userAgent).replaceFirst("(Windows NT 10.0; Win64; x64)");
        }

        override.put("userAgent", userAgent);
        override.put("platform", getPlatform(userAgent, false));
        Map<String, Object> metadata = new HashMap<>();
        override.put("userAgentMetadata", metadata);
        metadata.put("platform", getPlatform(userAgent, true));
        metadata.put("platformVersion", getPlatformVersion(userAgent));
        metadata.put("architecture", getPlatformArch(userAgent));
        metadata.put("model", getPlatformModel(userAgent));
        metadata.put("mobile", isMobile(userAgent));

        /*
         * TODO: handle other browsers
         * const uaVersion = ua.includes('Chrome/')
         *       ? ua.match(/Chrome\/([0-9.]+)/)[1]
         *       : (await page.browser().version()).match(/\/([0-9.]+)/)[1]
         */
        if (!userAgent.contains("Chrome/")) {
            return override;
        }

        Matcher uaVersionMatcher = CHROME_VERSION.matcher(userAgent);
        if (!uaVersionMatcher.find()) {
            return override;
        }
        String uaVersion = uaVersionMatcher.group(1);

        metadata.put("fullVersion", uaVersion);
        metadata.put("brands", getBrands(uaVersion));

        return override;
    }

    String getPlatform(String userAgent, boolean extended) {
        if (userAgent.contains(PLATFORM_MAC_OS_X)) {
            return extended ? PLATFORM_MAC_OS_X : "MacIntel";
        } else if (userAgent.contains(PLATFORM_ANDROID)) {
            return PLATFORM_ANDROID;
        } else if (userAgent.contains(PLATFORM_LINUX)) {
            return PLATFORM_LINUX;
        } else {
            return extended ? PLATFORM_WINDOWS : "Win32";
        }
    }

    static class Brand {
        final String brand;
        final String version;

        public Brand(String brand, String version) {
            this.brand = brand;
            this.version = version;
        }

        Map<String, String> toMap() {
            Map<String, String> map = new HashMap<>();
            map.put("brand", brand);
            map.put("version", version);
            return map;
        }
    }

    /**
     * Source in C++:
     * https://source.chromium.org/chromium/chromium/src/+/master:components/embedder_support/user_agent_utils.cc;l=55-100
     */
    List<Map<String, String>> getBrands(String uaVersion) {
        int seed = Integer.parseInt(uaVersion.split("[.]")[0]); // the major version number
        int[] order =
                new int[][] {
                            {0, 1, 2},
                            {0, 2, 1},
                            {1, 0, 2},
                            {1, 2, 0},
                            {2, 0, 1},
                            {2, 1, 0}
                        }
                        [seed % 6];
        String[] escapedChars = new String[] {" ", " ", ";"};
        String greaseyBrand =
                escapedChars[order[0]]
                        + "Not"
                        + escapedChars[order[1]]
                        + "A"
                        + escapedChars[order[2]]
                        + "Brand";

        List<Map<String, String>> greasedBrandVersionList = new ArrayList<>(3);
        greasedBrandVersionList.add(null);
        greasedBrandVersionList.add(null);
        greasedBrandVersionList.add(null);
        greasedBrandVersionList.set(order[0], new Brand(greaseyBrand, "99").toMap());
        greasedBrandVersionList.set(order[1], new Brand("Chromium", String.valueOf(seed)).toMap());
        greasedBrandVersionList.set(
                order[2], new Brand("Google Chrome", String.valueOf(seed)).toMap());
        return greasedBrandVersionList;
    }

    /**
     * Extract the platform version. Linux is intentionally not included. It is not a common user
     * platform and hints to automation.
     *
     * @return version string or empty string
     */
    String getPlatformVersion(String userAgent) {
        if (userAgent.contains("Mac OS X ")) {
            Matcher m = MACOS_VERSION.matcher(userAgent);
            if (m.find()) {
                return m.group(1);
            }
        } else if (userAgent.contains("Android ")) {
            Matcher m = ANDROID_VERSION.matcher(userAgent);
            if (m.find()) {
                return m.group(1);
            }
        } else if (userAgent.contains("Windows ")) {
            Matcher m = WINDOWS_VERSION.matcher(userAgent);
            if (m.find()) {
                return m.group(1);
            }
        }

        return "";
    }

    boolean isMobile(String userAgent) {
        return userAgent.contains(PLATFORM_ANDROID);
    }

    String getPlatformArch(String userAgent) {
        if (isMobile(userAgent)) {
            return "";
        } else {
            return "x86";
        }
    }

    String getPlatformModel(String userAgent) {
        if (!isMobile(userAgent)) {
            return "";
        }
        Matcher matcher = ANDROID_MODEL.matcher(userAgent);
        if (matcher.find()) {
            String[] androidParts = matcher.group(1).split(";");
            for (String part : androidParts) {
                if (part.length() == 2) {
                    // language?
                    continue;
                }
                if (part.length() == 5 && part.charAt(2) == '-') {
                    // language
                    continue;
                }
                return part.trim();
            }
        }
        return "";
    }
}
