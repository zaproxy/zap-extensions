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
package org.zaproxy.addon.network;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import org.apache.commons.configuration.ConversionException;
import org.apache.commons.configuration.HierarchicalConfiguration;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.addon.network.internal.GlobalExclusion;
import org.zaproxy.zap.common.VersionedAbstractParam;

/** The global exclusions (e.g. domains, URLs). */
public class GlobalExclusionsOptions extends VersionedAbstractParam {

    private static final Logger LOGGER = LogManager.getLogger(GlobalExclusionsOptions.class);

    protected static final int CURRENT_CONFIG_VERSION = 2;

    private static final String BASE_KEY = "network.globalExclusions";

    private static final String CONFIG_VERSION_KEY = BASE_KEY + VERSION_ATTRIBUTE;

    private static final String EXCLUSIONS_KEY = BASE_KEY + ".exclusions";
    private static final String EXCLUSION_KEY = EXCLUSIONS_KEY + ".exclusion";

    private static final String GLOBAL_EXCLUSION_NAME_KEY = "name";
    private static final String GLOBAL_EXCLUSION_VALUE_KEY = "value";
    private static final String GLOBAL_EXCLUSION_ENABLED_KEY = "enabled";
    private static final String GLOBAL_EXCLUSIONS_CONFIRM_REMOVE =
            EXCLUSIONS_KEY + ".confirmRemove";

    private static final List<GlobalExclusion> DEFAULT_GLOBAL_EXCLUSIONS =
            List.of(
                    new GlobalExclusion(
                            "Extension - Image (ends with .extension)",
                            "(?i)^.*\\.(?:gif|jpe?g|png|ico|icns|bmp|svg|webp)$",
                            false),
                    new GlobalExclusion(
                            "Extension - Audio/Video (ends with .extension)",
                            "(?i)^.*\\.(?:mp[34]|mpe?g|m4[ap]|aac|avi|mov|wmv|og[gav]|webm)$",
                            false),
                    new GlobalExclusion(
                            "Extension - PDF & Office (ends with .extension)",
                            "(?i)^.*\\.(?:pdf|docx?|xlsx?|pptx?)$",
                            false),
                    new GlobalExclusion(
                            "Extension - Stylesheet, JavaScript (ends with .extension)",
                            "(?i)^.*\\.(?:css|js)$",
                            false),
                    new GlobalExclusion(
                            "Extension - Flash & related (ends with .extension)",
                            "(?i)^.*\\.(?:sw[fa]|flv)$",
                            false),
                    new GlobalExclusion(
                            "ExtParam - Image (extension plus ?params=values)",
                            "(?i)^[^\\?]*\\.(?:gif|jpe?g|png|ico|icns|bmp|svg|webp)\\?.*$",
                            false),
                    new GlobalExclusion(
                            "ExtParam - Audio/Video (extension plus ?params=values)",
                            "(?i)^[^\\?]*\\.(?:mp[34]|mpe?g|m4[ap]|aac|avi|mov|wmv|og[gav]|webm)\\?.*$",
                            false),
                    new GlobalExclusion(
                            "ExtParam - PDF & Office (extension plus ?params=values)",
                            "(?i)^[^\\?]*\\.(?:pdf|docx?|xlsx?|pptx?)\\?.*$",
                            false),
                    new GlobalExclusion(
                            "ExtParam - Stylesheet, JavaScript (extension plus ?params=values)",
                            "(?i)^[^\\?]*\\.(?:css|js)\\?.*$",
                            false),
                    new GlobalExclusion(
                            "ExtParam - Flash & related (extension plus ?params=values)",
                            "(?i)^[^\\?]*\\.(?:sw[fa]|flv)\\?.*$",
                            false),
                    new GlobalExclusion(
                            "ExtParam - .NET axd resources (SR/WR.axd?d=)",
                            "(?i)^[^\\?]*/(?:WebResource|ScriptResource)\\.axd\\?d=.*$",
                            false),
                    new GlobalExclusion(
                            "Site - Bing API queries",
                            "(?i)^https?://api\\.bing\\.com/qsml\\.aspx?query=.*$",
                            false),
                    new GlobalExclusion(
                            "Site - Google malware detector updates",
                            "(?i)^https?://(?:safebrowsing-cache|sb-ssl|sb|safebrowsing).*\\.(?:google|googleapis)\\.com/.*$",
                            true),
                    new GlobalExclusion(
                            "Site - Lastpass manager",
                            "(?i)^https?://(?:[^/])*\\.?lastpass\\.com",
                            false),
                    new GlobalExclusion(
                            "Site - Firefox browser updates",
                            "(?i)^https?://(?:.*addons|aus[0-9])\\.mozilla\\.(?:org|net|com)/.*$",
                            true),
                    new GlobalExclusion(
                            "Site - Firefox extensions phoning home",
                            "(?i)^https?://(?:[^/])*\\.?(?:getfoxyproxy\\.org|getfirebug\\.com|noscript\\.net)",
                            false),
                    new GlobalExclusion(
                            "Site - Microsoft Windows updates",
                            // http://serverfault.com/questions/332003/what-urls-must-be-in-ies-trusted-sites-list-to-allow-windows-update
                            "(?i)^https?://(?:.*update\\.microsoft|.*\\.windowsupdate)\\.com/.*$",
                            true),
                    new GlobalExclusion(
                            "Site - Google Chrome extension updates",
                            "(?i)^https?://clients2\\.google\\.com/service/update2/crx.*$",
                            true),
                    new GlobalExclusion(
                            "Site - Firefox captive portal detection",
                            "(?i)^https?://detectportal\\.firefox\\.com.*$",
                            true),
                    new GlobalExclusion(
                            "Site - Google Analytics",
                            "(?i)^https?://www\\.google-analytics\\.com.*$",
                            false),
                    new GlobalExclusion(
                            "Site - Firefox h264 codec download",
                            // https://support.mozilla.org/t5/Firefox/Where-is-a-check-that-http-ciscobinary-openh264-org-openh264-is/m-p/1316497#M1005892
                            "(?i)^https?://ciscobinary\\.openh264\\.org.*$",
                            false),
                    new GlobalExclusion(
                            "Site - Fonts CDNs such as fonts.gstatic.com, etc.",
                            "(?i)^https?://fonts.*$",
                            false),
                    new GlobalExclusion(
                            "Site - Mozilla CDN (requests such as getpocket)",
                            "(?i)^https?://.*\\.cdn\\.mozilla\\.(?:com|org|net)/.*$",
                            true),
                    new GlobalExclusion(
                            "Site - Firefox browser telemetry",
                            "(?i)^https?://.*\\.telemetry\\.mozilla\\.(?:com|org|net)/.*$",
                            true),
                    new GlobalExclusion(
                            "Site - Adblockplus updates and notifications",
                            "(?i)^https?://.*\\.adblockplus\\.org.*$",
                            false),
                    new GlobalExclusion(
                            "Site - Firefox services",
                            "(?i)^https?://.*\\.services\\.mozilla\\.com.*$",
                            true),
                    new GlobalExclusion(
                            "Site - Google updates", "(?i)^https?://.*\\.gvt1\\.com.*$", true));

    private List<GlobalExclusion> globalExclusions = List.of();
    private boolean confirmRemoveGlobalExclusions = true;
    private boolean refreshUrls = true;
    private List<String> urls;

    @Override
    protected int getCurrentVersion() {
        return CURRENT_CONFIG_VERSION;
    }

    @Override
    protected String getConfigVersionKey() {
        return CONFIG_VERSION_KEY;
    }

    @Override
    @SuppressWarnings("fallthrough")
    protected void updateConfigsImpl(int fileVersion) {
        switch (fileVersion) {
            case NO_CONFIG_VERSION:
                migrateCoreConfigs();

                List<HierarchicalConfiguration> fields =
                        ((HierarchicalConfiguration) getConfig()).configurationsAt(EXCLUSION_KEY);
                if (fields.isEmpty()) {
                    setGlobalExclusions(DEFAULT_GLOBAL_EXCLUSIONS);
                    break;
                }
            case 1:
                updateToVersion2();
        }
    }

    private void updateToVersion2() {
        List<HierarchicalConfiguration> fields =
                ((HierarchicalConfiguration) getConfig()).configurationsAt(EXCLUSION_KEY);
        List<String> oldValues =
                List.of(
                        "^.*\\.(?:gif|jpe?g|png|ico|icns|bmp)$",
                        "^.*\\.(?:mp[34]|mpe?g|m4[ap]|aac|avi|mov|wmv|og[gav])$",
                        "^.*\\.(?:pdf|docx?|xlsx?|pptx?)$",
                        "^.*\\.(?:css|js)$",
                        "^.*\\.(?:sw[fa]|flv)$",
                        "^[^\\?]*\\.(?:gif|jpe?g|png|ico|icns|bmp)\\?.*$",
                        "^[^\\?]*\\.(?:mp[34]|mpe?g|m4[ap]|aac|avi|mov|wmv|og[gav])\\?.*$",
                        "^[^\\?]*\\.(?:pdf|docx?|xlsx?|pptx?)\\?.*$",
                        "^[^\\?]*\\.(?:css|js)\\?.*$",
                        "^[^\\?]*\\.(?:sw[fa]|flv)\\?.*$",
                        "^[^\\?]*/(?:WebResource|ScriptResource)\\.axd\\?d=.*$",
                        "^https?://api\\.bing\\.com/qsml\\.aspx?query=.*$",
                        "^https?://(?:safebrowsing-cache|sb-ssl|sb|safebrowsing).*\\.(?:google|googleapis)\\.com/.*$",
                        "^https?://(?:[^/])*\\.?lastpass\\.com",
                        "^https?://(?:.*addons|aus[0-9])\\.mozilla\\.(?:org|net|com)/.*$",
                        "^https?://(?:[^/])*\\.?(?:getfoxyproxy\\.org|getfirebug\\.com|noscript\\.net)",
                        "^https?://(?:.*update\\.microsoft|.*\\.windowsupdate)\\.com/.*$",
                        "^https?://clients2\\.google\\.com/service/update2/crx.*$",
                        "^https?://detectportal\\.firefox\\.com.*$",
                        "^https?://www\\.google-analytics\\.com.*$",
                        "^https?://ciscobinary\\.openh264\\.org.*$",
                        "^https?://fonts.*$",
                        "^https?://.*\\.cdn\\.mozilla\\.(?:com|org|net)/.*$",
                        "^https?://.*\\.telemetry\\.mozilla\\.(?:com|org|net)/.*$",
                        "^https?://.*\\.adblockplus\\.org.*$",
                        "^https?://.*\\.services\\.mozilla\\.com.*$",
                        "^https?://.*\\.gvt1\\.com.*$");
        for (HierarchicalConfiguration sub : fields) {
            try {
                String value = sub.getString(GLOBAL_EXCLUSION_VALUE_KEY, "");
                if (oldValues.contains(value)) {
                    String name = sub.getString(GLOBAL_EXCLUSION_NAME_KEY, "");
                    // Fix naming mistake
                    if (name.contains("adx")) {
                        name = name.replace("adx", "axd");
                        sub.setProperty(GLOBAL_EXCLUSION_NAME_KEY, name);
                    }
                    // Extend image types pattern(s)
                    if (value.contains("|bmp)")) {
                        value = value.replace("|bmp)", "|bmp|svg|webp)");
                    }
                    // Extend audio/video types pattern(s)
                    if (value.contains("|og[gav])")) {
                        value = value.replace("|og[gav])", "|og[gav]|webm)");
                    }
                    // Make them case insensitive
                    value = "(?i)" + value;
                    sub.setProperty(GLOBAL_EXCLUSION_VALUE_KEY, value);
                }
            } catch (ConversionException e) {
                LOGGER.warn("An error occurred while reading a global exclusion:", e);
            }
        }
    }

    @Override
    protected void parseImpl() {
        // Do always, for now, in case -config args are in use.
        migrateCoreConfigs();

        List<HierarchicalConfiguration> fields =
                ((HierarchicalConfiguration) getConfig()).configurationsAt(EXCLUSION_KEY);
        globalExclusions = new ArrayList<>(fields.size());
        for (HierarchicalConfiguration sub : fields) {
            try {
                String value = sub.getString(GLOBAL_EXCLUSION_VALUE_KEY, "");
                if (validateGlobalExclusionPattern(value)) {
                    globalExclusions.add(
                            new GlobalExclusion(
                                    sub.getString(GLOBAL_EXCLUSION_NAME_KEY, ""),
                                    value,
                                    sub.getBoolean(GLOBAL_EXCLUSION_ENABLED_KEY, true)));
                }
            } catch (ConversionException e) {
                LOGGER.warn("An error occurred while reading a global exclusion:", e);
            }
        }
        confirmRemoveGlobalExclusions = getBoolean(GLOBAL_EXCLUSIONS_CONFIRM_REMOVE, true);

        refreshUrls = true;
    }

    private void migrateCoreConfigs() {
        try {
            List<HierarchicalConfiguration> exclusions =
                    ((HierarchicalConfiguration) getConfig())
                            .configurationsAt("globalexcludeurl.url_list.url");
            for (int i = 0; i < exclusions.size(); ++i) {
                String oldConfig = "globalexcludeurl.url_list.url(" + i + ").";
                String newConfig = EXCLUSION_KEY + "(" + i + ").";
                migrateConfig(oldConfig + "description", newConfig + GLOBAL_EXCLUSION_NAME_KEY);
                migrateConfig(oldConfig + "regex", newConfig + GLOBAL_EXCLUSION_VALUE_KEY);
                migrateConfig(oldConfig + "enabled", newConfig + GLOBAL_EXCLUSION_ENABLED_KEY);
            }
            migrateConfig("globalexcludeurl.confirmRemoveToken", GLOBAL_EXCLUSIONS_CONFIRM_REMOVE);
        } catch (Exception e) {
            LOGGER.warn("An error occurred while migrating old global exclusions:", e);
        }

        ((HierarchicalConfiguration) getConfig()).clearTree("globalexcludeurl");
    }

    private void migrateConfig(String oldConfig, String newConfig) {
        Object oldValue = getConfig().getProperty(oldConfig);
        if (oldValue != null) {
            getConfig().setProperty(newConfig, oldValue);
        }
    }

    private void persistglobalExclusions() {
        ((HierarchicalConfiguration) getConfig()).clearTree(EXCLUSION_KEY);

        for (int i = 0, size = globalExclusions.size(); i < size; ++i) {
            String elementBaseKey = EXCLUSION_KEY + "(" + i + ").";
            GlobalExclusion exclusion = globalExclusions.get(i);

            getConfig()
                    .setProperty(elementBaseKey + GLOBAL_EXCLUSION_NAME_KEY, exclusion.getName());
            getConfig()
                    .setProperty(elementBaseKey + GLOBAL_EXCLUSION_VALUE_KEY, exclusion.getValue());
            getConfig()
                    .setProperty(
                            elementBaseKey + GLOBAL_EXCLUSION_ENABLED_KEY, exclusion.isEnabled());
        }
    }

    /**
     * Sets the global exclusions.
     *
     * @param globalExclusions the global exclusions.
     * @throws NullPointerException if the given list is {@code null}.
     */
    public void setGlobalExclusions(List<GlobalExclusion> globalExclusions) {
        Objects.requireNonNull(globalExclusions);

        this.globalExclusions = new ArrayList<>(globalExclusions);
        persistglobalExclusions();

        refreshUrls = true;
    }

    /**
     * Gets all the global exclusions.
     *
     * @return the list of global exclusions, never {@code null}.
     */
    public List<GlobalExclusion> getGlobalExclusions() {
        return globalExclusions;
    }

    public List<String> getUrls() {
        if (refreshUrls) {
            urls =
                    globalExclusions.stream()
                            .filter(GlobalExclusion::isEnabled)
                            .map(GlobalExclusion::getValue)
                            .collect(Collectors.toList());
            refreshUrls = false;
        }
        return urls;
    }

    /**
     * Sets whether or not the removal of a global exclusion needs confirmation.
     *
     * @param confirmRemove {@code true} if the removal needs confirmation, {@code false} otherwise.
     */
    public void setConfirmRemoveGlobalExclusions(boolean confirmRemove) {
        this.confirmRemoveGlobalExclusions = confirmRemove;
        getConfig().setProperty(GLOBAL_EXCLUSIONS_CONFIRM_REMOVE, confirmRemoveGlobalExclusions);
    }

    /**
     * Tells whether or not the removal of a global exclusion needs confirmation.
     *
     * @return {@code true} if the removal needs confirmation, {@code false} otherwise.
     */
    public boolean isConfirmRemoveGlobalExclusions() {
        return confirmRemoveGlobalExclusions;
    }

    private static boolean validateGlobalExclusionPattern(String value) {
        try {
            return GlobalExclusion.validatePattern(value);
        } catch (IllegalArgumentException e) {
            LOGGER.warn("Ignoring invalid global exclusion pattern: {}", value, e);
            return false;
        }
    }
}
