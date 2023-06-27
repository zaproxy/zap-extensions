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

    protected static final int CURRENT_CONFIG_VERSION = 1;

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
                            "^.*\\.(?:gif|jpe?g|png|ico|icns|bmp)$",
                            false),
                    new GlobalExclusion(
                            "Extension - Audio/Video (ends with .extension)",
                            "^.*\\.(?:mp[34]|mpe?g|m4[ap]|aac|avi|mov|wmv|og[gav])$",
                            false),
                    new GlobalExclusion(
                            "Extension - PDF & Office (ends with .extension)",
                            "^.*\\.(?:pdf|docx?|xlsx?|pptx?)$",
                            false),
                    new GlobalExclusion(
                            "Extension - Stylesheet, JavaScript (ends with .extension)",
                            "^.*\\.(?:css|js)$",
                            false),
                    new GlobalExclusion(
                            "Extension - Flash & related (ends with .extension)",
                            "^.*\\.(?:sw[fa]|flv)$",
                            false),
                    new GlobalExclusion(
                            "ExtParam - Image (extension plus ?params=values)",
                            "^[^\\?]*\\.(?:gif|jpe?g|png|ico|icns|bmp)\\?.*$",
                            false),
                    new GlobalExclusion(
                            "ExtParam - Audio/Video (extension plus ?params=values)",
                            "^[^\\?]*\\.(?:mp[34]|mpe?g|m4[ap]|aac|avi|mov|wmv|og[gav])\\?.*$",
                            false),
                    new GlobalExclusion(
                            "ExtParam - PDF & Office (extension plus ?params=values)",
                            "^[^\\?]*\\.(?:pdf|docx?|xlsx?|pptx?)\\?.*$",
                            false),
                    new GlobalExclusion(
                            "ExtParam - Stylesheet, JavaScript (extension plus ?params=values)",
                            "^[^\\?]*\\.(?:css|js)\\?.*$",
                            false),
                    new GlobalExclusion(
                            "ExtParam - Flash & related (extension plus ?params=values)",
                            "^[^\\?]*\\.(?:sw[fa]|flv)\\?.*$",
                            false),
                    new GlobalExclusion(
                            "ExtParam - .NET adx resources (SR/WR.adx?d=)",
                            "^[^\\?]*/(?:WebResource|ScriptResource)\\.axd\\?d=.*$",
                            false),
                    new GlobalExclusion(
                            "Site - Bing API queries",
                            "^https?://api\\.bing\\.com/qsml\\.aspx?query=.*$",
                            false),
                    new GlobalExclusion(
                            "Site - Google malware detector updates",
                            "^https?://(?:safebrowsing-cache|sb-ssl|sb|safebrowsing).*\\.(?:google|googleapis)\\.com/.*$",
                            true),
                    new GlobalExclusion(
                            "Site - Lastpass manager",
                            "^https?://(?:[^/])*\\.?lastpass\\.com",
                            false),
                    new GlobalExclusion(
                            "Site - Firefox browser updates",
                            "^https?://(?:.*addons|aus[0-9])\\.mozilla\\.(?:org|net|com)/.*$",
                            true),
                    new GlobalExclusion(
                            "Site - Firefox extensions phoning home",
                            "^https?://(?:[^/])*\\.?(?:getfoxyproxy\\.org|getfirebug\\.com|noscript\\.net)",
                            false),
                    new GlobalExclusion(
                            "Site - Microsoft Windows updates",
                            // http://serverfault.com/questions/332003/what-urls-must-be-in-ies-trusted-sites-list-to-allow-windows-update
                            "^https?://(?:.*update\\.microsoft|.*\\.windowsupdate)\\.com/.*$",
                            true),
                    new GlobalExclusion(
                            "Site - Google Chrome extension updates",
                            "^https?://clients2\\.google\\.com/service/update2/crx.*$",
                            true),
                    new GlobalExclusion(
                            "Site - Firefox captive portal detection",
                            "^https?://detectportal\\.firefox\\.com.*$",
                            true),
                    new GlobalExclusion(
                            "Site - Google Analytics",
                            "^https?://www\\.google-analytics\\.com.*$",
                            false),
                    new GlobalExclusion(
                            "Site - Firefox h264 codec download",
                            // https://support.mozilla.org/t5/Firefox/Where-is-a-check-that-http-ciscobinary-openh264-org-openh264-is/m-p/1316497#M1005892
                            "^https?://ciscobinary\\.openh264\\.org.*$",
                            false),
                    new GlobalExclusion(
                            "Site - Fonts CDNs such as fonts.gstatic.com, etc.",
                            "^https?://fonts.*$",
                            false),
                    new GlobalExclusion(
                            "Site - Mozilla CDN (requests such as getpocket)",
                            "^https?://.*\\.cdn\\.mozilla\\.(?:com|org|net)/.*$",
                            true),
                    new GlobalExclusion(
                            "Site - Firefox browser telemetry",
                            "^https?://.*\\.telemetry\\.mozilla\\.(?:com|org|net)/.*$",
                            true),
                    new GlobalExclusion(
                            "Site - Adblockplus updates and notifications",
                            "^https?://.*\\.adblockplus\\.org.*$",
                            false),
                    new GlobalExclusion(
                            "Site - Firefox services",
                            "^https?://.*\\.services\\.mozilla\\.com.*$",
                            true),
                    new GlobalExclusion(
                            "Site - Google updates", "^https?://.*\\.gvt1\\.com.*$", true));

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
