/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.zap.extension.quickstart;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.zap.common.VersionedAbstractParam;
import org.zaproxy.zap.extension.api.ZapApiIgnore;
import org.zaproxy.zap.extension.quickstart.ajaxspider.AjaxSpiderExplorer;

public class QuickStartParam extends VersionedAbstractParam {

    private static final Logger LOGGER = LogManager.getLogger(QuickStartParam.class);

    private static final String PARAM_BASE_KEY = "quickstart";

    private static final String PARAM_TRAD_SPIDER_ENABLED = PARAM_BASE_KEY + ".tradSpider";

    private static final String PARAM_RECENT_URLS = PARAM_BASE_KEY + ".recentUrls";

    private static final String PARAM_MAX_RECENT_URLS = PARAM_BASE_KEY + ".maxRecentUrls";

    private static final String PARAM_LAUNCH_BASE_KEY = PARAM_BASE_KEY + ".launch";

    private static final String PARAM_START_PAGE = PARAM_LAUNCH_BASE_KEY + ".startPage";

    private static final String PARAM_DEFAULT_BROWSER = PARAM_LAUNCH_BASE_KEY + ".defaultBrowser";

    private static final String ZAP_START_PAGE = "ZAP";

    private static final String BLANK_START_PAGE = "BLANK";

    private static final String DEFAULT_BROWSER = "Firefox"; // The default default ;)

    private static final String PARAM_AJAX_BASE_KEY = PARAM_BASE_KEY + ".ajax";

    private static final String PARAM_AJAX_SPIDER_ENABLED = PARAM_AJAX_BASE_KEY + ".enabled";

    private static final String PARAM_AJAX_SPIDER_SELECTION = PARAM_AJAX_BASE_KEY + ".select";

    private static final String PARAM_AJAX_SPIDER_DEFAULT_BROWSER =
            PARAM_AJAX_BASE_KEY + ".browser";

    private static final String PARAM_CLEARED_NEWS_ITEM = PARAM_BASE_KEY + ".clearedNews";

    /**
     * The current version of the configurations. Used to keep track of configuration changes
     * between releases, in case changes/updates are needed.
     *
     * <p>It only needs to be incremented for configuration changes (not releases of the add-on).
     *
     * @see #CONFIG_VERSION_KEY
     * @see #updateConfigsImpl(int)
     */
    private static final int CURRENT_CONFIG_VERSION = 1;

    /**
     * The configuration key to read/write the version of the configurations.
     *
     * @see #CURRENT_CONFIG_VERSION
     */
    private static final String CONFIG_VERSION_KEY = PARAM_BASE_KEY + VERSION_ATTRIBUTE;

    private boolean isTradSpiderEnabled;
    private List<Object> recentUrls = new ArrayList<>(0);
    private int maxRecentUrls;
    private String launchStartPage;
    private String launchDefaultBrowser = DEFAULT_BROWSER;

    private String ajaxSpiderSelection;
    private String ajaxSpiderDefaultBrowser;
    private String clearedNewsItem;

    @Override
    protected void parseImpl() {
        try {
            isTradSpiderEnabled = getConfig().getBoolean(PARAM_TRAD_SPIDER_ENABLED, true);
        } catch (Exception e) {
            LOGGER.error("Failed to load the trad spider configuration", e);
        }
        try {
            recentUrls = getConfig().getList(PARAM_RECENT_URLS, new ArrayList<>(0));
        } catch (Exception e) {
            LOGGER.error("Failed to load the recent urls configuration", e);
        }
        try {
            maxRecentUrls = getConfig().getInt(PARAM_MAX_RECENT_URLS, 5);
        } catch (Exception e) {
            LOGGER.error("Failed to load the recent urls configuration", e);
        }
        try {
            launchStartPage = getConfig().getString(PARAM_START_PAGE, ZAP_START_PAGE);
        } catch (Exception e) {
            LOGGER.error("Failed to load the \"Start Page\" configuration", e);
        }
        try {
            launchDefaultBrowser = getConfig().getString(PARAM_DEFAULT_BROWSER, DEFAULT_BROWSER);
        } catch (Exception e) {
            LOGGER.error("Failed to load the \"Default Browser\" configuration", e);
        }
        try {
            ajaxSpiderSelection =
                    getConfig()
                            .getString(
                                    PARAM_AJAX_SPIDER_SELECTION,
                                    AjaxSpiderExplorer.Select.MODERN.name());
        } catch (Exception e) {
            LOGGER.error("Failed to load the ajax spider selection", e);
        }
        try {
            ajaxSpiderDefaultBrowser =
                    getConfig().getString(PARAM_AJAX_SPIDER_DEFAULT_BROWSER, DEFAULT_BROWSER);
        } catch (Exception e) {
            LOGGER.error("Failed to load the Ajax \"Default Browser\" configuration", e);
        }
        try {
            clearedNewsItem = getConfig().getString(PARAM_CLEARED_NEWS_ITEM, "");
        } catch (Exception e) {
            LOGGER.error("Failed to load the cleared news item configuration", e);
        }
    }

    @Override
    @ZapApiIgnore
    protected String getConfigVersionKey() {
        return CONFIG_VERSION_KEY;
    }

    @Override
    @ZapApiIgnore
    protected int getCurrentVersion() {
        return CURRENT_CONFIG_VERSION;
    }

    @Override
    protected void updateConfigsImpl(int fileVersion) {
        switch (fileVersion) {
            case -1:
                // Previously unversioned
                getConfig().clearProperty(PARAM_AJAX_SPIDER_ENABLED);
                break;
            default:
        }
    }

    public String getLaunchStartPage() {
        return launchStartPage;
    }

    public boolean isLaunchZapStartPage() {
        return ZAP_START_PAGE.equals(launchStartPage);
    }

    public boolean isLaunchBlankStartPage() {
        return BLANK_START_PAGE.equals(launchStartPage);
    }

    public void setLaunchZapStartPage() {
        setLaunchStartPage(ZAP_START_PAGE);
    }

    public void setLaunchBlankStartPage() {
        setLaunchStartPage(BLANK_START_PAGE);
    }

    public void setLaunchStartPage(URL url) {
        if (url == null) {
            setLaunchZapStartPage();
        } else {
            setLaunchStartPage(url.toString());
        }
    }

    private void setLaunchStartPage(String str) {
        this.launchStartPage = str;
        getConfig().setProperty(PARAM_START_PAGE, str);
    }

    public String getLaunchDefaultBrowser() {
        return launchDefaultBrowser;
    }

    public void setLaunchDefaultBrowser(String defaultBrowser) {
        this.launchDefaultBrowser = defaultBrowser;
        getConfig().setProperty(PARAM_DEFAULT_BROWSER, defaultBrowser);
    }

    public boolean isTradSpiderEnabled() {
        return this.isTradSpiderEnabled;
    }

    public void setTradSpiderEnabled(boolean isTradSpiderEnabled) {
        this.isTradSpiderEnabled = isTradSpiderEnabled;
        getConfig().setProperty(PARAM_TRAD_SPIDER_ENABLED, isTradSpiderEnabled);
        QuickStartHelper.raiseOptionsChangedEvent();
    }

    public String getAjaxSpiderSelection() {
        return ajaxSpiderSelection;
    }

    public void setAjaxSpiderSelection(String ajaxSpiderSelection) {
        this.ajaxSpiderSelection = ajaxSpiderSelection;
        getConfig().setProperty(PARAM_AJAX_SPIDER_SELECTION, ajaxSpiderSelection);
        QuickStartHelper.raiseOptionsChangedEvent();
    }

    public String getAjaxSpiderDefaultBrowser() {
        return ajaxSpiderDefaultBrowser;
    }

    public void setAjaxSpiderDefaultBrowser(String ajaxSpiderDefaultBrowser) {
        this.ajaxSpiderDefaultBrowser = ajaxSpiderDefaultBrowser;
        getConfig().setProperty(PARAM_AJAX_SPIDER_DEFAULT_BROWSER, ajaxSpiderDefaultBrowser);
        QuickStartHelper.raiseOptionsChangedEvent();
    }

    public List<Object> getRecentUrls() {
        return this.recentUrls;
    }

    public void addRecentUrl(String url) {
        // Always remove to force it to the top of the list
        this.recentUrls.remove(url);
        this.recentUrls.add(0, url);
        while (this.recentUrls.size() > this.maxRecentUrls) {
            this.recentUrls.remove(this.recentUrls.size() - 1);
        }
        getConfig().setProperty(PARAM_RECENT_URLS, this.recentUrls);
        QuickStartHelper.raiseOptionsChangedEvent();
    }

    public String getClearedNewsItem() {
        return clearedNewsItem;
    }

    public void setClearedNewsItem(String clearedNewsItem) {
        this.clearedNewsItem = clearedNewsItem;
        getConfig().setProperty(PARAM_CLEARED_NEWS_ITEM, clearedNewsItem);
    }
}
