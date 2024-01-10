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
package org.zaproxy.addon.client;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.addon.commonlib.Constants;
import org.zaproxy.zap.common.VersionedAbstractParam;
import org.zaproxy.zap.extension.api.ZapApiIgnore;
import org.zaproxy.zap.extension.selenium.Browser;

public class ClientOptions extends VersionedAbstractParam {

    private static final Logger LOGGER = LogManager.getLogger(ClientOptions.class);

    protected static final int CURRENT_CONFIG_VERSION = 1;

    static final String CLIENT_BASE_KEY = "client";

    private static final String CONFIG_VERSION_KEY = CLIENT_BASE_KEY + VERSION_ATTRIBUTE;
    private static final String PSCAN_ENABLED_KEY = CLIENT_BASE_KEY + ".pscanEnabled";
    private static final String PSCAN_DISABLED_RULES_KEY = CLIENT_BASE_KEY + ".pscanRulesDisabled";
    private static final String BROWSER_ID_KEY = CLIENT_BASE_KEY + ".browserId";
    private static final String SHOW_ADV_OPTIONS_KEY = CLIENT_BASE_KEY + ".showAdvOptions";
    private static final String THREAD_COUNT_KEY = CLIENT_BASE_KEY + ".threads";
    private static final String INITIAL_LOAD_TIME_KEY = CLIENT_BASE_KEY + ".initialLoadTime";
    private static final String PAGE_LOAD_TIME_KEY = CLIENT_BASE_KEY + ".pageLoadTime";
    private static final String SHUTDOWN_TIME_KEY = CLIENT_BASE_KEY + ".shutdownTime";
    private static final String MAX_DEPTH_KEY = CLIENT_BASE_KEY + ".maxDepth";
    private static final String MAX_DURATION_KEY = CLIENT_BASE_KEY + ".maxDuration";
    private static final String MAX_CHILDREN_KEY = CLIENT_BASE_KEY + ".maxChildren";

    private static final String DEFAULT_BROWSER_ID = Browser.FIREFOX_HEADLESS.getId();

    private String browserId;
    private int threadCount;
    private int initialLoadTimeInSecs;
    private int pageLoadTimeInSecs;
    private int shutdownTimeInSecs;
    private boolean pscanEnabled;
    private List<Integer> pscanRulesDisabled;
    private boolean showAdvancedDialog;
    private int maxChildren;
    private int maxDepth = 5;
    private int maxDuration;

    @Override
    public ClientOptions clone() {
        return (ClientOptions) super.clone();
    }

    @Override
    protected void parseImpl() {
        this.pscanEnabled = getBoolean(PSCAN_ENABLED_KEY, true);
        this.browserId = getString(BROWSER_ID_KEY, DEFAULT_BROWSER_ID);
        this.threadCount = Math.max(1, getInt(THREAD_COUNT_KEY, Constants.getDefaultThreadCount()));
        this.initialLoadTimeInSecs = getInt(INITIAL_LOAD_TIME_KEY, 5);
        this.pageLoadTimeInSecs = getInt(PAGE_LOAD_TIME_KEY, 1);
        this.shutdownTimeInSecs = getInt(SHUTDOWN_TIME_KEY, 5);
        this.maxChildren = getInt(MAX_CHILDREN_KEY, 0);
        this.maxDepth = getInt(MAX_DEPTH_KEY, 5);
        this.maxDuration = getInt(MAX_DURATION_KEY, 0);

        try {
            pscanRulesDisabled =
                    getConfig().getList(PSCAN_DISABLED_RULES_KEY).stream()
                            .map(Object::toString)
                            .map(Integer::parseInt)
                            .collect(Collectors.toList());
        } catch (Exception e) {
            LOGGER.warn(e.getMessage(), e);
            pscanRulesDisabled = new ArrayList<>();
        }
        browserId = getString(BROWSER_ID_KEY, DEFAULT_BROWSER_ID);
        try {
            Browser.getBrowserWithId(browserId);
        } catch (IllegalArgumentException e) {
            LOGGER.warn(
                    "Unknown browser [{}] using default [{}].", browserId, DEFAULT_BROWSER_ID, e);
            browserId = DEFAULT_BROWSER_ID;
        }
        this.showAdvancedDialog = getBoolean(SHOW_ADV_OPTIONS_KEY, false);
    }

    @Override
    protected int getCurrentVersion() {
        return CURRENT_CONFIG_VERSION;
    }

    @Override
    protected void updateConfigsImpl(int fileVersion) {
        // first version, nothing to update yet
    }

    @Override
    protected String getConfigVersionKey() {
        return CONFIG_VERSION_KEY;
    }

    public boolean isPscanEnabled() {
        return pscanEnabled;
    }

    public void setPscanEnabled(boolean pscanEnabled) {
        this.pscanEnabled = pscanEnabled;
        getConfig().setProperty(PSCAN_ENABLED_KEY, pscanEnabled);
    }

    public List<Integer> getPscanRulesDisabled() {
        return pscanRulesDisabled;
    }

    public void setPscanRulesDisabled(List<Integer> pscanDisabled) {
        this.pscanRulesDisabled = pscanDisabled;
        getConfig().setProperty(PSCAN_DISABLED_RULES_KEY, pscanDisabled);
    }

    public String getBrowserId() {
        return browserId;
    }

    public void setBrowserId(String browserId) {
        this.browserId = browserId;
        getConfig().setProperty(BROWSER_ID_KEY, browserId);
    }

    @ZapApiIgnore
    public boolean isShowAdvancedDialog() {
        return this.showAdvancedDialog;
    }

    @ZapApiIgnore
    public void setShowAdvancedDialog(boolean show) {
        this.showAdvancedDialog = show;
        getConfig().setProperty(SHOW_ADV_OPTIONS_KEY, Boolean.valueOf(showAdvancedDialog));
    }

    public int getThreadCount() {
        return threadCount;
    }

    public void setThreadCount(int threadCount) {
        this.threadCount = threadCount;
        getConfig().setProperty(THREAD_COUNT_KEY, threadCount);
    }

    public int getInitialLoadTimeInSecs() {
        return initialLoadTimeInSecs;
    }

    public void setInitialLoadTimeInSecs(int initialLoadTimeInSecs) {
        this.initialLoadTimeInSecs = initialLoadTimeInSecs;
        getConfig().setProperty(INITIAL_LOAD_TIME_KEY, initialLoadTimeInSecs);
    }

    public int getPageLoadTimeInSecs() {
        return pageLoadTimeInSecs;
    }

    public void setPageLoadTimeInSecs(int pageLoadTimeInSecs) {
        this.pageLoadTimeInSecs = pageLoadTimeInSecs;
        getConfig().setProperty(PAGE_LOAD_TIME_KEY, pageLoadTimeInSecs);
    }

    public int getShutdownTimeInSecs() {
        return shutdownTimeInSecs;
    }

    public void setShutdownTimeInSecs(int shutdownTimeInSecs) {
        this.shutdownTimeInSecs = shutdownTimeInSecs;
        getConfig().setProperty(SHUTDOWN_TIME_KEY, shutdownTimeInSecs);
    }

    public int getMaxChildren() {
        return maxChildren;
    }

    public void setMaxChildren(int maxChildren) {
        this.maxChildren = maxChildren;
        getConfig().setProperty(MAX_CHILDREN_KEY, maxChildren);
    }

    public int getMaxDepth() {
        return maxDepth;
    }

    public void setMaxDepth(int maxDepth) {
        this.maxDepth = maxDepth;
        getConfig().setProperty(MAX_DEPTH_KEY, maxDepth);
    }

    public int getMaxDuration() {
        return maxDuration;
    }

    public void setMaxDuration(int maxDuration) {
        this.maxDuration = maxDuration;
        getConfig().setProperty(MAX_DURATION_KEY, maxDuration);
    }
}
