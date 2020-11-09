/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.spiderAjax;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import org.apache.commons.configuration.ConversionException;
import org.apache.commons.configuration.HierarchicalConfiguration;
import org.apache.log4j.Logger;
import org.zaproxy.zap.common.VersionedAbstractParam;
import org.zaproxy.zap.extension.api.ZapApiIgnore;
import org.zaproxy.zap.extension.selenium.Browser;

public class AjaxSpiderParam extends VersionedAbstractParam {

    private static final Logger logger = Logger.getLogger(AjaxSpiderParam.class);

    /**
     * The current version of the configurations. Used to keep track of configuration changes
     * between releases, in case changes/updates are needed.
     *
     * <p>It only needs to be incremented for configuration changes (not releases of the add-on).
     *
     * @see #CONFIG_VERSION_KEY
     * @see #updateConfigsImpl(int)
     */
    private static final int CURRENT_CONFIG_VERSION = 4;

    private static final String AJAX_SPIDER_BASE_KEY = "ajaxSpider";

    /**
     * The configuration key for the version of the configurations.
     *
     * @see #CURRENT_CONFIG_VERSION
     */
    private static final String CONFIG_VERSION_KEY = AJAX_SPIDER_BASE_KEY + VERSION_ATTRIBUTE;

    private static final String OLD_CONFIG_VERSION_KEY = AJAX_SPIDER_BASE_KEY + ".configVersion";

    private static final String NUMBER_OF_BROWSERS_KEY = AJAX_SPIDER_BASE_KEY + ".numberOfBrowsers";

    private static final String MAX_CRAWL_DEPTH_KEY = AJAX_SPIDER_BASE_KEY + ".maxCrawlDepth";

    private static final String MAX_CRAWL_STATES_KEY = AJAX_SPIDER_BASE_KEY + ".maxCrawlStates";

    private static final String MAX_DURATION_KEY = AJAX_SPIDER_BASE_KEY + ".maxDuration";

    private static final String EVENT_WAIT_TIME_KEY = AJAX_SPIDER_BASE_KEY + ".eventWait";

    private static final String RELOAD_WAIT_TIME_KEY = AJAX_SPIDER_BASE_KEY + ".reloadWait";

    private static final String BROWSER_ID_KEY = AJAX_SPIDER_BASE_KEY + ".browserId";

    private static final String CLICK_DEFAULT_ELEMS_KEY =
            AJAX_SPIDER_BASE_KEY + ".clickDefaultElems";

    private static final String CLICK_ELEMS_ONCE_KEY = AJAX_SPIDER_BASE_KEY + ".clickElemsOnce";

    private static final String RANDOM_INPUTS_KEY = AJAX_SPIDER_BASE_KEY + ".randomInputs";

    private static final String SHOW_ADV_OPTIONS_KEY = AJAX_SPIDER_BASE_KEY + ".showAdvOptions";

    private static final String ALL_ELEMS_KEY = AJAX_SPIDER_BASE_KEY + ".elems.elem";

    private static final String ELEM_NAME_KEY = "name";

    private static final String ELEM_ENABLED_KEY = "enabled";

    private static final String CONFIRM_REMOVE_ELEM_KEY =
            AJAX_SPIDER_BASE_KEY + ".confirmRemoveElem";

    private static final String[] DEFAULT_ELEMS_NAMES = {
        "a",
        "button",
        "td",
        "span",
        "div",
        "tr",
        "ol",
        "li",
        "radio",
        "form",
        "select",
        "input",
        "option",
        "img",
        "p",
        "abbr",
        "address",
        "area",
        "article",
        "aside",
        "audio",
        "canvas",
        "details",
        "footer",
        "header",
        "label",
        "nav",
        "section",
        "summary",
        "table",
        "textarea",
        "th",
        "ul",
        "video"
    };

    private static final int DEFAULT_NUMBER_OF_BROWSERS = 1;

    private static final int DEFAULT_MAX_CRAWL_DEPTH = 10;

    private static final int DEFAULT_CRAWL_STATES = 0;

    private static final int DEFAULT_MAX_DURATION = 60;

    private static final int DEFAULT_EVENT_WAIT_TIME = 1000;

    private static final int DEFAULT_RELOAD_WAIT_TIME = 1000;

    private static final String DEFAULT_BROWSER_ID = Browser.FIREFOX_HEADLESS.getId();

    private static final boolean DEFAULT_CLICK_DEFAULT_ELEMS = true;

    private static final boolean DEFAULT_CLICK_ELEMS_ONCE = true;

    private static final boolean DEFAULT_RANDOM_INPUTS = true;

    private static final String ALL_ALLOWED_RESOURCES_KEY =
            AJAX_SPIDER_BASE_KEY + ".allowedResources.allowedResource";

    private static final String ALLOWED_RESOURCE_REGEX_KEY = "regex";

    private static final String ALLOWED_RESOURCE_ENABLED_KEY = "enabled";

    private static final String CONFIRM_REMOVE_ALLOWED_RESOURCE =
            AJAX_SPIDER_BASE_KEY + ".confirmRemoveAllowedResource";

    private static final List<AllowedResource> DEFAULT_ALLOWED_RESOURCES =
            Arrays.asList(
                    new AllowedResource(
                            AllowedResource.createDefaultPattern("^http.*\\.js(?:\\?.*)?$")),
                    new AllowedResource(
                            AllowedResource.createDefaultPattern("^http.*\\.css(?:\\?.*)?$")));

    private int numberOfBrowsers;
    private int maxCrawlDepth;
    private int maxCrawlStates;
    private int maxDuration;
    private int eventWait;
    private int reloadWait;

    private List<AjaxSpiderParamElem> elems = null;
    private List<String> enabledElemsNames = null;

    private String browserId;

    private boolean clickDefaultElems;
    private boolean clickElemsOnce;
    private boolean randomInputs;
    private boolean confirmRemoveElem = true;
    private boolean showAdvancedDialog;

    private boolean confirmRemoveAllowedResource;
    private List<AllowedResource> allowedResources = Collections.emptyList();

    @Override
    public AjaxSpiderParam clone() {
        return (AjaxSpiderParam) super.clone();
    }

    @Override
    protected int getCurrentVersion() {
        return CURRENT_CONFIG_VERSION;
    }

    @Override
    protected String getConfigVersionKey() {
        return CONFIG_VERSION_KEY;
    }

    @Override
    protected int readConfigFileVersion() {
        int version = super.readConfigFileVersion();
        if (version == NO_CONFIG_VERSION) {
            version = getConfig().getInt(OLD_CONFIG_VERSION_KEY, NO_CONFIG_VERSION);
        }
        return version;
    }

    @Override
    protected void parseImpl() {
        try {
            this.numberOfBrowsers =
                    getConfig().getInt(NUMBER_OF_BROWSERS_KEY, DEFAULT_NUMBER_OF_BROWSERS);
        } catch (ConversionException e) {
            logger.error("Error while loading the number of browsers: " + e.getMessage(), e);
        }

        try {
            this.maxCrawlDepth = getConfig().getInt(MAX_CRAWL_DEPTH_KEY, DEFAULT_MAX_CRAWL_DEPTH);
        } catch (ConversionException e) {
            logger.error("Error while loading the max crawl depth: " + e.getMessage(), e);
        }

        try {
            this.maxCrawlStates = getConfig().getInt(MAX_CRAWL_STATES_KEY, DEFAULT_CRAWL_STATES);
        } catch (ConversionException e) {
            logger.error("Error while loading max crawl states: " + e.getMessage(), e);
        }

        try {
            this.maxDuration = getConfig().getInt(MAX_DURATION_KEY, DEFAULT_MAX_DURATION);
        } catch (ConversionException e) {
            logger.error("Error while loading the crawl duration: " + e.getMessage(), e);
        }

        try {
            this.eventWait = getConfig().getInt(EVENT_WAIT_TIME_KEY, DEFAULT_EVENT_WAIT_TIME);
        } catch (ConversionException e) {
            logger.error("Error while loading the event wait time: " + e.getMessage(), e);
        }

        try {
            this.reloadWait = getConfig().getInt(RELOAD_WAIT_TIME_KEY, DEFAULT_RELOAD_WAIT_TIME);
        } catch (ConversionException e) {
            logger.error("Error while loading the reload wait time: " + e.getMessage(), e);
        }

        try {
            browserId = getConfig().getString(BROWSER_ID_KEY, DEFAULT_BROWSER_ID);
        } catch (ConversionException e) {
            logger.error("Error while loading the browser id: " + e.getMessage(), e);
            browserId = DEFAULT_BROWSER_ID;
        }
        try {
            Browser.getBrowserWithId(browserId);
        } catch (IllegalArgumentException e) {
            logger.warn(
                    "Unknow browser ["
                            + browserId
                            + "] using default ["
                            + DEFAULT_BROWSER_ID
                            + "].",
                    e);
            browserId = DEFAULT_BROWSER_ID;
        }

        try {
            this.clickDefaultElems =
                    getConfig().getBoolean(CLICK_DEFAULT_ELEMS_KEY, DEFAULT_CLICK_DEFAULT_ELEMS);
        } catch (ConversionException e) {
            logger.error("Error while loading the click default option: " + e.getMessage(), e);
        }

        try {
            this.clickElemsOnce =
                    getConfig().getBoolean(CLICK_ELEMS_ONCE_KEY, DEFAULT_CLICK_ELEMS_ONCE);
        } catch (ConversionException e) {
            logger.error("Error while loading the click once option: " + e.getMessage(), e);
        }

        try {
            this.randomInputs = getConfig().getBoolean(RANDOM_INPUTS_KEY, DEFAULT_RANDOM_INPUTS);
        } catch (ConversionException e) {
            logger.error("Error while loading the random inputs option: " + e.getMessage(), e);
        }

        try {
            this.showAdvancedDialog = getConfig().getBoolean(SHOW_ADV_OPTIONS_KEY, false);
        } catch (ConversionException e) {
            logger.error("Error while loading the show advanced option: " + e.getMessage(), e);
        }

        try {
            List<HierarchicalConfiguration> fields =
                    ((HierarchicalConfiguration) getConfig()).configurationsAt(ALL_ELEMS_KEY);
            this.elems = new ArrayList<>(fields.size());
            enabledElemsNames = new ArrayList<>(fields.size());
            List<String> tempElemsNames = new ArrayList<>(fields.size());
            for (HierarchicalConfiguration sub : fields) {
                String name = sub.getString(ELEM_NAME_KEY, "");
                if (!"".equals(name) && !tempElemsNames.contains(name)) {
                    boolean enabled = sub.getBoolean(ELEM_ENABLED_KEY, true);
                    this.elems.add(new AjaxSpiderParamElem(name, enabled));
                    tempElemsNames.add(name);
                    if (enabled) {
                        enabledElemsNames.add(name);
                    }
                }
            }
        } catch (ConversionException e) {
            logger.error("Error while loading clickable elements: " + e.getMessage(), e);
            this.elems = new ArrayList<>(DEFAULT_ELEMS_NAMES.length);
            this.enabledElemsNames = new ArrayList<>(DEFAULT_ELEMS_NAMES.length);
        }

        if (this.elems.size() == 0) {
            for (String elemName : DEFAULT_ELEMS_NAMES) {
                this.elems.add(new AjaxSpiderParamElem(elemName));
                this.enabledElemsNames.add(elemName);
            }
        }

        try {
            this.confirmRemoveElem = getConfig().getBoolean(CONFIRM_REMOVE_ELEM_KEY, true);
        } catch (ConversionException e) {
            logger.error(
                    "Error while loading the confirm remove element option: " + e.getMessage(), e);
        }

        try {
            List<HierarchicalConfiguration> fields =
                    ((HierarchicalConfiguration) getConfig())
                            .configurationsAt(ALL_ALLOWED_RESOURCES_KEY);
            this.allowedResources = new ArrayList<>(fields.size());
            List<String> regexes = new ArrayList<>(fields.size());
            for (HierarchicalConfiguration sub : fields) {
                String regex = sub.getString(ALLOWED_RESOURCE_REGEX_KEY, "");
                if (!"".equals(regex) && !regexes.contains(regex)) {
                    boolean enabled = sub.getBoolean(ALLOWED_RESOURCE_ENABLED_KEY, true);
                    this.allowedResources.add(
                            new AllowedResource(
                                    AllowedResource.createDefaultPattern(regex), enabled));
                    regexes.add(regex);
                }
            }
        } catch (ConversionException e) {
            logger.error("Error while loading allowed resources: " + e.getMessage(), e);
            this.allowedResources = new ArrayList<>(DEFAULT_ALLOWED_RESOURCES);
        }
        confirmRemoveAllowedResource = getBoolean(CONFIRM_REMOVE_ALLOWED_RESOURCE, true);
    }

    @SuppressWarnings({"fallthrough"})
    @Override
    protected void updateConfigsImpl(int fileVersion) {
        switch (fileVersion) {
            case NO_CONFIG_VERSION:
                // No updates/changes needed, the configurations were not previously persisted
                // and the current version is already written after this method.
                break;
            case 1:
                String crawlInDepthKey = AJAX_SPIDER_BASE_KEY + ".crawlInDepth";
                try {
                    boolean crawlInDepth = getConfig().getBoolean(crawlInDepthKey, false);
                    getConfig()
                            .setProperty(CLICK_DEFAULT_ELEMS_KEY, Boolean.valueOf(!crawlInDepth));
                } catch (ConversionException e) {
                    logger.warn(
                            "Failed to read (old) configuration '"
                                    + crawlInDepthKey
                                    + "', no update will be made.");
                }
                getConfig().clearProperty(crawlInDepthKey);
                // $FALL-THROUGH$
            case 2:
                // Remove old version element, from now on the version is saved as an attribute of
                // root element
                getConfig().clearProperty(OLD_CONFIG_VERSION_KEY);
            case 3:
                setAllowedResources(DEFAULT_ALLOWED_RESOURCES);
        }
    }

    @Override
    public void reset() {
        super.reset();

        setAllowedResources(DEFAULT_ALLOWED_RESOURCES);
    }

    public int getNumberOfBrowsers() {
        return numberOfBrowsers;
    }

    public void setNumberOfBrowsers(int numberOfBrowsers) {
        this.numberOfBrowsers = numberOfBrowsers;
        getConfig().setProperty(NUMBER_OF_BROWSERS_KEY, Integer.valueOf(numberOfBrowsers));
    }

    public int getMaxCrawlDepth() {
        return maxCrawlDepth;
    }

    public void setMaxCrawlDepth(int maxCrawlDepth) {
        this.maxCrawlDepth = maxCrawlDepth;
        getConfig().setProperty(MAX_CRAWL_DEPTH_KEY, Integer.valueOf(maxCrawlDepth));
    }

    public int getMaxCrawlStates() {
        return maxCrawlStates;
    }

    public void setMaxCrawlStates(int maxCrawlStates) {
        this.maxCrawlStates = maxCrawlStates;
        getConfig().setProperty(MAX_CRAWL_STATES_KEY, Integer.valueOf(maxCrawlStates));
    }

    public int getMaxDuration() {
        return maxDuration;
    }

    public void setMaxDuration(int maxDuration) {
        this.maxDuration = maxDuration;
        getConfig().setProperty(MAX_DURATION_KEY, Integer.valueOf(maxDuration));
    }

    public int getEventWait() {
        return eventWait;
    }

    public void setEventWait(int eventWait) {
        this.eventWait = eventWait;
        getConfig().setProperty(EVENT_WAIT_TIME_KEY, Integer.valueOf(eventWait));
    }

    public int getReloadWait() {
        return reloadWait;
    }

    public void setReloadWait(int reloadWait) {
        this.reloadWait = reloadWait;
        getConfig().setProperty(RELOAD_WAIT_TIME_KEY, Integer.valueOf(reloadWait));
    }

    public String getBrowserId() {
        return browserId;
    }

    public void setBrowserId(String browserId) {
        this.browserId = browserId;
        getConfig().setProperty(BROWSER_ID_KEY, browserId);
    }

    public boolean isClickDefaultElems() {
        return clickDefaultElems;
    }

    public void setClickDefaultElems(boolean clickDefaultElems) {
        this.clickDefaultElems = clickDefaultElems;
        getConfig().setProperty(CLICK_DEFAULT_ELEMS_KEY, Boolean.valueOf(clickDefaultElems));
    }

    public boolean isClickElemsOnce() {
        return clickElemsOnce;
    }

    public void setClickElemsOnce(boolean clickElemsOnce) {
        this.clickElemsOnce = clickElemsOnce;
        getConfig().setProperty(CLICK_ELEMS_ONCE_KEY, Boolean.valueOf(clickElemsOnce));
    }

    public boolean isRandomInputs() {
        return randomInputs;
    }

    public void setRandomInputs(boolean randomInputs) {
        this.randomInputs = randomInputs;
        getConfig().setProperty(RANDOM_INPUTS_KEY, Boolean.valueOf(randomInputs));
    }

    protected List<AjaxSpiderParamElem> getElems() {
        return elems;
    }

    protected void setElems(List<AjaxSpiderParamElem> elems) {
        this.elems = new ArrayList<>(elems);

        ((HierarchicalConfiguration) getConfig()).clearTree(ALL_ELEMS_KEY);

        ArrayList<String> enabledElems = new ArrayList<>(elems.size());
        for (int i = 0, size = elems.size(); i < size; ++i) {
            String elementBaseKey = ALL_ELEMS_KEY + "(" + i + ").";
            AjaxSpiderParamElem elem = elems.get(i);

            getConfig().setProperty(elementBaseKey + ELEM_NAME_KEY, elem.getName());
            getConfig()
                    .setProperty(
                            elementBaseKey + ELEM_ENABLED_KEY, Boolean.valueOf(elem.isEnabled()));

            if (elem.isEnabled()) {
                enabledElems.add(elem.getName());
            }
        }

        enabledElems.trimToSize();
        this.enabledElemsNames = enabledElems;
    }

    protected List<String> getElemsNames() {
        return enabledElemsNames;
    }

    @ZapApiIgnore
    public boolean isConfirmRemoveElem() {
        return this.confirmRemoveElem;
    }

    @ZapApiIgnore
    public void setConfirmRemoveElem(boolean confirmRemove) {
        this.confirmRemoveElem = confirmRemove;
        getConfig().setProperty(CONFIRM_REMOVE_ELEM_KEY, Boolean.valueOf(confirmRemoveElem));
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

    @ZapApiIgnore
    public boolean isConfirmRemoveAllowedResource() {
        return this.confirmRemoveAllowedResource;
    }

    @ZapApiIgnore
    public void setConfirmRemoveAllowedResource(boolean confirmRemove) {
        this.confirmRemoveAllowedResource = confirmRemove;
        getConfig()
                .setProperty(
                        CONFIRM_REMOVE_ALLOWED_RESOURCE,
                        Boolean.valueOf(confirmRemoveAllowedResource));
    }

    @ZapApiIgnore
    public void setAllowedResources(List<AllowedResource> allowedResources) {
        this.allowedResources = new ArrayList<>(Objects.requireNonNull(allowedResources));

        ((HierarchicalConfiguration) getConfig()).clearTree(ALL_ALLOWED_RESOURCES_KEY);

        for (int i = 0, size = allowedResources.size(); i < size; ++i) {
            String allowedResourceBaseKey = ALL_ALLOWED_RESOURCES_KEY + "(" + i + ").";
            AllowedResource allowedResource = allowedResources.get(i);

            getConfig()
                    .setProperty(
                            allowedResourceBaseKey + ALLOWED_RESOURCE_REGEX_KEY,
                            allowedResource.getPattern().pattern());
            getConfig()
                    .setProperty(
                            allowedResourceBaseKey + ALLOWED_RESOURCE_ENABLED_KEY,
                            Boolean.valueOf(allowedResource.isEnabled()));
        }
    }

    /**
     * Gets the allowed resources.
     *
     * @return an unmodifiable list containing the allowed resources.
     */
    @ZapApiIgnore
    public List<AllowedResource> getAllowedResources() {
        return Collections.unmodifiableList(allowedResources);
    }
}
