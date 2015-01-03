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
 *	 http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.spiderAjax;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.configuration.ConversionException;
import org.apache.commons.configuration.HierarchicalConfiguration;
import org.apache.log4j.Logger;
import org.parosproxy.paros.common.AbstractParam;
import org.zaproxy.zap.extension.api.ZapApiIgnore;

public class AjaxSpiderParam extends AbstractParam {

    private static final Logger logger = Logger.getLogger(AjaxSpiderParam.class);

    public enum Browser {
        CHROME("chrome"),
        FIREFOX("firefox"),
        HTML_UNIT("htmlunit"),
        PHANTOM_JS("phantomjs"),
        INTERNET_EXPLORER("ie");

        private final String id;

        private Browser(String id) {
            this.id = id;
        }

        private static Browser getBrowserById(String id) {
            if (CHROME.id.equals(id)) {
                return CHROME;
            } else if (FIREFOX.id.equals(id)) {
                return FIREFOX;
            } else if (HTML_UNIT.id.equals(id)) {
                return HTML_UNIT;
            } else if (PHANTOM_JS.id.equals(id)) {
                return PHANTOM_JS;
            } else if (INTERNET_EXPLORER.id.equals(id)) {
                return INTERNET_EXPLORER;
            }
            return FIREFOX;
        }
    };

    /**
     * The current version of the configurations. Used to keep track of configuration changes between releases, in case
     * changes/updates are needed.
     * <p>
     * It only needs to be incremented for configuration changes (not releases of the add-on).
     * 
     * @see #CONFIG_VERSION_KEY
     * @see #NO_CONFIG_VERSION
     * @see #ERROR_READING_CONFIG_VERSION
     * @see #updateConfigFile()
     */
    private static final int CURRENT_CONFIG_VERSION = 2;

    /**
     * A dummy version number used at runtime to indicate that the configurations were never persisted.
     * 
     * @see #CURRENT_CONFIG_VERSION
     * @see #ERROR_READING_CONFIG_VERSION
     */
    private static final int NO_CONFIG_VERSION = -1;

    /**
     * A dummy version number used at runtime to indicate that an error occurred while reading the version from the file.
     * 
     * @see #CURRENT_CONFIG_VERSION
     * @see #NO_CONFIG_VERSION
     */
    private static final int ERROR_READING_CONFIG_VERSION = -2;

    private static final String AJAX_SPIDER_BASE_KEY = "ajaxSpider";

    /**
     * The configuration key for the version of the configurations.
     * 
     * @see #CURRENT_CONFIG_VERSION
     */
    private static final String CONFIG_VERSION_KEY = AJAX_SPIDER_BASE_KEY + ".configVersion";

    private static final String NUMBER_OF_BROWSERS_KEY = AJAX_SPIDER_BASE_KEY + ".numberOfBrowsers";

    private static final String MAX_CRAWL_DEPTH_KEY = AJAX_SPIDER_BASE_KEY + ".maxCrawlDepth";

    private static final String MAX_CRAWL_STATES_KEY = AJAX_SPIDER_BASE_KEY + ".maxCrawlStates";
 
    private static final String MAX_DURATION_KEY = AJAX_SPIDER_BASE_KEY + ".maxDuration";
    
    private static final String EVENT_WAIT_TIME_KEY = AJAX_SPIDER_BASE_KEY + ".eventWait";
    
    private static final String RELOAD_WAIT_TIME_KEY = AJAX_SPIDER_BASE_KEY + ".reloadWait";

    private static final String BROWSER_ID_KEY = AJAX_SPIDER_BASE_KEY + ".browserId";

    private static final String CLICK_DEFAULT_ELEMS_KEY = AJAX_SPIDER_BASE_KEY + ".clickDefaultElems";
    
    private static final String CLICK_ELEMS_ONCE_KEY = AJAX_SPIDER_BASE_KEY + ".clickElemsOnce";
    
    private static final String RANDOM_INPUTS_KEY = AJAX_SPIDER_BASE_KEY + ".randomInputs";
    
    private static final String ALL_ELEMS_KEY = AJAX_SPIDER_BASE_KEY + ".elems.elem";
    
    private static final String ELEM_NAME_KEY = "name";
    
    private static final String ELEM_ENABLED_KEY = "enabled";
    
    private static final String CONFIRM_REMOVE_ELEM_KEY = AJAX_SPIDER_BASE_KEY + ".confirmRemoveElem";
    
    private static final String[] DEFAULT_ELEMS_NAMES = {"a","button","td","span","div","tr","ol","li","radio",
    	"form","select","input","option","img","p","abbr","address","area","article","aside","audio","canvas",
    	"details","footer","header","label","nav","section","summary","table","textarea","th","ul","video"};
    
    private static final int DEFAULT_NUMBER_OF_BROWSERS = 1;
    
    private static final int DEFAULT_MAX_CRAWL_DEPTH = 10;
    
    private static final int DEFAULT_CRAWL_STATES = 0;
    
    private static final int DEFAULT_MAX_DURATION = 60;
    
    private static final int DEFAULT_EVENT_WAIT_TIME = 1000;
    
    private static final int DEFAULT_RELOAD_WAIT_TIME = 1000;

    private static final Browser DEFAULT_BROWSER = Browser.FIREFOX;

    private static final boolean DEFAULT_CLICK_DEFAULT_ELEMS = true;

    private static final boolean DEFAULT_CLICK_ELEMS_ONCE = true;
    
    private static final boolean DEFAULT_RANDOM_INPUTS = true;

    private int numberOfBrowsers;
    private int numberOfThreads;
    private int maxCrawlDepth;
    private int maxCrawlStates;
    private int maxDuration;
    private int eventWait;
    private int reloadWait;
    
    private List<AjaxSpiderParamElem> elems = null;
    private List<String> enabledElemsNames = null;

    private Browser browser;

    private boolean clickDefaultElems;
    private boolean clickElemsOnce;
    private boolean randomInputs;
    private boolean confirmRemoveElem = true;
    

    @Override
    protected void parse() {
        updateConfigFile();

        try {
            this.numberOfBrowsers = getConfig().getInt(NUMBER_OF_BROWSERS_KEY, DEFAULT_NUMBER_OF_BROWSERS);
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
        
        String browserId;
        try {
            browserId = getConfig().getString(BROWSER_ID_KEY, DEFAULT_BROWSER.id);
        } catch (ConversionException e) {
            logger.error("Error while loading the browser id: " + e.getMessage(), e);
            browserId = DEFAULT_BROWSER.id;
        }
        try {
            this.browser = Browser.getBrowserById(browserId);
        } catch (IllegalArgumentException e) {
            logger.warn("Unknow browser [" + browserId + "] using default [" + DEFAULT_BROWSER.id + "].", e);
            this.browser = DEFAULT_BROWSER;
        }

        try {
            this.clickDefaultElems = getConfig().getBoolean(CLICK_DEFAULT_ELEMS_KEY, DEFAULT_CLICK_DEFAULT_ELEMS);
        } catch (ConversionException e) {
            logger.error("Error while loading the click default option: " + e.getMessage(), e);
        }
        
        try {
            this.clickElemsOnce = getConfig().getBoolean(CLICK_ELEMS_ONCE_KEY, DEFAULT_CLICK_ELEMS_ONCE);
        } catch (ConversionException e) {
            logger.error("Error while loading the click once option: " + e.getMessage(), e);
        }      
        
        try {
            this.randomInputs = getConfig().getBoolean(RANDOM_INPUTS_KEY, DEFAULT_RANDOM_INPUTS);
        } catch (ConversionException e) {
            logger.error("Error while loading the random inputs option: " + e.getMessage(), e);
        }    
        
        try {
            List<HierarchicalConfiguration> fields = ((HierarchicalConfiguration) getConfig()).configurationsAt(ALL_ELEMS_KEY);
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
            logger.error("Error while loading the confirm remove element option: " + e.getMessage(), e);
        }
    }

    /**
     * Updates the configurations in the file, if needed.
     * <p>
     * The following steps are made:
     * <ol>
     * <li>Read the version of the configurations that are in the file;</li>
     * <li>Check if the version read is the latest version;</li>
     * <li>If it's not at the latest version, update the configurations.</li>
     * </ol>
     * 
     * @see #CURRENT_CONFIG_VERSION
     * @see #isLatestConfigVersion(int)
     * @see #updateConfigsFromVersion(int)
     */
    private void updateConfigFile() {
        int configVersion;
        try {
            configVersion = getConfig().getInt(CONFIG_VERSION_KEY, NO_CONFIG_VERSION);
        } catch (ConversionException e) {
            logger.error("Error while getting the version of the configurations: " + e.getMessage(), e);
            configVersion = ERROR_READING_CONFIG_VERSION;
        }

        if (!isLatestConfigVersion(configVersion)) {
            updateConfigsFromVersion(configVersion);
        }
    }

    /**
     * Tells whether or not the given {@code version} number is the latest version, that is, is the same version number as the
     * version of the running code.
     *
     * @param version the version that will be checked
     * @return {@code true} if the given {@code version} is the latest version, {@code false} otherwise
     * @see #CURRENT_CONFIG_VERSION
     * @see #updateConfigFile() 
     */
    private static boolean isLatestConfigVersion(int version) {
        return version == CURRENT_CONFIG_VERSION;
    }

    /**
     * Called when the configuration version in the file is different than the version of the running code.
     * <p>
     * Any required configuration changes/updates should be added to this method.
     * <p>
     * If the given {@code fileVersion} is:
     * <ul>
     * <li>&lt; {@code CURRENT_CONFIG_VERSION} - expected case, the configurations are changed/updated to the current version.
     * Before returning the version in the configuration file is updated to the current version.</li>
     * <li>&gt; {@code CURRENT_CONFIG_VERSION} - no changes/updates are made, the method logs a warn and returns;</li>
     * <li>{@code NO_CONFIG_VERSION} - only the current version is written to the configuration file;</li>
     * <li>{@code ERROR_READING_CONFIG_VERSION} - no changes/updates are made, the method logs a warn and returns.</li>
     * </ul>
     * <p>
     * 
     * @param fileVersion the version of the configurations in the file
     * @see #CURRENT_CONFIG_VERSION
     * @see #NO_CONFIG_VERSION
     * @see #ERROR_READING_CONFIG_VERSION
     * @see #updateConfigFile()
     */
    private void updateConfigsFromVersion(int fileVersion) {
        if (fileVersion == CURRENT_CONFIG_VERSION) {
            return;
        }

        if (fileVersion == ERROR_READING_CONFIG_VERSION) {
            // There's not much that can be done (quickly and easily)... log and return.
            logger.warn("Configurations might not be in expected state, errors might happen...");
            return;
        }

        if (fileVersion != NO_CONFIG_VERSION) {
            if (fileVersion > CURRENT_CONFIG_VERSION) {
                logger.warn("Configurations will not be updated, file version (v" + fileVersion
                        + ") is greater than the version of running code (v" + CURRENT_CONFIG_VERSION
                        + "), errors might happen...");
                return;
            }
            logger.info("Updating configurations from v" + fileVersion + " to v" + CURRENT_CONFIG_VERSION);
        }

        switch (fileVersion) {
        case NO_CONFIG_VERSION:
            // No updates/changes needed, the configurations were not previously persisted
            // and the current version is already written at the end of the method.
            break;
        case 1: 
            String crawlInDepthKey = AJAX_SPIDER_BASE_KEY + ".crawlInDepth";
            try {
                boolean crawlInDepth = getConfig().getBoolean(crawlInDepthKey, false);
                getConfig().setProperty(CLICK_DEFAULT_ELEMS_KEY, Boolean.valueOf(!crawlInDepth));
            } catch (ConversionException e) {
                logger.warn("Failed to read (old) configuration '" + crawlInDepthKey + "', no update will be made.");
            }
        	getConfig().clearProperty(crawlInDepthKey);
        }

        getConfig().setProperty(CONFIG_VERSION_KEY, Integer.valueOf(CURRENT_CONFIG_VERSION));
    }

    public int getNumberOfBrowsers() {
        return numberOfBrowsers;
    }
    
    public void setNumberOfBrowsers(int numberOfBrowsers) {
        this.numberOfBrowsers = numberOfBrowsers;
        getConfig().setProperty(NUMBER_OF_BROWSERS_KEY, Integer.valueOf(numberOfBrowsers));
    }
    
    public int getNumberOfThreads() {
        return numberOfThreads;
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

    public Browser getBrowser() {
        return browser;
    }

    public void setBrowser(Browser browser) {
        this.browser = browser;
        getConfig().setProperty(BROWSER_ID_KEY, browser.id);
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
    
    public void setRandomInputs(boolean randomInputs){
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
            getConfig().setProperty(elementBaseKey + ELEM_ENABLED_KEY, Boolean.valueOf(elem.isEnabled()));
            
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
}
