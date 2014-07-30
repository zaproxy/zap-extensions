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

import org.apache.commons.configuration.ConversionException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.common.AbstractParam;

public class AjaxSpiderParam extends AbstractParam {

    private static final Logger logger = Logger.getLogger(AjaxSpiderParam.class);

    public enum Browser {
        CHROME("chrome"),
        FIREFOX("firefox"),
        HTML_UNIT("htmlunit");

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
            }
            return FIREFOX;
        }
    };

    private static final int CONFIG_VERSION = 1;

    private static final String AJAX_SPIDER_BASE_KEY = "ajaxSpider";

    private static final String CONFIG_VERSION_KEY = AJAX_SPIDER_BASE_KEY + ".configVersion";

    private static final String NUMBER_OF_BROWSERS_KEY = AJAX_SPIDER_BASE_KEY + ".numberOfBrowsers";
    
    private static final String MAX_CRAWL_DEPTH_KEY = AJAX_SPIDER_BASE_KEY + ".MaxCrawlDepth";
    
    private static final String MAX_CRAWL_STATES_KEY = AJAX_SPIDER_BASE_KEY + ".MaxCrawlStates";
    
    private static final String MAX_DURATION_KEY = AJAX_SPIDER_BASE_KEY + ".MaxDuration";
    
    private static final String EVENT_WAIT_TIME_KEY = AJAX_SPIDER_BASE_KEY + ".EventWaitTime";
    
    private static final String RELOAD_WAIT_TIME_KEY = AJAX_SPIDER_BASE_KEY + ".ReloadWaitTime";

    private static final String BROWSER_ID_KEY = AJAX_SPIDER_BASE_KEY + ".browserId";

    private static final String CRAWL_IN_DEPTH_KEY = AJAX_SPIDER_BASE_KEY + ".crawlInDepth";
    
    private static final String CLICK_ONCE_KEY = AJAX_SPIDER_BASE_KEY + ".ClickOnce";

    private static final int DEFAULT_NUMBER_OF_BROWSERS = 1;
    
    private static final int DEFAULT_MAX_CRAWL_DEPTH = 10;
    
    private static final int DEFAULT_CRAWL_STATES = 0;
    
    private static final int DEFAULT_MAX_DURATION = 60;
    
    private static final int DEFAULT_EVENT_WAIT_TIME = 1000;
    
    private static final int DEFAULT_RELOAD_WAIT_TIME = 1000;

    private static final Browser DEFAULT_BROWSER = Browser.FIREFOX;
 
    private static final boolean DEFAULT_CRAWL_IN_DEPTH = true;
    
    private static final boolean DEFAULT_CLICK_ONCE = true;

    private int numberOfBrowsers;
    private int numberOfThreads;
    private int MaxCrawlDepth;
    private int MaxCrawlStates;
    private int MaxDuration;
    private int EventWait;
    private int ReloadWait;

    private Browser browser;

    private boolean crawlInDepth;
    
    private boolean ClickOnce;

    @Override
    protected void parse() {
        int configVersion;
        try {
            configVersion = getConfig().getInt(CONFIG_VERSION_KEY, -1);
        } catch (ConversionException e) {
            logger.error("Error while getting the version of the configurations: " + e.getMessage(), e);
            configVersion = -1;
        }

        if (configVersion == -1) {
            getConfig().setProperty(CONFIG_VERSION_KEY, Integer.valueOf(CONFIG_VERSION));
        }

        try {
            this.numberOfBrowsers = getConfig().getInt(NUMBER_OF_BROWSERS_KEY, DEFAULT_NUMBER_OF_BROWSERS);
        } catch (ConversionException e) {
            logger.error("Error while loading the number of browsers: " + e.getMessage(), e);
        }
        
        try {
            this.MaxCrawlDepth = getConfig().getInt(MAX_CRAWL_DEPTH_KEY, DEFAULT_MAX_CRAWL_DEPTH);
        } catch (ConversionException e) {
            logger.error("Error while loading the max crawl depth: " + e.getMessage(), e);
        }
        
        try {
            this.MaxCrawlStates = getConfig().getInt(MAX_CRAWL_STATES_KEY, DEFAULT_CRAWL_STATES);
        } catch (ConversionException e) {
            logger.error("Error while loading max crawl states: " + e.getMessage(), e);
        }
        
        try {
            this.MaxDuration = getConfig().getInt(MAX_DURATION_KEY, DEFAULT_MAX_DURATION);
        } catch (ConversionException e) {
            logger.error("Error while loading the crawl duration: " + e.getMessage(), e);
        }
        
        try {
            this.EventWait = getConfig().getInt(EVENT_WAIT_TIME_KEY, DEFAULT_EVENT_WAIT_TIME);
        } catch (ConversionException e) {
            logger.error("Error while loading the event wait time: " + e.getMessage(), e);
        }
        
        try {
            this.ReloadWait = getConfig().getInt(RELOAD_WAIT_TIME_KEY, DEFAULT_RELOAD_WAIT_TIME);
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
            this.crawlInDepth = getConfig().getBoolean(CRAWL_IN_DEPTH_KEY, DEFAULT_CRAWL_IN_DEPTH);
        } catch (ConversionException e) {
            logger.error("Error while loading the crawl in depth option: " + e.getMessage(), e);
        }
        
        try {
            this.ClickOnce = getConfig().getBoolean(CLICK_ONCE_KEY, DEFAULT_CLICK_ONCE);
        } catch (ConversionException e) {
            logger.error("Error while loading the click once option: " + e.getMessage(), e);
        }
        
        
        
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
    	return MaxCrawlDepth; 
    }
    
    public void setMaxCrawlDepth(int MaxCrawlDepth) {
        this.MaxCrawlDepth = MaxCrawlDepth;
        getConfig().setProperty(MAX_CRAWL_DEPTH_KEY, Integer.valueOf(MaxCrawlDepth));
    }
    
    
    
    public int getMaxCrawlStates() {
    	return MaxCrawlStates; 
    }
    
    public void setMaxCrawlStates(int MaxCrawlStates) {
        this.MaxCrawlStates = MaxCrawlStates;
        getConfig().setProperty(MAX_CRAWL_STATES_KEY, Integer.valueOf(MaxCrawlStates));
    }
    
    
    public int getMaxDuration() {
    	return MaxDuration; 
    }
    
    public void setMaxDuration(int MaxDuration) {
        this.MaxDuration = MaxDuration;
        getConfig().setProperty(MAX_DURATION_KEY, Integer.valueOf(MaxDuration));
    }
    
    public int getEventWait() {
    	return EventWait; 
    }
    
    
    public void setEventWait(int EventWait) {
        this.EventWait = EventWait;
        getConfig().setProperty(EVENT_WAIT_TIME_KEY, Integer.valueOf(EventWait));
    }
    
    
    public int getReloadWait() {
    	return ReloadWait; 
    }
    
    public void setReloadWait(int ReloadWait) {
        this.ReloadWait = ReloadWait;
        getConfig().setProperty(RELOAD_WAIT_TIME_KEY, Integer.valueOf(ReloadWait));
    }
    

    public Browser getBrowser() {
        return browser;
    }

    public void setBrowser(Browser browser) {
        this.browser = browser;
        getConfig().setProperty(BROWSER_ID_KEY, browser.id);
    }

    public boolean isCrawlInDepth() {
        return crawlInDepth;
    }

    public void setCrawlInDepth(boolean crawlInDepth) {
        this.crawlInDepth = crawlInDepth;
        getConfig().setProperty(CRAWL_IN_DEPTH_KEY, Boolean.valueOf(crawlInDepth));
    }
    
    public boolean isClickOnce() {
        return ClickOnce;
    }

    public void setClickOnce(boolean ClickOnce) {
        this.ClickOnce = ClickOnce;
        getConfig().setProperty(CLICK_ONCE_KEY, Boolean.valueOf(ClickOnce));
    }
    
  
    
}
