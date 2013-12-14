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

    private static final String PROXY_IP_KEY = AJAX_SPIDER_BASE_KEY + ".proxyIp";
    private static final String PROXY_PORT_KEY = AJAX_SPIDER_BASE_KEY + ".proxyPort";

    private static final String NUMBER_OF_BROWSERS_KEY = AJAX_SPIDER_BASE_KEY + ".numberOfBrowsers";
    private static final String NUMBER_OF_THREADS_KEY = AJAX_SPIDER_BASE_KEY + ".numberOfThreads";

    private static final String BROWSER_ID_KEY = AJAX_SPIDER_BASE_KEY + ".browserId";

    private static final String CRAWL_IN_DEPTH_KEY = AJAX_SPIDER_BASE_KEY + ".crawlInDepth";

    private static final String DEFAULT_PROXY_IP = "localhost";
    private static final int DEFAULT_PROXY_PORT = 8081;

    private static final int DEFAULT_NUMBER_OF_BROWSERS = 1;
    private static final int DEFAULT_NUMBER_OF_THREADS = 1;

    private static final Browser DEFAULT_BROWSER = Browser.FIREFOX;

    private static final boolean DEFAULT_CRAWL_IN_DEPTH = false;

    private String proxyIp;
    private int proxyPort;

    private int numberOfBrowsers;
    private int numberOfThreads;

    private Browser browser;

    private boolean crawlInDepth;

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
            this.proxyIp = getConfig().getString(PROXY_IP_KEY, DEFAULT_PROXY_IP);
        } catch (ConversionException e) {
            logger.error("Error while loading the proxy ip: " + e.getMessage(), e);
        }

        try {
            this.proxyPort = getConfig().getInt(PROXY_PORT_KEY, DEFAULT_PROXY_PORT);
        } catch (ConversionException e) {
            logger.error("Error while loading the proxy port: " + e.getMessage(), e);
        }

        try {
            this.numberOfBrowsers = getConfig().getInt(NUMBER_OF_BROWSERS_KEY, DEFAULT_NUMBER_OF_BROWSERS);
        } catch (ConversionException e) {
            logger.error("Error while loading the number of browsers: " + e.getMessage(), e);
        }

        try {
            this.numberOfThreads = getConfig().getInt(NUMBER_OF_THREADS_KEY, DEFAULT_NUMBER_OF_THREADS);
        } catch (ConversionException e) {
            logger.error("Error while loading the number of threads: " + e.getMessage(), e);
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
    }

    public String getProxyIp() {
        return proxyIp;
    }

    public void setProxyIp(String proxyIp) {
        this.proxyIp = proxyIp;
        getConfig().setProperty(PROXY_IP_KEY, proxyIp);
    }

    public int getProxyPort() {
        return proxyPort;
    }

    public void setProxyPort(int proxyPort) {
        this.proxyPort = proxyPort;
        getConfig().setProperty(PROXY_PORT_KEY, Integer.valueOf(proxyPort));
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

    public void setNumberOfThreads(int numberOfThreads) {
        this.numberOfThreads = numberOfThreads;
        getConfig().setProperty(NUMBER_OF_THREADS_KEY, Integer.valueOf(numberOfThreads));
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
}
