/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.selenium;

import org.apache.commons.configuration.ConversionException;
import org.apache.commons.lang.Validate;
import org.apache.log4j.Logger;
import org.openqa.selenium.chrome.ChromeDriverService;
import org.openqa.selenium.ie.InternetExplorerDriverService;
import org.openqa.selenium.phantomjs.PhantomJSDriverService;
import org.zaproxy.zap.common.VersionedAbstractParam;
import org.zaproxy.zap.extension.api.ZapApiIgnore;

/**
 * Manages the Selenium configurations saved in the configuration file.
 * <p>
 * It allows to change, programmatically, the following options:
 * <ul>
 * <li>The path to ChromeDriver;</li>
 * <li>The path to IEDriverServer;</li>
 * <li>The path to PhantomJS binary.</li>
 * </ul>
 * 
 */
public class SeleniumOptions extends VersionedAbstractParam {

    private static final Logger LOGGER = Logger.getLogger(SeleniumOptions.class);

    private static final String CHROME_DRIVER_SYSTEM_PROPERTY = ChromeDriverService.CHROME_DRIVER_EXE_PROPERTY;
    private static final String IE_DRIVER_SYSTEM_PROPERTY = InternetExplorerDriverService.IE_DRIVER_EXE_PROPERTY;
    private static final String PHANTOM_JS_BINARY_SYSTEM_PROPERTY = PhantomJSDriverService.PHANTOMJS_EXECUTABLE_PATH_PROPERTY;

    /**
     * The current version of the configurations. Used to keep track of configuration changes between releases, in case
     * changes/updates are needed.
     * <p>
     * It only needs to be incremented for configuration changes (not releases of the add-on).
     * 
     * @see #CONFIG_VERSION_KEY
     * @see #updateConfigsImpl(int)
     */
    private static final int CURRENT_CONFIG_VERSION = 1;

    /**
     * The base key for all selenium configurations.
     */
    private static final String SELENIUM_BASE_KEY = "selenium";

    /**
     * The configuration key to read/write the version of the configurations.
     * 
     * @see #CURRENT_CONFIG_VERSION
     */
    private static final String CONFIG_VERSION_KEY = SELENIUM_BASE_KEY + VERSION_ATTRIBUTE;

    /**
     * The configuration key to read/write the path to ChromeDriver.
     */
    private static final String CHROME_DRIVER_KEY = SELENIUM_BASE_KEY + ".chromeDriver";

    /**
     * The configuration key to read/write the path to IEDriverServer.
     */
    private static final String IE_DRIVER_KEY = SELENIUM_BASE_KEY + ".ieDriver";

    /**
     * The configuration key to read/write the path PhantomJS binary.
     */
    private static final String PHANTOM_JS_BINARY_KEY = SELENIUM_BASE_KEY + ".phantomJsBinary";

    /**
     * The path to ChromeDriver.
     */
    private String chromeDriverPath = "";

    /**
     * The path to IEDriverServer.
     */
    private String ieDriverPath = "";

    /**
     * The path to PhantomJS binary.
     */
    private String phantomJsBinaryPath = "";

    @Override
    @ZapApiIgnore
    protected int getCurrentVersion() {
        return CURRENT_CONFIG_VERSION;
    }

    @Override
    @ZapApiIgnore
    protected String getConfigVersionKey() {
        return CONFIG_VERSION_KEY;
    }

    @Override
    protected void parseImpl() {
        chromeDriverPath = readSystemPropertyWithOptionFallback(CHROME_DRIVER_SYSTEM_PROPERTY, CHROME_DRIVER_KEY);
        ieDriverPath = readSystemPropertyWithOptionFallback(IE_DRIVER_SYSTEM_PROPERTY, IE_DRIVER_KEY);
        phantomJsBinaryPath = readSystemPropertyWithOptionFallback(PHANTOM_JS_BINARY_SYSTEM_PROPERTY, PHANTOM_JS_BINARY_KEY);
    }

    /**
     * Reads the given {@code systemProperty}, falling back to the option with the given {@code optionKey} if not set.
     * <p>
     * The system property if set, is saved in the file with the given {@code optionKey}.
     * 
     * @param systemProperty the name of the system property
     * @param optionKey the key of the option used as fallback
     * @return the value of the system property, or if not set, the option read from the configuration file, might be
     *         {@code null} if neither the system property nor the option are set.
     */
    private String readSystemPropertyWithOptionFallback(String systemProperty, String optionKey) {
        String value = System.getProperty(systemProperty);
        if (value == null) {
            try {
                value = getConfig().getString(optionKey, "");
            } catch (ConversionException e) {
                LOGGER.error("Failed to read '" + optionKey + "'", e);
                value = "";
            }
        } else {
            getConfig().setProperty(optionKey, value);
        }
        return value;
    }

    @Override
    protected void updateConfigsImpl(int fileVersion) {
        // Nothing to do.
    }

    /**
     * Gets the path to ChromeDriver.
     *
     * @return the path to ChromeDriver, or empty if not set.
     */
    public String getChromeDriverPath() {
        return chromeDriverPath;
    }

    /**
     * Sets the path to ChromeDriver.
     *
     * @param chromeDriverPath the path to ChromeDriver, or empty if not known.
     * @throws IllegalArgumentException if {@code chromeDriverPath} is {@code null}.
     */
    public void setChromeDriverPath(String chromeDriverPath) {
        Validate.notNull(chromeDriverPath, "Parameter chromeDriverPath must not be null.");

        if (!this.chromeDriverPath.equals(chromeDriverPath)) {
            this.chromeDriverPath = chromeDriverPath;

            saveAndSetSystemProperty(CHROME_DRIVER_KEY, CHROME_DRIVER_SYSTEM_PROPERTY, chromeDriverPath);
        }
    }

    /**
     * Saves the given {@code value} to the configuration file, with the given {@code optionKey}, and sets it to the given
     * {@code systemProperty}.
     *
     * @param optionKey the key of the option
     * @param systemProperty the system property
     * @param value the value saved and set to the system property
     */
    private void saveAndSetSystemProperty(String optionKey, String systemProperty, String value) {
        getConfig().setProperty(optionKey, value);
        System.setProperty(systemProperty, value);
    }

    /**
     * Gets the path to IEDriverServer.
     *
     * @return the path to IEDriverServer, or empty if not set.
     */
    public String getIeDriverPath() {
        return ieDriverPath;
    }

    /**
     * Sets the path to IEDriverServer.
     *
     * @param ieDriverPath the path to IEDriverServer, or empty if not known.
     * @throws IllegalArgumentException if {@code ieDriverPath} is {@code null}.
     */
    public void setIeDriverPath(String ieDriverPath) {
        Validate.notNull(ieDriverPath, "Parameter ieDriverPath must not be null.");

        if (!this.ieDriverPath.equals(ieDriverPath)) {
            this.ieDriverPath = ieDriverPath;

            saveAndSetSystemProperty(IE_DRIVER_KEY, IE_DRIVER_SYSTEM_PROPERTY, ieDriverPath);
        }
    }

    /**
     * Gets the path to PhantomJS binary.
     *
     * @return the path to PhantomJS binary, or empty if not set.
     */
    public String getPhantomJsBinaryPath() {
        return phantomJsBinaryPath;
    }

    /**
     * Sets the path to PhantomJS binary.
     *
     * @param phantomJsBinaryPath the path to PhantomJS binary, or empty if not known.
     * @throws IllegalArgumentException if {@code phantomJsBinaryPath} is {@code null}.
     */
    public void setPhantomJsBinaryPath(String phantomJsBinaryPath) {
        Validate.notNull(phantomJsBinaryPath, "Parameter phantomJsBinaryPath must not be null.");

        if (!this.phantomJsBinaryPath.equals(phantomJsBinaryPath)) {
            this.phantomJsBinaryPath = phantomJsBinaryPath;

            saveAndSetSystemProperty(PHANTOM_JS_BINARY_KEY, PHANTOM_JS_BINARY_SYSTEM_PROPERTY, phantomJsBinaryPath);
        }
    }

}
