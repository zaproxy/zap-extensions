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

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

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
 * <li>The path to Firefox binary;</li>
 * <li>The path to Firefox driver (geckodriver);</li>
 * <li>The path to IEDriverServer;</li>
 * <li>The path to PhantomJS binary.</li>
 * </ul>
 * 
 */
public class SeleniumOptions extends VersionedAbstractParam {

    private static final Logger LOGGER = Logger.getLogger(SeleniumOptions.class);

    public static final String CHROME_DRIVER_SYSTEM_PROPERTY = ChromeDriverService.CHROME_DRIVER_EXE_PROPERTY;
    public static final String FIREFOX_BINARY_SYSTEM_PROPERTY = "zap.selenium.webdriver.firefox.bin";
    public static final String FIREFOX_DRIVER_SYSTEM_PROPERTY = "webdriver.gecko.driver";
    public static final String IE_DRIVER_SYSTEM_PROPERTY = InternetExplorerDriverService.IE_DRIVER_EXE_PROPERTY;
    public static final String PHANTOM_JS_BINARY_SYSTEM_PROPERTY = PhantomJSDriverService.PHANTOMJS_EXECUTABLE_PATH_PROPERTY;

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
     * The configuration key to read/write the path Firefox binary.
     */
    private static final String FIREFOX_BINARY_KEY = SELENIUM_BASE_KEY + ".firefoxBinary";

    /**
     * The configuration key to read/write the path Firefox driver (geckodriver).
     */
    private static final String FIREFOX_DRIVER_KEY = SELENIUM_BASE_KEY + ".firefoxDriver";

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
     * The path to Firefox binary.
     */
    private String firefoxBinaryPath = "";

    /**
     * The path to Firefox driver (geckodriver).
     */
    private String firefoxDriverPath = "";

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
        chromeDriverPath = getWebDriverPath(Browser.CHROME, CHROME_DRIVER_SYSTEM_PROPERTY, CHROME_DRIVER_KEY);
        firefoxBinaryPath = readSystemPropertyWithOptionFallback(FIREFOX_BINARY_SYSTEM_PROPERTY, FIREFOX_BINARY_KEY);
        firefoxDriverPath = getWebDriverPath(Browser.FIREFOX, FIREFOX_DRIVER_SYSTEM_PROPERTY, FIREFOX_DRIVER_KEY);
        ieDriverPath = getWebDriverPath(Browser.INTERNET_EXPLORER, IE_DRIVER_SYSTEM_PROPERTY, IE_DRIVER_KEY);

        phantomJsBinaryPath = readSystemPropertyWithOptionFallback(PHANTOM_JS_BINARY_SYSTEM_PROPERTY, PHANTOM_JS_BINARY_KEY);
    }

    /**
     * Gets the path to the WebDriver of the given browser.
     * <p>
     * Reads the given {@code systemProperty}, falling back to the option with the given {@code optionKey} if not set. If both
     * properties are empty it returns the path to the bundled WebDriver, if available.
     *
     * @param browser the target browser
     * @param systemProperty the name of the system property
     * @param optionKey the key of the option used as fallback
     * @return the path to the WebDriver, or empty if none set or available.
     * @see #readSystemPropertyWithOptionFallback(String, String)
     */
    private String getWebDriverPath(Browser browser, String systemProperty, String optionKey) {
        String path = readSystemPropertyWithOptionFallback(systemProperty, optionKey);
        if (path.isEmpty()) {
            String bundledPath = Browser.getBundledWebDriverPath(browser);
            if (bundledPath != null) {
                saveAndSetSystemProperty(optionKey, systemProperty, bundledPath);
                return bundledPath;
            }
        } else if (Browser.isBundledWebDriverPath(path)) {
            Path driver = Paths.get(path);
            if (!Files.exists(driver) || !Browser.ensureExecutable(driver)) {
                saveAndSetSystemProperty(optionKey, systemProperty, "");
                return "";
            }
        }
        return path;
    }

    /**
     * Reads the given {@code systemProperty}, falling back to the option with the given {@code optionKey} if not set.
     * <p>
     * The system property if set, is saved in the file with the given {@code optionKey}. If not set, it's restored with the
     * option if available.
     * 
     * @param systemProperty the name of the system property
     * @param optionKey the key of the option used as fallback
     * @return the value of the system property, or if not set, the option read from the configuration file. If neither the
     *         system property nor the option are set it returns an empty {@code String}.
     */
    private String readSystemPropertyWithOptionFallback(String systemProperty, String optionKey) {
        String value = System.getProperty(systemProperty);
        if (value == null) {
            try {
                value = getConfig().getString(optionKey, "");
                if (!value.isEmpty()) {
                    System.setProperty(systemProperty, value);
                }
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
     * Gets the path to Firefox binary.
     *
     * @return the path to Firefox binary, or empty if not set.
     */
    public String getFirefoxBinaryPath() {
        return firefoxBinaryPath;
    }

    /**
     * Sets the path to Firefox binary.
     *
     * @param firefoxBinaryPath the path to Firefox binary, or empty if not known.
     * @throws IllegalArgumentException if {@code firefoxBinaryPath} is {@code null}.
     */
    public void setFirefoxBinaryPath(String firefoxBinaryPath) {
        Validate.notNull(firefoxBinaryPath, "Parameter firefoxBinaryPath must not be null.");

        if (!this.firefoxBinaryPath.equals(firefoxBinaryPath)) {
            this.firefoxBinaryPath = firefoxBinaryPath;

            saveAndSetSystemProperty(FIREFOX_BINARY_KEY, FIREFOX_BINARY_SYSTEM_PROPERTY, firefoxBinaryPath);
        }
    }

    /**
     * Gets the path to Firefox driver (geckodriver).
     *
     * @return the path to Firefox driver, or empty if not set.
     */
    public String getFirefoxDriverPath() {
        return firefoxDriverPath;
    }

    /**
     * Sets the path to Firefox driver (geckodriver).
     *
     * @param firefoxDriverPath the path to Firefox driver, or empty if not known.
     * @throws IllegalArgumentException if {@code firefoxDriverPath} is {@code null}.
     */
    public void setFirefoxDriverPath(String firefoxDriverPath) {
        Validate.notNull(firefoxDriverPath, "Parameter firefoxDriverPath must not be null.");

        if (!this.firefoxDriverPath.equals(firefoxDriverPath)) {
            this.firefoxDriverPath = firefoxDriverPath;

            saveAndSetSystemProperty(FIREFOX_DRIVER_KEY, FIREFOX_DRIVER_SYSTEM_PROPERTY, firefoxDriverPath);
        }
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
