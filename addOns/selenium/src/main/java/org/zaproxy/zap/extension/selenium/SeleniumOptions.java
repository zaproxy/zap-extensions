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

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.Validate;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.chrome.ChromeDriverService;
import org.openqa.selenium.ie.InternetExplorerDriverService;
import org.openqa.selenium.phantomjs.PhantomJSDriverService;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.common.VersionedAbstractParam;
import org.zaproxy.zap.extension.api.ZapApiIgnore;

/**
 * Manages the Selenium configurations saved in the configuration file.
 *
 * <p>It allows to change, programmatically, the following options:
 *
 * <ul>
 *   <li>The path to Chrome binary;
 *   <li>The path to ChromeDriver;
 *   <li>The path to Firefox binary;
 *   <li>The path to Firefox driver (geckodriver);
 *   <li>The path to PhantomJS binary.
 * </ul>
 */
public class SeleniumOptions extends VersionedAbstractParam {

    public static final String CHROME_BINARY_SYSTEM_PROPERTY = "zap.selenium.webdriver.chrome.bin";
    public static final String CHROME_DRIVER_SYSTEM_PROPERTY =
            ChromeDriverService.CHROME_DRIVER_EXE_PROPERTY;
    public static final String FIREFOX_BINARY_SYSTEM_PROPERTY =
            "zap.selenium.webdriver.firefox.bin";
    public static final String FIREFOX_DRIVER_SYSTEM_PROPERTY = "webdriver.gecko.driver";
    /** @deprecated IE is no longer supported. */
    @Deprecated
    public static final String IE_DRIVER_SYSTEM_PROPERTY =
            InternetExplorerDriverService.IE_DRIVER_EXE_PROPERTY;

    public static final String PHANTOM_JS_BINARY_SYSTEM_PROPERTY =
            PhantomJSDriverService.PHANTOMJS_EXECUTABLE_PATH_PROPERTY;

    private static final File EXTENSIONS_DIR =
            new File(Constant.getZapHome() + "/selenium/extensions/");
    private static final File[] NO_FILES = {};

    private static final Logger LOGGER = LogManager.getLogger(SeleniumOptions.class);

    /**
     * The current version of the configurations. Used to keep track of configuration changes
     * between releases, in case changes/updates are needed.
     *
     * <p>It only needs to be incremented for configuration changes (not releases of the add-on).
     *
     * @see #CONFIG_VERSION_KEY
     * @see #updateConfigsImpl(int)
     */
    private static final int CURRENT_CONFIG_VERSION = 2;

    /** The base key for all selenium configurations. */
    private static final String SELENIUM_BASE_KEY = "selenium";

    /**
     * The configuration key to read/write the version of the configurations.
     *
     * @see #CURRENT_CONFIG_VERSION
     */
    private static final String CONFIG_VERSION_KEY = SELENIUM_BASE_KEY + VERSION_ATTRIBUTE;

    /** The configuration key to read/write the path Chrome binary. */
    private static final String CHROME_BINARY_KEY = SELENIUM_BASE_KEY + ".chromeBinary";

    /** The configuration key to read/write the path to ChromeDriver. */
    private static final String CHROME_DRIVER_KEY = SELENIUM_BASE_KEY + ".chromeDriver";

    /** The configuration key to read/write the path Firefox binary. */
    private static final String FIREFOX_BINARY_KEY = SELENIUM_BASE_KEY + ".firefoxBinary";

    /** The configuration key to read/write the path Firefox driver (geckodriver). */
    private static final String FIREFOX_DRIVER_KEY = SELENIUM_BASE_KEY + ".firefoxDriver";

    /** The configuration key to read/write the path PhantomJS binary. */
    private static final String PHANTOM_JS_BINARY_KEY = SELENIUM_BASE_KEY + ".phantomJsBinary";

    private static final String DISABLED_EXTENSIONS_KEY = SELENIUM_BASE_KEY + ".disabledExts";

    private static final String EXTENSIONS_LAST_DIR_KEY = SELENIUM_BASE_KEY + ".lastDir";

    /** The path to Chrome binary. */
    private String chromeBinaryPath = "";

    /** The path to ChromeDriver. */
    private String chromeDriverPath = "";

    /** The path to Firefox binary. */
    private String firefoxBinaryPath = "";

    /** The path to Firefox driver (geckodriver). */
    private String firefoxDriverPath = "";

    /** The path to PhantomJS binary. */
    private String phantomJsBinaryPath = "";

    private List<Object> disabledExtensions;

    private String lastDirectory;

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
        try {
            Files.createDirectories(EXTENSIONS_DIR.toPath());
        } catch (IOException e) {
            LOGGER.error("Failed to create the extensions directory:", e);
        }

        chromeBinaryPath =
                readSystemPropertyWithOptionFallback(
                        CHROME_BINARY_SYSTEM_PROPERTY, CHROME_BINARY_KEY);
        chromeDriverPath =
                getWebDriverPath(Browser.CHROME, CHROME_DRIVER_SYSTEM_PROPERTY, CHROME_DRIVER_KEY);
        firefoxBinaryPath =
                readSystemPropertyWithOptionFallback(
                        FIREFOX_BINARY_SYSTEM_PROPERTY, FIREFOX_BINARY_KEY);
        firefoxDriverPath =
                getWebDriverPath(
                        Browser.FIREFOX, FIREFOX_DRIVER_SYSTEM_PROPERTY, FIREFOX_DRIVER_KEY);

        phantomJsBinaryPath =
                readSystemPropertyWithOptionFallback(
                        PHANTOM_JS_BINARY_SYSTEM_PROPERTY, PHANTOM_JS_BINARY_KEY);

        disabledExtensions = getConfig().getList(DISABLED_EXTENSIONS_KEY);

        lastDirectory = getConfig().getString(EXTENSIONS_LAST_DIR_KEY);
    }

    /**
     * Gets the path to the WebDriver of the given browser.
     *
     * <p>Reads the given {@code systemProperty}, falling back to the option with the given {@code
     * optionKey} if not set. If both properties are empty it returns the path to the bundled
     * WebDriver, if available.
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
     * Reads the given {@code systemProperty}, falling back to the option with the given {@code
     * optionKey} if not set.
     *
     * <p>The system property if set, is saved in the file with the given {@code optionKey}. If not
     * set, it's restored with the option if available.
     *
     * @param systemProperty the name of the system property
     * @param optionKey the key of the option used as fallback
     * @return the value of the system property, or if not set, the option read from the
     *     configuration file. If neither the system property nor the option are set it returns an
     *     empty {@code String}.
     */
    private String readSystemPropertyWithOptionFallback(String systemProperty, String optionKey) {
        String value = System.getProperty(systemProperty);
        if (value == null) {
            value = getString(optionKey, "");
            if (!value.isEmpty()) {
                System.setProperty(systemProperty, value);
            }
        } else {
            getConfig().setProperty(optionKey, value);
        }
        return value;
    }

    @Override
    protected void updateConfigsImpl(int fileVersion) {
        switch (fileVersion) {
            case 1:
                getConfig().clearProperty("selenium.ieDriver");
                break;
        }
    }

    /**
     * Gets the path to Chrome binary.
     *
     * @return the path to Chrome binary, or empty if not set.
     */
    public String getChromeBinaryPath() {
        return chromeBinaryPath;
    }

    /**
     * Sets the path to Chrome binary.
     *
     * @param chromeBinaryPath the path to Chrome binary, or empty if not known.
     * @throws IllegalArgumentException if {@code chromeBinaryPath} is {@code null}.
     */
    public void setChromeBinaryPath(String chromeBinaryPath) {
        Validate.notNull(chromeBinaryPath, "Parameter chromeBinaryPath must not be null.");

        if (!this.chromeBinaryPath.equals(chromeBinaryPath)) {
            this.chromeBinaryPath = chromeBinaryPath;

            saveAndSetSystemProperty(
                    CHROME_BINARY_KEY, CHROME_BINARY_SYSTEM_PROPERTY, chromeBinaryPath);
        }
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

            saveAndSetSystemProperty(
                    CHROME_DRIVER_KEY, CHROME_DRIVER_SYSTEM_PROPERTY, chromeDriverPath);
        }
    }

    /**
     * Saves the given {@code value} to the configuration file, with the given {@code optionKey},
     * and sets it to the given {@code systemProperty}.
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

            saveAndSetSystemProperty(
                    FIREFOX_BINARY_KEY, FIREFOX_BINARY_SYSTEM_PROPERTY, firefoxBinaryPath);
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

            saveAndSetSystemProperty(
                    FIREFOX_DRIVER_KEY, FIREFOX_DRIVER_SYSTEM_PROPERTY, firefoxDriverPath);
        }
    }

    /**
     * Gets the path to IEDriverServer.
     *
     * @return the path to IEDriverServer, or empty if not set.
     * @deprecated IE is no longer supported.
     */
    @Deprecated
    public String getIeDriverPath() {
        return "";
    }

    /**
     * Sets the path to IEDriverServer.
     *
     * @param ieDriverPath the path to IEDriverServer, or empty if not known.
     * @throws IllegalArgumentException if {@code ieDriverPath} is {@code null}.
     * @deprecated IE is no longer supported.
     */
    @Deprecated
    public void setIeDriverPath(String ieDriverPath) {
        // Nothing to do.
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

            saveAndSetSystemProperty(
                    PHANTOM_JS_BINARY_KEY, PHANTOM_JS_BINARY_SYSTEM_PROPERTY, phantomJsBinaryPath);
        }
    }

    public List<BrowserExtension> getEnabledBrowserExtensions(Browser browser) {
        return this.getBrowserExtensions().stream()
                .filter(BrowserExtension::isEnabled)
                .filter(be -> be.getBrowser() == browser)
                .collect(Collectors.toList());
    }

    public List<BrowserExtension> getBrowserExtensions() {
        List<BrowserExtension> list = new ArrayList<>();
        if (EXTENSIONS_DIR.exists() && EXTENSIONS_DIR.isDirectory()) {
            // Always read these from filestore so we always pickup new files
            for (File file : EXTENSIONS_DIR.listFiles()) {
                Path path = file.toPath();
                if (BrowserExtension.isBrowserExtension(path)) {
                    BrowserExtension ext = new BrowserExtension(path);
                    ext.setEnabled(
                            !this.disabledExtensions.contains(ext.getPath().toFile().getName()));
                    list.add(ext);
                }
            }
        }
        return list;
    }

    public void setBrowserExtensions(List<BrowserExtension> exts) {
        this.disabledExtensions.clear();
        // Delete any that are not in the list
        for (File file : getFiles(EXTENSIONS_DIR)) {
            Path path = file.toPath();
            if (BrowserExtension.isBrowserExtension(path)) {
                boolean found = false;
                for (BrowserExtension ext : exts) {
                    if (ext.getPath().equals(path)) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    try {
                        Files.delete(file.toPath());
                    } catch (IOException e) {
                        LOGGER.error(
                                "Failed to delete browser extension {}", file.getAbsoluteFile(), e);
                    }
                }
            }
        }
        // Copy any newly added extensions
        for (BrowserExtension ext : exts) {
            File f = ext.getPath().toFile();
            if (!f.getParentFile().equals(EXTENSIONS_DIR)) {
                File target = new File(EXTENSIONS_DIR, f.getName());
                try {
                    FileUtils.copyFileToDirectory(f, EXTENSIONS_DIR, false);
                } catch (Exception e) {
                    LOGGER.error(
                            "Failed to copy browser extension {} to {} ",
                            f.getAbsolutePath(),
                            target.getAbsolutePath(),
                            e);
                }
            }
            if (!ext.isEnabled()) {
                this.disabledExtensions.add(ext.getPath().toFile().getName());
            }
        }
        this.getConfig().setProperty(DISABLED_EXTENSIONS_KEY, this.disabledExtensions);
    }

    private static File[] getFiles(File file) {
        File[] files = file.listFiles();
        if (files != null) {
            return files;
        }
        return NO_FILES;
    }

    public String getLastDirectory() {
        return lastDirectory;
    }

    public void setLastDirectory(String lastDirectory) {
        this.lastDirectory = lastDirectory;
        this.getConfig().setProperty(EXTENSIONS_LAST_DIR_KEY, this.lastDirectory);
    }
}
