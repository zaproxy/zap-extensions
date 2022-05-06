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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;
import org.apache.commons.lang.Validate;
import org.apache.commons.lang3.SystemUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;

/** Defines the browsers supported by the add-on. */
public enum Browser {
    CHROME("chrome", false),
    CHROME_HEADLESS("chrome-headless", true),
    FIREFOX("firefox", false),
    FIREFOX_HEADLESS("firefox-headless", true),
    /**
     * Headless browser, guaranteed to be always available.
     *
     * @see #getFailSafeBrowser()
     */
    HTML_UNIT("htmlunit", true),
    /**
     * @deprecated Does not support required capabilities ({@link
     *     org.openqa.selenium.remote.CapabilityType#ACCEPT_INSECURE_CERTS ACCEPT_INSECURE_CERTS}).
     */
    @Deprecated
    INTERNET_EXPLORER("ie", false),
    OPERA("opera", false),
    PHANTOM_JS("phantomjs", true),
    SAFARI("safari", false);

    private static final String WEB_DRIVERS_DIR_NAME = "webdriver";

    private static final Logger logger = LogManager.getLogger(Browser.class);

    private static Path zapHomeDir;

    private final String id;

    private final boolean headless;

    private Browser(String id, boolean isHeadless) {
        this.id = id;
        this.headless = isHeadless;
    }

    /**
     * Gets the ID of this browser.
     *
     * <p>The ID can be used for persistence and later creation, using the method {@code
     * getBrowserWithId(String)}.
     *
     * @return the ID of the browser
     * @see #getBrowserWithId(String)
     */
    public String getId() {
        return id;
    }

    /**
     * Gets the browser that has the given {@code id}.
     *
     * <p>If no match is found returns the browser guaranteed to be always available, as returned by
     * {@code getFailSafeBrowser()}.
     *
     * @param id the ID of the browser
     * @return the browser that matches the given {@code id}, or if not found the browser returned
     *     by {@code getFailSafeBrowser()}
     * @throws IllegalArgumentException if the given {@code id} is {@code null} or empty.
     * @see #getId()
     * @see #getFailSafeBrowser()
     */
    public static Browser getBrowserWithId(String id) {
        Validate.notEmpty(id, "Parameter id must not be null or empty.");

        Browser browser = getBrowserWithIdNoFailSafe(id);
        if (browser != null) {
            return browser;
        }
        return getFailSafeBrowser();
    }

    public static Browser getBrowserWithIdNoFailSafe(String id) {
        Validate.notEmpty(id, "Parameter id must not be null or empty.");

        if (CHROME.id.equals(id)) {
            return CHROME;
        } else if (CHROME_HEADLESS.id.equals(id)) {
            return CHROME_HEADLESS;
        } else if (FIREFOX.id.equals(id)) {
            return FIREFOX;
        } else if (FIREFOX_HEADLESS.id.equals(id)) {
            return FIREFOX_HEADLESS;
        } else if (HTML_UNIT.id.equals(id)) {
            return HTML_UNIT;
        } else if (INTERNET_EXPLORER.id.equals(id)) {
            return INTERNET_EXPLORER;
        } else if (OPERA.id.equals(id)) {
            return OPERA;
        } else if (PHANTOM_JS.id.equals(id)) {
            return PHANTOM_JS;
        } else if (SAFARI.id.equals(id)) {
            return SAFARI;
        }

        return null;
    }

    /**
     * Gets the browser that is guaranteed to be always available.
     *
     * @return the {@code Browser} that is guaranteed to be always available.
     * @see #HTML_UNIT
     */
    public static Browser getFailSafeBrowser() {
        return HTML_UNIT;
    }

    /**
     * Tells whether or not the given path is a bundled WebDriver.
     *
     * <p>No actual check is done to test whether or not the WebDriver really exists, just that it's
     * under the directory of the bundled WebDrivers.
     *
     * @param path the path to check
     * @return {@code true} if the path is a bundled WebDriver, {@code false} otherwise.
     */
    public static boolean isBundledWebDriverPath(String path) {
        if (path == null || path.isEmpty()) {
            return false;
        }

        try {
            return Paths.get(path).startsWith(getWebDriversDir());
        } catch (InvalidPathException e) {
            logger.warn("Failed to create path for {}", path, e);
            return false;
        }
    }

    private static Path getWebDriversDir() {
        return getZapHomeDir().resolve(WEB_DRIVERS_DIR_NAME);
    }

    /**
     * Tells whether or not a bundled WebDriver exists for the given browser.
     *
     * @param browser the browser that will be checked
     * @return {@code true} if the bundled WebDriver exists, {@code false} otherwise.
     * @see #getBundledWebDriverPath(Browser)
     */
    public static boolean hasBundledWebDriver(Browser browser) {
        return getBundledWebDriverPath(browser) != null;
    }

    /**
     * Gets the path to the bundled WebDriver of the given browser.
     *
     * @param browser the target browser
     * @return the path to the bundled WebDriver, or {@code null} if none available.
     * @see #hasBundledWebDriver(Browser)
     */
    public static String getBundledWebDriverPath(Browser browser) {
        String osDirName = getOsDirName();
        if (osDirName == null) {
            return null;
        }

        String driverName = getWebDriverName(browser);
        if (driverName == null) {
            return null;
        }

        if ("windows".equals(osDirName)) {
            driverName += ".exe";
        }

        Path basePath = getWebDriversDir().resolve(osDirName);
        String archDir = getArchDir();
        String driverPath = process(basePath.resolve(archDir).resolve(driverName));
        if (driverPath != null) {
            return driverPath;
        }

        // Fallback to 32 in case the WebDriver does not have a 64 specific.
        return process(basePath.resolve("32").resolve(driverName));
    }

    private static String process(Path driver) {
        if (Files.exists(driver)) {
            try {
                setExecutable(driver);
                return driver.toAbsolutePath().toString();
            } catch (IOException e) {
                logger.warn("Failed to set the bundled WebDriver executable:", e);
            }
        }

        return null;
    }

    private static String getWebDriverName(Browser browser) {
        switch (browser) {
            case CHROME:
            case CHROME_HEADLESS:
                return "chromedriver";
            case FIREFOX:
            case FIREFOX_HEADLESS:
                return "geckodriver";
            default:
                return null;
        }
    }

    private static String getOsDirName() {
        if (SystemUtils.IS_OS_WINDOWS) {
            return "windows";
        }
        if (SystemUtils.IS_OS_MAC) {
            return "macos";
        }
        if (SystemUtils.IS_OS_UNIX) {
            return "linux";
        }
        return null;
    }

    private static String getArchDir() {
        String arch = System.getProperty("os.arch");
        String archDir = "32";
        if (arch.contains("amd64") || arch.contains("x86_64")) {
            archDir = "64";
        } else if (arch.contains("aarch64")) {
            archDir = "arm64";
        }
        return archDir;
    }

    private static void setExecutable(Path file) throws IOException {
        if (!SystemUtils.IS_OS_MAC && !SystemUtils.IS_OS_UNIX) {
            return;
        }

        Set<PosixFilePermission> perms =
                Files.readAttributes(file, PosixFileAttributes.class).permissions();
        if (perms.contains(PosixFilePermission.OWNER_EXECUTE)) {
            return;
        }

        perms.add(PosixFilePermission.OWNER_EXECUTE);
        Files.setPosixFilePermissions(file, perms);
    }

    static boolean ensureExecutable(Path driver) {
        try {
            setExecutable(driver);
            return true;
        } catch (IOException e) {
            logger.warn("Failed to set the bundled WebDriver executable:", e);
        }
        return false;
    }

    static void setZapHomeDir(Path path) {
        zapHomeDir = path;
    }

    private static Path getZapHomeDir() {
        if (zapHomeDir == null) {
            zapHomeDir = Paths.get(Constant.getZapHome());
        }
        return zapHomeDir;
    }

    public boolean isHeadless() {
        return headless;
    }
}
