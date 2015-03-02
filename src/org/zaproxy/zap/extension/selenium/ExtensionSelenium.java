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

import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.apache.commons.lang.Validate;
import org.openqa.selenium.Proxy;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.htmlunit.HtmlUnitDriver;
import org.openqa.selenium.ie.InternetExplorerDriver;
import org.openqa.selenium.phantomjs.PhantomJSDriver;
import org.openqa.selenium.phantomjs.PhantomJSDriverService;
import org.openqa.selenium.remote.CapabilityType;
import org.openqa.selenium.remote.DesiredCapabilities;
import org.openqa.selenium.safari.SafariDriver;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.zap.Version;
import org.zaproxy.zap.extension.api.API;

import com.opera.core.systems.OperaDriver;

/**
 * An {@code Extension} that provides {@code WebDriver} implementations for several {@code Browser}s.
 *
 * @see WebDriver
 * @see Browser
 */
public class ExtensionSelenium extends ExtensionAdaptor {

    public static final String NAME = "ExtensionSelenium";

    private static final int MIN_PORT = 1;

    private static final int MAX_PORT = 65535;

    /**
     * The version of the extension. As consistency should be kept in sync with the version of the add-on (under ZapAddOn.xml
     * file).
     */
    private static final Version CURRENT_VERSION = new Version("1.0.0");

    private SeleniumOptions options;
    private SeleniumOptionsPanel optionsPanel;

    private SeleniumAPI seleniumApi;

    /**
     * A list containing all supported browsers by this extension.
     * <p>
     * Lazy initialised with {@code initialiseBrowserUIList()}.
     * 
     * @see #initialiseBrowserUIList()
     */
    private List<BrowserUI> browserUIList;

    public ExtensionSelenium() {
        super(NAME, CURRENT_VERSION);
    }

    @Override
    public String getUIName() {
        return getMessages().getString("selenium.extension.ui.name");
    }

    @Override
    public String getDescription() {
        return getMessages().getString("selenium.extension.desc");
    }

    @Override
    public String getAuthor() {
        return Constant.ZAP_TEAM;
    }

    @Override
    public void init() {
        super.init();

        seleniumApi = new SeleniumAPI(getOptions());
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        extensionHook.addOptionsParamSet(getOptions());

        if (getView() != null) {
            extensionHook.getHookView().addOptionPanel(getOptionsPanel());
        }

        API.getInstance().registerApiImplementor(seleniumApi);
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        super.unload();

        API.getInstance().removeApiImplementor(seleniumApi);
    }

    /**
     * Returns the (internationalised) name of the given {@code browser}.
     *
     * @param browser the browser whose name will be obtained
     * @return a String containing the name of the browser
     * @see #getBrowserUIList()
     * @see #createBrowsersComboBoxModel()
     */
    public String getName(Browser browser) {
        return getMessages().getString("selenium.browser.name." + browser.getId());
    }

    /**
     * Returns a new {@code BrowsersComboBoxModel} with the browsers returned by {@code getBrowserUIList()}.
     *
     * @return a new {@code BrowsersComboBoxModel} with the browsers returned by {@code getBrowserUIList()}
     * @see #getBrowserUIList()
     */
    public BrowsersComboBoxModel createBrowsersComboBoxModel() {
        return new BrowsersComboBoxModel(getBrowserUIList());
    }

    /**
     * Gets the (unmodifiable) list of {@code BrowseUI} objects for all {@code Browser}s supported by this extension.
     *
     * @return an unmodifiable list with all browsers supported by this extension
     * @see #getName(Browser)
     * @see #createBrowsersComboBoxModel()
     */
    public List<BrowserUI> getBrowserUIList() {
        if (browserUIList == null) {
            initialiseBrowserUIList();
        }
        return browserUIList;
    }

    /**
     * Initialises the instance variable {@code browserUIList} with all {@code Browser}s supported by this extension.
     * 
     * @code {@link #browserUIList}
     */
    private synchronized void initialiseBrowserUIList() {
        if (browserUIList == null) {
            List<BrowserUI> browsers = new ArrayList<>(Browser.values().length);
            for (Browser browser : Browser.values()) {
                browsers.add(new BrowserUI(getName(browser), browser));
            }
            Collections.sort(browsers);
            browserUIList = Collections.unmodifiableList(browsers);
        }
    }

    private SeleniumOptions getOptions() {
        if (options == null) {
            options = new SeleniumOptions();
        }
        return options;
    }

    private SeleniumOptionsPanel getOptionsPanel() {
        if (optionsPanel == null) {
            optionsPanel = new SeleniumOptionsPanel(getMessages());
        }
        return optionsPanel;
    }

    /**
     * Gets a {@code WebDriver} for the given {@code browser}.
     *
     * @param browser the target browser
     * @return the {@code WebDriver} to the given {@code browser}
     * @see #getWebDriver(Browser, String, int)
     */
    public static WebDriver getWebDriver(Browser browser) {
        return getWebDriverImpl(browser, null, -1);
    }

    /**
     * Gets a {@code WebDriver} for the given {@code browser} proxying through the given address and port.
     *
     * @param browser the target browser
     * @param proxyAddress the address of the proxy
     * @param proxyPort the port of the proxy
     * @return the {@code WebDriver} to the given {@code browser}, proxying through the given address and port
     * @throws IllegalArgumentException if {@code proxyAddress} is {@code null} or empty, or if {@code proxyPort} is not a valid
     *             port number (between 1 and 65535)
     * @see #getWebDriver(Browser)
     */
    public static WebDriver getWebDriver(Browser browser, String proxyAddress, int proxyPort) {
        Validate.notEmpty(proxyAddress, "Parameter proxyAddress must not be null nor empty.");
        if (proxyPort < MIN_PORT || proxyPort > MAX_PORT) {
            throw new IllegalArgumentException("Parameter proxyPort must be under: " + MIN_PORT + " <= port <= " + MAX_PORT);
        }

        return getWebDriverImpl(browser, proxyAddress, proxyPort);
    }

    private static WebDriver getWebDriverImpl(Browser browser, String proxyAddress, int proxyPort) {
        DesiredCapabilities capabilities = new DesiredCapabilities();
        if (proxyAddress != null) {
            String httpProxy = proxyAddress + ":" + proxyPort;
            Proxy proxy = new Proxy();
            proxy.setHttpProxy(httpProxy);
            proxy.setSslProxy(httpProxy);
            capabilities.setCapability(CapabilityType.PROXY, proxy);
        }

        switch (browser) {
        case CHROME:
            return new ChromeDriver(capabilities);
        case FIREFOX:
            return new FirefoxDriver(capabilities);
        case HTML_UNIT:
            return new HtmlUnitDriver(capabilities);
        case INTERNET_EXPLORER:
            capabilities.setCapability(InternetExplorerDriver.IE_USE_PRE_PROCESS_PROXY, true);

            return new InternetExplorerDriver(capabilities);
        case OPERA:
            OperaDriver driver = new OperaDriver(capabilities);
            if (proxyAddress != null) {
                driver.proxy().setProxyLocal(true);
                // XXX Workaround, in operadriver <= 1.5 the HTTPS proxy settings are not set according to desired capabilities
                // For more details see OperaProxy.parse(Proxy)
                driver.proxy().setHttpsProxy(proxyAddress + ":" + proxyPort);
            }

            return driver;
        case PHANTOM_JS:
            final ArrayList<String> cliArgs = new ArrayList<>(4);
            cliArgs.add("--ssl-protocol=any");
            cliArgs.add("--ignore-ssl-errors=yes");

            cliArgs.add("--webdriver-logfile=" + Constant.getZapHome() + "/phantomjsdriver.log");
            cliArgs.add("--webdriver-loglevel=WARN");

            capabilities.setCapability(PhantomJSDriverService.PHANTOMJS_CLI_ARGS, cliArgs);

            return new PhantomJSDriver(capabilities);
        case SAFARI:
            return new SafariDriver(capabilities);
        default:
            throw new IllegalArgumentException("Unknown browser: " + browser);
        }
    }

    /**
     * Returns an error message for the given {@code browser} that failed to start.
     * <p>
     * Some browsers require extra steps to start them with a WebDriver, for such cases there's a custom error message, for the
     * remaining cases there's a generic error message.
     *
     * @param browser the browser that failed to start
     * @return a {@code String} with the error message
     */
    public String getWarnMessageFailedToStart(Browser browser) {
        switch (browser) {
        case CHROME:
            return getMessages().getString("selenium.warn.message.failed.start.browser.chrome");
        case INTERNET_EXPLORER:
            return getMessages().getString("selenium.warn.message.failed.start.browser.ie");
        case PHANTOM_JS:
            return getMessages().getString("selenium.warn.message.failed.start.browser.phantomjs");
        default:
            return MessageFormat.format(getMessages().getString("selenium.warn.message.failed.start.browser"), getName(browser));
        }
    }
}
