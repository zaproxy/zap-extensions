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

import java.lang.ref.WeakReference;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import javax.swing.ImageIcon;
import javax.swing.SwingUtilities;
import javax.swing.event.ListDataEvent;
import javax.swing.event.ListDataListener;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.Validate;
import org.openqa.selenium.MutableCapabilities;
import org.openqa.selenium.Proxy;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebDriverException;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.firefox.FirefoxOptions;
import org.openqa.selenium.htmlunit.HtmlUnitDriver;
import org.openqa.selenium.phantomjs.PhantomJSDriver;
import org.openqa.selenium.phantomjs.PhantomJSDriverService;
import org.openqa.selenium.remote.CapabilityType;
import org.openqa.selenium.remote.DesiredCapabilities;
import org.openqa.selenium.safari.SafariDriver;
import org.openqa.selenium.safari.SafariOptions;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.extension.AddonFilesChangedListener;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.selenium.internal.BuiltInSingleWebDriverProvider;

/**
 * An {@code Extension} that provides {@code WebDriver} implementations for several {@code
 * Browser}s.
 *
 * @see WebDriver
 * @see Browser
 */
public class ExtensionSelenium extends ExtensionAdaptor {

    public static final String NAME = "ExtensionSelenium";
    public static final String SCRIPT_TYPE_SELENIUM = "selenium";

    private static final int MIN_PORT = 1;

    private static final int MAX_PORT = 65535;

    private SeleniumOptions options;
    private SeleniumOptionsPanel optionsPanel;

    private SeleniumAPI seleniumApi;

    private AddonFilesChangedListener addonFilesChangedListener;

    /**
     * A list containing all supported browsers by this extension.
     *
     * <p>Lazy initialised with {@code initialiseBrowserUIList()}.
     *
     * @see #initialiseBrowserUIList()
     */
    private List<BrowserUI> browserUIList;

    /** A list containing all (installed) WebDriverProviders. */
    private Map<String, SingleWebDriverProvider> webDriverProviders;

    /** A map of {@code ProvidedBrowser}'s ID to the {@code ProvidedBrowser} instance. */
    private Map<String, ProvidedBrowser> providedBrowsers;

    /**
     * A list containing all (installed) UI wrappers of {@code ProvidedBrowser}s.
     *
     * @see #buildProvidedBrowserUIList
     */
    private List<ProvidedBrowserUI> providedBrowserUIList;

    /**
     * A list containing all of the proxied WebDrivers opened, so that they can be closed when ZAP
     * is closed.
     */
    private Map<String, List<WebDriver>> proxiedWebDrivers = new HashMap<>();

    private List<WeakReference<ProvidedBrowsersComboBoxModel>> providedBrowserComboBoxModels =
            new ArrayList<WeakReference<ProvidedBrowsersComboBoxModel>>();

    private ExtensionScript extScript;

    private ScriptType seleniumScriptType;

    public ExtensionSelenium() {
        super(NAME);
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
    public int getOrder() {
        return 300;
    }

    @Override
    public boolean supportsDb(String type) {
        return true;
    }

    @Override
    public void init() {
        super.init();

        seleniumApi = new SeleniumAPI(getOptions());
        addonFilesChangedListener = new AddonFilesChangedListenerImpl();
        webDriverProviders =
                Collections.synchronizedMap(new HashMap<String, SingleWebDriverProvider>());
        providedBrowsers = Collections.synchronizedMap(new HashMap<String, ProvidedBrowser>());

        addBuiltInProvider(Browser.CHROME);
        addBuiltInProvider(Browser.CHROME_HEADLESS);
        addBuiltInProvider(Browser.FIREFOX);
        addBuiltInProvider(Browser.FIREFOX_HEADLESS);
        addBuiltInProvider(Browser.HTML_UNIT);
        addBuiltInProvider(Browser.PHANTOM_JS);
        addBuiltInProvider(Browser.SAFARI);

        providedBrowserUIList = new ArrayList<>();
        buildProvidedBrowserUIList();
    }

    private void addBuiltInProvider(Browser browser) {
        webDriverProviders.put(
                browser.getId(), new BuiltInSingleWebDriverProvider(getName(browser), browser));
    }

    private void buildProvidedBrowserUIList() {
        providedBrowserUIList.clear();
        for (SingleWebDriverProvider provider : webDriverProviders.values()) {
            providedBrowserUIList.add(new ProvidedBrowserUI(provider.getProvidedBrowser()));
        }
        Collections.sort(providedBrowserUIList);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        extensionHook.addOptionsParamSet(getOptions());
        extensionHook.addAddonFilesChangedListener(addonFilesChangedListener);

        if (getView() != null) {
            extensionHook.getHookView().addOptionPanel(getOptionsPanel());
            extensionHook.getHookMenu().addPopupMenuItem(new PopupMenuOpenInBrowser(this));
        }

        extensionHook.addApiImplementor(seleniumApi);

        if (getExtScript() != null) {
            seleniumScriptType =
                    new ScriptType(
                            SCRIPT_TYPE_SELENIUM,
                            "selenium.scripts.type.selenium",
                            createScriptIcon(),
                            true);
            extScript.registerScriptType(seleniumScriptType);
        }
    }

    private ExtensionScript getExtScript() {
        if (extScript == null) {
            extScript =
                    Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
        }
        return extScript;
    }

    private ImageIcon createScriptIcon() {
        if (getView() == null) {
            return null;
        }
        return new ImageIcon(
                ExtensionSelenium.class.getResource(
                        "/org/zaproxy/zap/extension/selenium/resources/script-selenium.png"));
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        if (extScript != null) {
            extScript.removeScriptType(seleniumScriptType);
        }
    }

    @Override
    public void stop() {
        super.stop();
        this.proxiedWebDrivers.values().forEach(ExtensionSelenium::quitWebDrivers);
        this.proxiedWebDrivers.clear();
    }

    private static void quitWebDrivers(List<WebDriver> drivers) {
        if (drivers == null || drivers.isEmpty()) {
            return;
        }

        for (WebDriver wd : drivers) {
            try {
                wd.quit();
            } catch (Exception ex) {
                // Ignore - the user might well have already closed the browser
            }
        }
    }

    /**
     * Adds the given WebDriver provider.
     *
     * @param webDriverProvider the WebDriver provider to add
     * @throws IllegalArgumentException if the the given WebDriver provider is {@code null} or its
     *     ID is {@code null} or empty. Also, if the ID already exists.
     * @since 1.1.0
     */
    public void addWebDriverProvider(SingleWebDriverProvider webDriverProvider) {
        validateWebDriverProvider(webDriverProvider);

        if (webDriverProviders.containsKey(webDriverProvider.getId())) {
            throw new IllegalArgumentException(
                    "A provider with the ID [" + webDriverProvider.getId() + "] already exists.");
        }

        webDriverProviders.put(webDriverProvider.getId(), webDriverProvider);

        ProvidedBrowser providedBrowser = webDriverProvider.getProvidedBrowser();
        providedBrowsers.put(providedBrowser.getId(), providedBrowser);

        ProvidedBrowserUI pbui = new ProvidedBrowserUI(providedBrowser);
        providedBrowserUIList.add(pbui);
        Collections.sort(providedBrowserUIList);

        final int idx = providedBrowserUIList.indexOf(pbui);

        if (getView() != null) {
            SwingUtilities.invokeLater(
                    new Runnable() {
                        @Override
                        public void run() {
                            ListDataEvent ev =
                                    new ListDataEvent(this, ListDataEvent.INTERVAL_ADDED, idx, idx);
                            Iterator<WeakReference<ProvidedBrowsersComboBoxModel>> iter =
                                    providedBrowserComboBoxModels.iterator();
                            while (iter.hasNext()) {
                                WeakReference<ProvidedBrowsersComboBoxModel> wr = iter.next();
                                ProvidedBrowsersComboBoxModel pb = wr.get();
                                if (pb == null) {
                                    iter.remove();
                                } else {
                                    for (ListDataListener listener : pb.getListDataListeners()) {
                                        listener.contentsChanged(ev);
                                    }
                                }
                            }
                        }
                    });
        }
    }

    /**
     * Validates that the given WebDriver provider is not {@code null} nor has a {@code null} or
     * empty ID.
     *
     * @param webDriverProvider the WebDriver provider to validate.
     * @throws IllegalArgumentException if the the given WebDriver provider is {@code null} or its
     *     ID is {@code null} or empty.
     */
    private static void validateWebDriverProvider(SingleWebDriverProvider webDriverProvider) {
        if (webDriverProvider == null) {
            throw new IllegalArgumentException("Parameter webDriverProvider must not be null.");
        }

        if (StringUtils.isEmpty(webDriverProvider.getId())) {
            throw new IllegalArgumentException(
                    "The ID of the webDriverProvider must not be null nor empty.");
        }
    }

    /**
     * Removes the given WebDriver provider.
     *
     * @param webDriverProvider the WebDriver provider to remove
     * @throws IllegalArgumentException if the the given WebDriver provider is {@code null} or its
     *     ID is {@code null} or empty.
     * @since 1.1.0
     */
    public void removeWebDriverProvider(SingleWebDriverProvider webDriverProvider) {
        validateWebDriverProvider(webDriverProvider);

        quitWebDrivers(proxiedWebDrivers.remove(webDriverProvider.getId()));
        webDriverProviders.remove(webDriverProvider.getId());
        providedBrowsers.remove(webDriverProvider.getProvidedBrowser().getId());
        buildProvidedBrowserUIList();

        if (getView() != null) {
            SwingUtilities.invokeLater(
                    new Runnable() {
                        @Override
                        public void run() {
                            ListDataEvent ev =
                                    new ListDataEvent(
                                            this,
                                            ListDataEvent.CONTENTS_CHANGED,
                                            0,
                                            providedBrowserUIList.size());
                            Iterator<WeakReference<ProvidedBrowsersComboBoxModel>> iter =
                                    providedBrowserComboBoxModels.iterator();
                            while (iter.hasNext()) {
                                WeakReference<ProvidedBrowsersComboBoxModel> wr = iter.next();
                                ProvidedBrowsersComboBoxModel pb = wr.get();
                                if (pb == null) {
                                    iter.remove();
                                } else {
                                    for (ListDataListener listener : pb.getListDataListeners()) {
                                        listener.contentsChanged(ev);
                                    }
                                }
                            }
                        }
                    });
        }
    }

    /**
     * Returns a new {@code ProvidedBrowsersComboBoxModel} with the provided browsers.
     *
     * @return a new model with the provided browsers.
     * @see #getBrowserUIList()
     * @since 1.1.0
     */
    public ProvidedBrowsersComboBoxModel createProvidedBrowsersComboBoxModel() {
        ProvidedBrowsersComboBoxModel model =
                new ProvidedBrowsersComboBoxModel(providedBrowserUIList);
        providedBrowserComboBoxModels.add(new WeakReference<ProvidedBrowsersComboBoxModel>(model));
        return model;
    }

    /**
     * Gets the (unmodifiable) list of {@code ProvidedBrowserUI} objects for all {@code
     * ProvidedBrowser}s installed.
     *
     * @return an unmodifiable list with all browsers installed
     * @since 1.1.0
     * @see #createProvidedBrowsersComboBoxModel()
     */
    public List<ProvidedBrowserUI> getProvidedBrowserUIList() {
        return Collections.unmodifiableList(providedBrowserUIList);
    }

    public List<ProvidedBrowserUI> getUsableProvidedBrowserUIList() {
        return this.getUsableProvidedBrowserUIList(false);
    }

    public List<ProvidedBrowserUI> getUsableProvidedBrowserUIList(boolean incHeadless) {
        List<ProvidedBrowserUI> list = new ArrayList<ProvidedBrowserUI>();
        for (ProvidedBrowserUI provided : providedBrowserUIList) {
            if (provided.getBrowser().isConfigured()
                    && (incHeadless || !provided.getBrowser().isHeadless())) {
                list.add(provided);
            }
        }
        return list;
    }

    public List<String> getUsableProvidedBrowserUINameList() {
        return this.getUsableProvidedBrowserUINameList(false);
    }

    public List<String> getUsableProvidedBrowserUINameList(boolean incHeadless) {
        List<String> list = new ArrayList<String>();
        for (ProvidedBrowserUI provided : providedBrowserUIList) {
            if (provided.getBrowser().isConfigured()
                    && (incHeadless || !provided.getBrowser().isHeadless())) {
                list.add(provided.getName());
            }
        }
        return list;
    }

    /**
     * Gets the {@code ProvidedBrowser} with the given ID.
     *
     * @param providedBrowserId the ID of the provided browser.
     * @return the {@code ProvidedBrowser}, or {@code null} if not found/installed.
     */
    private ProvidedBrowser getProvidedBrowser(String providedBrowserId) {
        ProvidedBrowser providedBrowser = providedBrowsers.get(providedBrowserId);
        if (providedBrowser == null) {
            SingleWebDriverProvider webDriverProvider = webDriverProviders.get(providedBrowserId);
            if (webDriverProvider != null) {
                providedBrowser = webDriverProvider.getProvidedBrowser();
            }
        }
        return providedBrowser;
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
     * Returns a new {@code BrowsersComboBoxModel} with the browsers returned by {@code
     * getBrowserUIList()}.
     *
     * @return a new {@code BrowsersComboBoxModel} with the browsers returned by {@code
     *     getBrowserUIList()}
     * @see #getBrowserUIList()
     */
    public BrowsersComboBoxModel createBrowsersComboBoxModel() {
        return new BrowsersComboBoxModel(getBrowserUIList());
    }

    /**
     * Gets the (unmodifiable) list of {@code BrowseUI} objects for all {@code Browser}s supported
     * by this extension.
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
     * Initialises the instance variable {@code browserUIList} with all {@code Browser}s supported
     * by this extension.
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
     * Gets a {@code WebDriver} to the provided browser for the given requester.
     *
     * @param requester the ID of the (ZAP) component that's requesting the {@code WebDriver}.
     * @param providedBrowserId the ID of the provided browser.
     * @return the {@code WebDriver} to the provided browser.
     * @throws IllegalArgumentException if the provided browser was not found.
     * @since 1.1.0
     */
    public WebDriver getWebDriver(int requester, String providedBrowserId) {
        return getWebDriverImpl(requester, providedBrowserId, null, -1);
    }

    /**
     * Gets a {@code WebDriver} to the provided browser for the given requester, proxying through
     * the given address and port.
     *
     * @param requester the ID of the (ZAP) component that's requesting the {@code WebDriver}.
     * @param providedBrowserId the ID of the provided browser.
     * @param proxyAddress the address of the proxy.
     * @param proxyPort the port of the proxy.
     * @return the {@code WebDriver} to the provided browser, proxying through the given address and
     *     port.
     * @throws IllegalArgumentException if {@code proxyAddress} is {@code null} or empty, or if
     *     {@code proxyPort} is not a valid port number (between 1 and 65535). Also, if the provided
     *     browser was not found.
     * @since 1.1.0
     */
    public WebDriver getWebDriver(
            int requester, String providedBrowserId, String proxyAddress, int proxyPort) {
        validateProxyAddressPort(proxyAddress, proxyPort);

        return getWebDriverImpl(requester, providedBrowserId, proxyAddress, proxyPort);
    }

    /**
     * Returns a WebDriver configured to proxy via ZAP
     *
     * @param requester the ZAP component that will use the browser
     * @param providedBrowserId the browser id
     * @return
     */
    public WebDriver getWebDriverProxyingViaZAP(int requester, String providedBrowserId) {
        return this.getWebDriver(
                requester,
                providedBrowserId,
                Model.getSingleton().getOptionsParam().getProxyParam().getProxyIp(),
                Model.getSingleton().getOptionsParam().getProxyParam().getProxyPort());
    }

    /**
     * Opens the identified browser for manual proxying through ZAP
     *
     * @param providedBrowserId the browser id
     */
    public WebDriver getProxiedBrowser(String providedBrowserId) {
        return this.getProxiedBrowser(providedBrowserId, null);
    }

    /**
     * Opens the identified browser for manual proxying through ZAP
     *
     * @param browserName the browser name
     */
    public WebDriver getProxiedBrowserByName(final String browserName) {
        return this.getProxiedBrowserByName(browserName, null);
    }

    /**
     * Opens the identified browser for manual proxying through ZAP
     *
     * @param browserName the browser name
     * @param url the url to open
     */
    public WebDriver getProxiedBrowserByName(final String browserName, final String url) {
        return this.getProxiedBrowserByName(HttpSender.PROXY_INITIATOR, browserName, url);
    }

    /**
     * Opens the identified browser for proxying through ZAP
     *
     * @param requester the ZAP component that will use the browser
     * @param browserName the browser name
     * @param url the url to open
     */
    public WebDriver getProxiedBrowserByName(
            final int requester, final String browserName, final String url) {
        for (ProvidedBrowserUI provided : providedBrowserUIList) {
            if (provided.getName().equals(browserName)) {
                return getProxiedBrowser(requester, provided.getBrowser().getId(), url);
            }
        }
        return null;
    }

    /**
     * Opens the browser for manual proxying through ZAP
     *
     * @param provided the browser
     * @param url the URL to open
     */
    public WebDriver getProxiedBrowser(final ProvidedBrowserUI provided, final String url) {
        return getProxiedBrowser(provided.getBrowser().getId(), url);
    }

    /**
     * Opens the browser for manual proxying through ZAP
     *
     * @param providedBrowserId the browser id
     * @param url the URL to open
     */
    public WebDriver getProxiedBrowser(final String providedBrowserId, final String url) {
        return this.getProxiedBrowser(HttpSender.PROXY_INITIATOR, providedBrowserId, url);
    }

    /**
     * Opens the browser for manual proxying through ZAP
     *
     * @param requester the ZAP componenet that will use this browser
     * @param providedBrowserId the browser id
     * @param url the URL to open
     */
    public WebDriver getProxiedBrowser(
            final int requester, final String providedBrowserId, final String url) {
        WebDriver webDriver =
                getWebDriver(
                        requester,
                        providedBrowserId,
                        Model.getSingleton().getOptionsParam().getProxyParam().getProxyIp(),
                        Model.getSingleton().getOptionsParam().getProxyParam().getProxyPort());

        if (webDriver != null) {
            proxiedWebDrivers
                    .computeIfAbsent(providedBrowserId, k -> new ArrayList<>())
                    .add(webDriver);
            if (url != null) {
                webDriver.get(url);
            }
        }
        return webDriver;
    }

    private static void validateProxyAddressPort(String proxyAddress, int proxyPort) {
        Validate.notEmpty(proxyAddress, "Parameter proxyAddress must not be null nor empty.");
        if (proxyPort < MIN_PORT || proxyPort > MAX_PORT) {
            throw new IllegalArgumentException(
                    "Parameter proxyPort must be under: " + MIN_PORT + " <= port <= " + MAX_PORT);
        }
    }

    private WebDriver getWebDriverImpl(
            int requester, String providedBrowserId, String proxyAddress, int proxyPort) {
        ProvidedBrowser providedBrowser = getProvidedBrowser(providedBrowserId);
        if (providedBrowser == null) {
            throw new IllegalArgumentException("Unknown browser: " + providedBrowserId);
        }

        WebDriver wd;
        if (proxyAddress == null) {
            wd = webDriverProviders.get(providedBrowser.getProviderId()).getWebDriver(requester);
        } else {
            wd =
                    webDriverProviders
                            .get(providedBrowser.getProviderId())
                            .getWebDriver(requester, proxyAddress, proxyPort);
        }
        if (getExtScript() != null) {
            boolean synchronously = requester == HttpSender.AJAX_SPIDER_INITIATOR;
            List<ScriptWrapper> scripts = extScript.getScripts(SCRIPT_TYPE_SELENIUM);
            for (ScriptWrapper script : scripts) {
                try {
                    if (script.isEnabled()) {
                        SeleniumScript s = extScript.getInterface(script, SeleniumScript.class);

                        if (s != null) {
                            Runnable runnable =
                                    () -> {
                                        try {
                                            s.browserLaunched(
                                                    new SeleniumScriptUtils(
                                                            wd,
                                                            requester,
                                                            providedBrowserId,
                                                            proxyAddress,
                                                            proxyPort));
                                        } catch (Exception e) {
                                            extScript.handleScriptException(script, e);
                                        }
                                    };
                            if (synchronously) {
                                runnable.run();
                            } else {
                                new Thread(runnable, "ZAP-selenium-script").start();
                            }
                        } else {
                            extScript.handleFailedScriptInterface(
                                    script,
                                    Constant.messages.getString(
                                            "selenium.scripts.interface.error", script.getName()));
                        }
                    }

                } catch (Exception e) {
                    extScript.handleScriptException(script, e);
                }
            }
        }

        return wd;
    }

    /**
     * Gets a {@code WebDriver} for the given {@code browser}.
     *
     * @param browser the target browser
     * @return the {@code WebDriver} to the given {@code browser}
     * @see #getWebDriver(Browser, String, int)
     */
    public static WebDriver getWebDriver(Browser browser) {
        return getWebDriver(-1, browser);
    }

    /**
     * Gets a {@code WebDriver} for the given requester and {@code browser}.
     *
     * @param requester the ID of the component requesting the {@code WebDriver}.
     * @param browser the target browser.
     * @return the {@code WebDriver} to the given {@code browser}.
     * @see #getWebDriver(Browser)
     */
    public static WebDriver getWebDriver(int requester, Browser browser) {
        return getWebDriver(requester, browser, null, -1);
    }

    /**
     * Gets a {@code WebDriver} for the given {@code browser} proxying through the given address and
     * port.
     *
     * @param browser the target browser
     * @param proxyAddress the address of the proxy
     * @param proxyPort the port of the proxy
     * @return the {@code WebDriver} to the given {@code browser}, proxying through the given
     *     address and port
     * @throws IllegalArgumentException if {@code proxyAddress} is {@code null} or empty, or if
     *     {@code proxyPort} is not a valid port number (between 1 and 65535)
     * @see #getWebDriver(Browser)
     */
    public static WebDriver getWebDriver(Browser browser, String proxyAddress, int proxyPort) {
        return getWebDriver(-1, browser, proxyAddress, proxyPort);
    }

    /**
     * Gets a {@code WebDriver} for the given requester and {@code browser} proxying through the
     * given address and port.
     *
     * @param requester the ID of the component requesting the {@code WebDriver}.
     * @param browser the target browser.
     * @param proxyAddress the address of the proxy.
     * @param proxyPort the port of the proxy.
     * @return the {@code WebDriver} to the given {@code browser}, proxying through the given
     *     address and port.
     * @throws IllegalArgumentException if {@code proxyAddress} is {@code null} or empty, or if
     *     {@code proxyPort} is not a valid port number (between 1 and 65535).
     * @see #getWebDriver(Browser)
     */
    public static WebDriver getWebDriver(
            int requester, Browser browser, String proxyAddress, int proxyPort) {
        validateProxyAddressPort(proxyAddress, proxyPort);

        return getWebDriverImpl(requester, browser, proxyAddress, proxyPort);
    }

    private static void setCommonOptions(
            MutableCapabilities capabilities, String proxyAddress, int proxyPort) {
        capabilities.setCapability(CapabilityType.ACCEPT_SSL_CERTS, true);
        // W3C capability
        capabilities.setCapability(CapabilityType.ACCEPT_INSECURE_CERTS, true);

        if (proxyAddress != null) {
            String httpProxy = proxyAddress + ":" + proxyPort;
            Proxy proxy = new Proxy();
            proxy.setHttpProxy(httpProxy);
            proxy.setSslProxy(httpProxy);
            capabilities.setCapability(CapabilityType.PROXY, proxy);
        }
    }

    private static WebDriver getWebDriverImpl(
            int requester, Browser browser, String proxyAddress, int proxyPort) {
        switch (browser) {
            case CHROME:
            case CHROME_HEADLESS:
                ChromeOptions chromeOptions = new ChromeOptions();
                setCommonOptions(chromeOptions, proxyAddress, proxyPort);
                chromeOptions.addArguments("--proxy-bypass-list=<-loopback>");
                chromeOptions.addArguments("--ignore-certificate-errors");
                chromeOptions.setHeadless(browser == Browser.CHROME_HEADLESS);
                return new ChromeDriver(chromeOptions);
            case FIREFOX:
            case FIREFOX_HEADLESS:
                FirefoxOptions firefoxOptions = new FirefoxOptions();
                setCommonOptions(firefoxOptions, proxyAddress, proxyPort);

                String geckoDriver =
                        System.getProperty(SeleniumOptions.FIREFOX_DRIVER_SYSTEM_PROPERTY);
                firefoxOptions.setLegacy(geckoDriver == null || geckoDriver.isEmpty());

                String binaryPath =
                        System.getProperty(SeleniumOptions.FIREFOX_BINARY_SYSTEM_PROPERTY);
                if (binaryPath != null && !binaryPath.isEmpty()) {
                    firefoxOptions.setBinary(binaryPath);
                }

                // Keep proxying localhost on Firefox >= 67
                firefoxOptions.addPreference("network.proxy.allow_hijacking_localhost", true);

                // Ensure ServiceWorkers are enabled for the HUD.
                firefoxOptions.addPreference("dom.serviceWorkers.enabled", true);

                // Disable the captive checks/requests, mainly to avoid flooding
                // the AJAX Spider results (those requests are out of scope) but
                // also useful for other launched browsers.
                firefoxOptions.addPreference("network.captive-portal-service.enabled", false);

                if (requester == HttpSender.AJAX_SPIDER_INITIATOR) {
                    // Disable JSON viewer, otherwise AJAX Spider will crawl it.
                    // https://developer.mozilla.org/en-US/docs/Tools/JSON_viewer
                    firefoxOptions.addPreference("devtools.jsonview.enabled", false);
                }

                if (proxyAddress != null) {
                    // Some issues prevent the PROXY capability from being properly applied:
                    // https://bugzilla.mozilla.org/show_bug.cgi?id=1282873
                    // https://bugzilla.mozilla.org/show_bug.cgi?id=1369827
                    // For now set the preferences manually:
                    firefoxOptions.addPreference("network.proxy.type", 1);
                    firefoxOptions.addPreference("network.proxy.http", proxyAddress);
                    firefoxOptions.addPreference("network.proxy.http_port", proxyPort);
                    firefoxOptions.addPreference("network.proxy.ssl", proxyAddress);
                    firefoxOptions.addPreference("network.proxy.ssl_port", proxyPort);
                    firefoxOptions.addPreference("network.proxy.share_proxy_settings", true);
                    firefoxOptions.addPreference("network.proxy.no_proxies_on", "");
                    // Fixes a problem with the HUD
                    firefoxOptions.addPreference("browser.tabs.documentchannel", false);
                    // And remove the PROXY capability:
                    firefoxOptions.setCapability(CapabilityType.PROXY, (Object) null);
                }

                firefoxOptions.setHeadless(browser == Browser.FIREFOX_HEADLESS);
                return new FirefoxDriver(firefoxOptions);
            case HTML_UNIT:
                DesiredCapabilities htmlunitCapabilities = new DesiredCapabilities();
                setCommonOptions(htmlunitCapabilities, proxyAddress, proxyPort);
                return new HtmlUnitDriver(
                        DesiredCapabilities.htmlUnit().merge(htmlunitCapabilities));
            case INTERNET_EXPLORER:
                throw new WebDriverException(
                        "No longer available, does not support the required capabilities.");
                /* No longer supported in the Selenium standalone jar
                     * need to decide if we support older Opera versions
                case OPERA:
                    OperaDriver driver = new OperaDriver(capabilities);
                    if (proxyAddress != null) {
                        driver.proxy().setProxyLocal(true);
                        // XXX Workaround, in operadriver <= 1.5 the HTTPS proxy settings are not set according to desired capabilities
                        // For more details see OperaProxy.parse(Proxy)
                        driver.proxy().setHttpsProxy(proxyAddress + ":" + proxyPort);
                    }

                    return driver;
                    */
            case PHANTOM_JS:
                DesiredCapabilities phantomCapabilities = new DesiredCapabilities();
                setCommonOptions(phantomCapabilities, proxyAddress, proxyPort);
                final ArrayList<String> cliArgs = new ArrayList<>(4);
                cliArgs.add("--ssl-protocol=any");
                cliArgs.add("--ignore-ssl-errors=yes");

                cliArgs.add("--webdriver-logfile=" + Constant.getZapHome() + "phantomjsdriver.log");
                cliArgs.add("--webdriver-loglevel=WARN");

                phantomCapabilities.setCapability(
                        PhantomJSDriverService.PHANTOMJS_CLI_ARGS, cliArgs);

                return new PhantomJSDriver(phantomCapabilities);
            case SAFARI:
                SafariOptions safariOptions = new SafariOptions();
                setCommonOptions(safariOptions, proxyAddress, proxyPort);
                return new SafariDriver(safariOptions);
            default:
                throw new IllegalArgumentException("Unknown browser: " + browser);
        }
    }

    /**
     * Returns an error message for the given provided browser that failed to start.
     *
     * <p>Some browsers require extra steps to start them with a WebDriver, for such cases there's a
     * custom error message, for the remaining cases there's a generic error message.
     *
     * @param providedBrowserId the ID of provided browser that failed to start
     * @param e the error/exception that was thrown while obtaining/starting the WebDriver/browser.
     * @return a {@code String} with the error message
     * @since 1.1.0
     */
    public String getWarnMessageFailedToStart(String providedBrowserId, Throwable e) {
        ProvidedBrowser providedBrowser = getProvidedBrowser(providedBrowserId);
        if (providedBrowser == null) {
            return getMessages().getString("selenium.warn.message.failed.start.browser.notfound");
        }

        String msg = getProviderWarnMessage(providedBrowser, e);
        if (msg != null) {
            return msg;
        }

        Browser browser = Browser.getBrowserWithIdNoFailSafe(providedBrowser.getProviderId());
        if (browser != null) {
            return getWarnMessageFailedToStart(browser);
        }
        return MessageFormat.format(
                getMessages().getString("selenium.warn.message.failed.start.browser"),
                providedBrowser.getName());
    }

    private String getProviderWarnMessage(ProvidedBrowser providedBrowser, Throwable e) {
        SingleWebDriverProvider provider = webDriverProviders.get(providedBrowser.getProviderId());
        if (provider == null) {
            return null;
        }
        return provider.getWarnMessageFailedToStart(e);
    }

    /**
     * Returns an error message for the given {@code browser} that failed to start.
     *
     * <p>Some browsers require extra steps to start them with a WebDriver, for such cases there's a
     * custom error message, for the remaining cases there's a generic error message.
     *
     * @param browser the browser that failed to start
     * @return a {@code String} with the error message
     */
    public String getWarnMessageFailedToStart(Browser browser) {
        switch (browser) {
            case CHROME:
                return getMessages().getString("selenium.warn.message.failed.start.browser.chrome");
            case PHANTOM_JS:
                return getMessages()
                        .getString("selenium.warn.message.failed.start.browser.phantomjs");
            default:
                return MessageFormat.format(
                        getMessages().getString("selenium.warn.message.failed.start.browser"),
                        getName(browser));
        }
    }

    public List<Browser> getConfiguredBrowsers() {
        List<Browser> browsers = new ArrayList<>();
        // No configurations, just install the browser or
        // browser plugins to work properly
        browsers.add(Browser.HTML_UNIT);
        browsers.add(Browser.OPERA);
        browsers.add(Browser.SAFARI);
        // Requires drivers, but hopefully they are already provided.
        browsers.add(Browser.CHROME);
        browsers.add(Browser.FIREFOX);

        if (!getOptions().getPhantomJsBinaryPath().isEmpty()) {
            browsers.add(Browser.PHANTOM_JS);
        }
        return browsers;
    }

    /**
     * Returns true if the specified browser is configured for the platform
     *
     * @param webdriverId the webdriver id
     * @return true if the specified browser is configured for the platform
     */
    public boolean isConfigured(String webdriverId) {
        SingleWebDriverProvider provider = this.webDriverProviders.get(webdriverId);
        if (provider != null) {
            return provider.isConfigured();
        }
        return false;
    }

    private class AddonFilesChangedListenerImpl implements AddonFilesChangedListener {

        @Override
        public void filesAdded() {
            if (getOptions().getChromeDriverPath().isEmpty()) {
                String path = Browser.getBundledWebDriverPath(Browser.CHROME);
                if (path != null) {
                    getOptions().setChromeDriverPath(path);
                }
            }

            if (getOptions().getFirefoxDriverPath().isEmpty()) {
                String path = Browser.getBundledWebDriverPath(Browser.FIREFOX);
                if (path != null) {
                    getOptions().setFirefoxDriverPath(path);
                }
            }
        }

        @Override
        public void filesRemoved() {
            if (Browser.isBundledWebDriverPath(getOptions().getChromeDriverPath())
                    && Files.notExists(Paths.get(getOptions().getChromeDriverPath()))) {
                getOptions().setChromeDriverPath("");
            }

            if (Browser.isBundledWebDriverPath(getOptions().getFirefoxDriverPath())
                    && Files.notExists(Paths.get(getOptions().getFirefoxDriverPath()))) {
                getOptions().setFirefoxDriverPath("");
            }
        }
    }

    /**
     * Returns true if the specified built in browser is configured for the platform
     *
     * @param browser
     * @return true if the specified built in browser is configured for the platform
     */
    public static boolean isConfigured(Browser browser) {
        switch (browser) {
            case INTERNET_EXPLORER:
                return false;
            case SAFARI:
                return Constant.isMacOsX();
            default:
                // All the rest should work on all platforms
                return true;
        }
    }
}
