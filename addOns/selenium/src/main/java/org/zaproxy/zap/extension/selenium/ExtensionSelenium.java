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
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import javax.swing.ImageIcon;
import javax.swing.SwingUtilities;
import javax.swing.event.ListDataEvent;
import javax.swing.event.ListDataListener;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Validate;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.openqa.selenium.MutableCapabilities;
import org.openqa.selenium.Proxy;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebDriverException;
import org.openqa.selenium.bidi.webextension.ExtensionArchivePath;
import org.openqa.selenium.bidi.webextension.ExtensionPath;
import org.openqa.selenium.bidi.webextension.InstallExtensionParameters;
import org.openqa.selenium.bidi.webextension.WebExtension;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.chromium.ChromiumOptions;
import org.openqa.selenium.edge.EdgeDriver;
import org.openqa.selenium.edge.EdgeOptions;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.firefox.FirefoxOptions;
import org.openqa.selenium.firefox.FirefoxProfile;
import org.openqa.selenium.firefox.ProfilesIni;
import org.openqa.selenium.htmlunit.HtmlUnitDriver;
import org.openqa.selenium.remote.CapabilityType;
import org.openqa.selenium.remote.DesiredCapabilities;
import org.openqa.selenium.remote.RemoteWebDriver;
import org.openqa.selenium.safari.SafariDriver;
import org.openqa.selenium.safari.SafariOptions;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.addon.network.server.ServerInfo;
import org.zaproxy.zap.extension.AddonFilesChangedListener;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.selenium.internal.BrowserArgument;
import org.zaproxy.zap.extension.selenium.internal.BuiltInSingleWebDriverProvider;
import org.zaproxy.zap.extension.selenium.internal.CustomBrowserImpl;
import org.zaproxy.zap.extension.selenium.internal.CustomBrowserWebDriverProvider;
import org.zaproxy.zap.extension.selenium.internal.FirefoxProfileManager;
import org.zaproxy.zap.utils.Stats;

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

    private static final Logger LOGGER = LogManager.getLogger(ExtensionSelenium.class);

    private static final Logger WEBDRIVER_LOGGER = LogManager.getLogger("org.zaproxy.webdriver");

    private static final String BIDI_CAPABILITIY = "webSocketUrl";

    private static final List<Class<? extends Extension>> EXTENSION_DEPENDENCIES =
            List.of(ExtensionNetwork.class);

    private static final int MIN_PORT = 1;

    private static final int MAX_PORT = 65535;

    private SeleniumOptions options;
    private SeleniumOptionsPanel optionsPanel;

    private SeleniumAPI seleniumApi;

    private AddonFilesChangedListener addonFilesChangedListener;

    private Map<Browser, ProfileManager> profileManagerMap = new HashMap<>();

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
     * A list containing all of the WebDrivers opened, so that they can be closed when ZAP is
     * closed.
     */
    private static List<WebDriver> webDrivers = Collections.synchronizedList(new ArrayList<>());

    private List<WeakReference<ProvidedBrowsersComboBoxModel>> providedBrowserComboBoxModels =
            new ArrayList<>();

    private List<BrowserHook> browserHooks = Collections.synchronizedList(new ArrayList<>());

    private ExtensionScript extScript;

    private ScriptType seleniumScriptType;

    private ExtensionNetwork extensionNetwork;

    public ExtensionSelenium() {
        super(NAME);

        // Prevent verbose INFO logging of WebDriver BiDi exchanges.
        setLogLevel(List.of("org.openqa.selenium.bidi.Connection"), Level.WARN);
    }

    private static void setLogLevel(List<String> classnames, Level level) {
        boolean updateLoggers = false;
        LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
        Configuration configuration = ctx.getConfiguration();
        for (String classname : classnames) {
            LoggerConfig loggerConfig = configuration.getLoggerConfig(classname);
            if (!classname.equals(loggerConfig.getName())) {
                configuration.addLogger(
                        classname,
                        LoggerConfig.newBuilder()
                                .withLoggerName(classname)
                                .withLevel(level)
                                .withConfig(configuration)
                                .build());
                updateLoggers = true;
            }
        }

        if (updateLoggers) {
            ctx.updateLoggers();
        }
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
    public List<Class<? extends Extension>> getDependencies() {
        return EXTENSION_DEPENDENCIES;
    }

    @Override
    public boolean supportsDb(String type) {
        return true;
    }

    @Override
    public void init() {
        super.init();

        seleniumApi = new SeleniumAPI(getOptions(), this);
        addonFilesChangedListener = new AddonFilesChangedListenerImpl();
        webDriverProviders = Collections.synchronizedMap(new HashMap<>());
        providedBrowsers = Collections.synchronizedMap(new HashMap<>());

        addBuiltInProvider(Browser.CHROME);
        addBuiltInProvider(Browser.CHROME_HEADLESS);
        addBuiltInProvider(Browser.EDGE);
        addBuiltInProvider(Browser.EDGE_HEADLESS);
        addBuiltInProvider(Browser.FIREFOX);
        addBuiltInProvider(Browser.FIREFOX_HEADLESS);
        addBuiltInProvider(Browser.HTML_UNIT);
        addBuiltInProvider(Browser.SAFARI);

        providedBrowserUIList = new ArrayList<>();
        buildProvidedBrowserUIList();
    }

    /**
     * Registers custom browsers as WebDriver providers. This should be called after options are
     * loaded or when custom browsers are added/removed.
     */
    protected void registerCustomBrowsers() {
        // Remove existing custom browser providers
        List<SingleWebDriverProvider> toRemove = new ArrayList<>();
        for (Map.Entry<String, SingleWebDriverProvider> entry : webDriverProviders.entrySet()) {
            if (entry.getKey().startsWith("custom.")) {
                toRemove.add(entry.getValue());
            }
        }
        for (SingleWebDriverProvider provider : toRemove) {
            removeWebDriverProvider(provider);
        }

        // Register new custom browsers (both regular and headless versions)
        for (CustomBrowserImpl customBrowser : getOptions().getCustomBrowsers()) {
            if (customBrowser.isConfigured()) {
                try {
                    addWebDriverProvider(new CustomBrowserWebDriverProvider(customBrowser, false));
                    addWebDriverProvider(new CustomBrowserWebDriverProvider(customBrowser, true));
                } catch (Exception e) {
                    LOGGER.warn("Failed to register custom browser: " + customBrowser.getName(), e);
                }
            }
        }
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

        if (hasView()) {
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
        if (!hasView()) {
            return null;
        }
        return new ImageIcon(
                ExtensionSelenium.class.getResource(
                        "/org/zaproxy/zap/extension/selenium/resources/script-selenium.png"));
    }

    @Override
    public void optionsLoaded() {
        registerCustomBrowsers();
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
    public void destroy() {
        webDrivers.forEach(
                wd -> {
                    try {
                        wd.quit();
                    } catch (Exception ex) {
                        // Ignore - the user might well have already closed the browser
                    }
                });
        webDrivers.clear();
    }

    /**
     * Adds the given WebDriver provider.
     *
     * @param webDriverProvider the WebDriver provider to add
     * @throws IllegalArgumentException if the given WebDriver provider is {@code null} or its ID is
     *     {@code null} or empty. Also, if the ID already exists.
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

        if (hasView()) {
            SwingUtilities.invokeLater(
                    () -> {
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
                    });
        }
    }

    /**
     * Validates that the given WebDriver provider is not {@code null} nor has a {@code null} or
     * empty ID.
     *
     * @param webDriverProvider the WebDriver provider to validate.
     * @throws IllegalArgumentException if the given WebDriver provider is {@code null} or its ID is
     *     {@code null} or empty.
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
     * @throws IllegalArgumentException if the given WebDriver provider is {@code null} or its ID is
     *     {@code null} or empty.
     * @since 1.1.0
     */
    public void removeWebDriverProvider(SingleWebDriverProvider webDriverProvider) {
        validateWebDriverProvider(webDriverProvider);

        webDriverProviders.remove(webDriverProvider.getId());
        providedBrowsers.remove(webDriverProvider.getProvidedBrowser().getId());
        buildProvidedBrowserUIList();

        if (hasView()) {
            SwingUtilities.invokeLater(
                    () -> {
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
        providedBrowserComboBoxModels.add(new WeakReference<>(model));
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
        List<ProvidedBrowserUI> list = new ArrayList<>();
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
        List<String> list = new ArrayList<>();
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
    public static String getName(Browser browser) {
        return Constant.messages.getString("selenium.browser.name." + browser.getId());
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
            optionsPanel =
                    new SeleniumOptionsPanel(this, getView().getOptionsDialog(), getMessages());
        }
        return optionsPanel;
    }

    public WebDriver getWebDriver(int requester, String providedBrowserId) {
        return getWebDriver(requester, providedBrowserId, true);
    }

    /**
     * Gets a {@code WebDriver} to the provided browser for the given requester.
     *
     * @param requester the ID of the (ZAP) component that's requesting the {@code WebDriver}.
     * @param providedBrowserId the ID of the provided browser.
     * @param enableExtensions if true then optional browser extensions will be enabled
     * @return the {@code WebDriver} to the provided browser.
     * @throws IllegalArgumentException if the provided browser was not found.
     * @since 1.1.0
     */
    public WebDriver getWebDriver(
            int requester, String providedBrowserId, boolean enableExtensions) {
        return getWebDriverImpl(requester, providedBrowserId, null, -1, enableExtensions);
    }

    public WebDriver getWebDriver(
            int requester, String providedBrowserId, String proxyAddress, int proxyPort) {
        return this.getWebDriver(requester, providedBrowserId, proxyAddress, proxyPort, true);
    }

    /**
     * Gets a {@code WebDriver} to the provided browser for the given requester, proxying through
     * the given address and port.
     *
     * @param requester the ID of the (ZAP) component that's requesting the {@code WebDriver}.
     * @param providedBrowserId the ID of the provided browser.
     * @param proxyAddress the address of the proxy.
     * @param proxyPort the port of the proxy.
     * @param enableExtensions if true then optional browser extensions will be enabled
     * @return the {@code WebDriver} to the provided browser, proxying through the given address and
     *     port.
     * @throws IllegalArgumentException if {@code proxyAddress} is {@code null} or empty, or if
     *     {@code proxyPort} is not a valid port number (between 1 and 65535). Also, if the provided
     *     browser was not found.
     * @since 1.1.0
     */
    public WebDriver getWebDriver(
            int requester,
            String providedBrowserId,
            String proxyAddress,
            int proxyPort,
            boolean enableExtensions) {
        validateProxyAddressPort(proxyAddress, proxyPort);

        return getWebDriverImpl(
                requester, providedBrowserId, proxyAddress, proxyPort, enableExtensions);
    }

    public WebDriver getWebDriverProxyingViaZAP(int requester, String providedBrowserId) {
        return this.getWebDriverProxyingViaZAP(requester, providedBrowserId, true);
    }

    /**
     * Returns a WebDriver configured to proxy via ZAP
     *
     * @param requester the ZAP component that will use the browser
     * @param providedBrowserId the browser id
     * @param enableExtensions if true then optional browser extensions will be enabled
     */
    public WebDriver getWebDriverProxyingViaZAP(
            int requester, String providedBrowserId, boolean enableExtensions) {
        ServerInfo serverInfo = getExtensionNetwork().getMainProxyServerInfo();
        return this.getWebDriver(
                requester,
                providedBrowserId,
                serverInfo.getAddress(),
                serverInfo.getPort(),
                enableExtensions);
    }

    private ExtensionNetwork getExtensionNetwork() {
        if (extensionNetwork == null) {
            extensionNetwork =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionNetwork.class);
        }
        return extensionNetwork;
    }

    public WebDriver getProxiedBrowser(String providedBrowserId) {
        return this.getProxiedBrowser(providedBrowserId, true);
    }

    /**
     * Opens the identified browser for manual proxying through ZAP
     *
     * @param providedBrowserId the browser id
     * @param enableExtensions if true then optional browser extensions will be enabled
     */
    public WebDriver getProxiedBrowser(String providedBrowserId, boolean enableExtensions) {
        return this.getProxiedBrowser(providedBrowserId, null, enableExtensions);
    }

    public WebDriver getProxiedBrowserByName(final String browserName) {
        return this.getProxiedBrowserByName(browserName, true);
    }

    /**
     * Opens the identified browser for manual proxying through ZAP
     *
     * @param browserName the browser name
     * @param enableExtensions if true then optional browser extensions will be enabled
     */
    public WebDriver getProxiedBrowserByName(final String browserName, boolean enableExtensions) {
        return this.getProxiedBrowserByName(browserName, null, enableExtensions);
    }

    public WebDriver getProxiedBrowserByName(final String browserName, final String url) {
        return this.getProxiedBrowserByName(browserName, url, true);
    }

    /**
     * Opens the identified browser for manual proxying through ZAP
     *
     * @param browserName the browser name
     * @param url the url to open
     * @param enableExtensions if true then optional browser extensions will be enabled
     */
    public WebDriver getProxiedBrowserByName(
            final String browserName, final String url, boolean enableExtensions) {
        return this.getProxiedBrowserByName(
                HttpSender.PROXY_INITIATOR, browserName, url, enableExtensions);
    }

    public WebDriver getProxiedBrowserByName(
            final int requester, final String browserName, final String url) {
        return this.getProxiedBrowserByName(requester, browserName, url, true);
    }

    /**
     * Opens the identified browser for proxying through ZAP
     *
     * @param requester the ZAP component that will use the browser
     * @param browserName the browser name
     * @param url the url to open
     * @param enableExtensions if true then optional browser extensions will be enabled
     */
    public WebDriver getProxiedBrowserByName(
            final int requester,
            final String browserName,
            final String url,
            boolean enableExtensions) {
        for (ProvidedBrowserUI provided : providedBrowserUIList) {
            if (provided.getName().equals(browserName)) {
                return getProxiedBrowser(
                        requester, provided.getBrowser().getId(), url, enableExtensions);
            }
        }
        return null;
    }

    public WebDriver getProxiedBrowser(final ProvidedBrowserUI provided, final String url) {
        return this.getProxiedBrowser(provided, url, true);
    }

    /**
     * Opens the browser for manual proxying through ZAP
     *
     * @param provided the browser
     * @param url the URL to open
     * @param enableExtensions if true then optional browser extensions will be enabled
     */
    public WebDriver getProxiedBrowser(
            final ProvidedBrowserUI provided, final String url, boolean enableExtensions) {
        return getProxiedBrowser(provided.getBrowser().getId(), url, enableExtensions);
    }

    public WebDriver getProxiedBrowser(final String providedBrowserId, final String url) {
        return this.getProxiedBrowser(providedBrowserId, url, true);
    }

    /**
     * Opens the browser for manual proxying through ZAP
     *
     * @param providedBrowserId the browser id
     * @param url the URL to open
     * @param enableExtensions if true then optional browser extensions will be enabled
     */
    public WebDriver getProxiedBrowser(
            final String providedBrowserId, final String url, boolean enableExtensions) {
        return this.getProxiedBrowser(
                HttpSender.PROXY_INITIATOR, providedBrowserId, url, enableExtensions);
    }

    public WebDriver getProxiedBrowser(
            final int requester, final String providedBrowserId, final String url) {
        return this.getProxiedBrowser(requester, providedBrowserId, url, true);
    }

    /**
     * Opens the browser for manual proxying through ZAP
     *
     * @param requester the ZAP component that will use this browser
     * @param providedBrowserId the browser id
     * @param url the URL to open
     * @param enableExtensions if true then optional browser extensions will be enabled
     */
    public WebDriver getProxiedBrowser(
            final int requester,
            final String providedBrowserId,
            final String url,
            boolean enableExtensions) {
        ServerInfo serverInfo = getExtensionNetwork().getMainProxyServerInfo();
        WebDriver webDriver =
                getWebDriver(
                        requester,
                        providedBrowserId,
                        serverInfo.getAddress(),
                        serverInfo.getPort(),
                        enableExtensions);

        if (webDriver != null && url != null) {
            webDriver.get(url);
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
            int requester,
            String providedBrowserId,
            String proxyAddress,
            int proxyPort,
            boolean enableExtensions) {
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
                            .getWebDriver(requester, proxyAddress, proxyPort, enableExtensions);
        }

        SeleniumScriptUtils ssu =
                new SeleniumScriptUtils(wd, requester, providedBrowserId, proxyAddress, proxyPort);

        // Run any hooks registered by add-ons first
        browserHooks.forEach(
                script -> {
                    try {
                        script.browserLaunched(ssu);
                    } catch (Exception e) {
                        LOGGER.error(e.getMessage(), e);
                    }
                });

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
                                            s.browserLaunched(ssu);
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
        return getWebDriver(requester, browser, proxyAddress, proxyPort, false);
    }

    public static WebDriver getWebDriver(
            int requester,
            Browser browser,
            String proxyAddress,
            int proxyPort,
            boolean enableExtensions) {
        return getWebDriver(requester, browser, proxyAddress, proxyPort, c -> {}, enableExtensions);
    }

    public static WebDriver getWebDriver(
            Browser browser,
            String proxyAddress,
            int proxyPort,
            Consumer<MutableCapabilities> consumer) {
        return getWebDriver(browser, proxyAddress, proxyPort, consumer, false);
    }

    public static WebDriver getWebDriver(
            Browser browser,
            String proxyAddress,
            int proxyPort,
            Consumer<MutableCapabilities> consumer,
            boolean enableExtensions) {
        return getWebDriver(-1, browser, proxyAddress, proxyPort, consumer, enableExtensions);
    }

    public static WebDriver getWebDriver(
            int requester,
            Browser browser,
            String proxyAddress,
            int proxyPort,
            Consumer<MutableCapabilities> consumer,
            boolean enableExtensions) {
        validateProxyAddressPort(proxyAddress, proxyPort);

        WebDriver wd;
        try {
            wd =
                    getWebDriverImpl(
                            requester,
                            browser,
                            proxyAddress,
                            proxyPort,
                            consumer,
                            enableExtensions);
            updateLaunchStats(requester, browser, true);
        } catch (Exception e) {
            updateLaunchStats(requester, browser, false);
            throw e;
        }
        webDrivers.add(wd);
        return wd;
    }

    private static void updateLaunchStats(int requester, Browser browser, boolean success) {
        String key = "stats.selenium.launch." + requester + "." + browser.getId();
        if (success) {
            Stats.incCounter("stats.selenium.launch." + browser.getId());
        } else {
            key += ".failure";
        }
        Stats.incCounter(key);
    }

    private static void setCommonOptions(
            MutableCapabilities capabilities, String proxyAddress, int proxyPort) {
        capabilities.setCapability(CapabilityType.ACCEPT_INSECURE_CERTS, true);

        if (proxyAddress != null) {
            String httpProxy = proxyAddress + ":" + proxyPort;
            Proxy proxy = new Proxy();
            proxy.setHttpProxy(httpProxy);
            proxy.setSslProxy(httpProxy);
            capabilities.setCapability(CapabilityType.PROXY, proxy);
        }
    }

    private static SeleniumOptions getSeleniumOptions() {
        return Model.getSingleton().getOptionsParam().getParamSet(SeleniumOptions.class);
    }

    private static void addFirefoxArguments(FirefoxOptions options) {
        List<String> arguments =
                getSeleniumOptions().getBrowserArguments(Browser.FIREFOX.getId()).stream()
                        .filter(BrowserArgument::isEnabled)
                        .map(BrowserArgument::getArgument)
                        .collect(Collectors.toList());
        if (!arguments.isEmpty()) {
            options.addArguments(arguments);
        }
    }

    private static void configureChromiumOptions(
            ChromiumOptions<?> options,
            String proxyAddress,
            int proxyPort,
            boolean headless,
            String binaryPath,
            List<String> customArguments) {
        options.setCapability(BIDI_CAPABILITIY, true);
        setCommonOptions(options, proxyAddress, proxyPort);
        options.addArguments("--proxy-bypass-list=<-loopback>");
        options.addArguments("--ignore-certificate-errors");
        options.addArguments("");
        options.addArguments("--remote-debugging-pipe");

        if (customArguments != null) {
            options.addArguments(customArguments);
        }

        if (headless) {
            options.addArguments("--headless=new");
        }

        if (StringUtils.isNotEmpty(binaryPath)) {
            options.setBinary(binaryPath);
        }
    }

    private static void configureBuiltInChromiumOptions(
            ChromiumOptions<?> options,
            Browser browser,
            String proxyAddress,
            int proxyPort,
            boolean headless,
            String binaryPath) {
        configureChromiumOptions(
                options, proxyAddress, proxyPort, headless, binaryPath, Collections.emptyList());

        List<String> arguments = new ArrayList<>();
        getSeleniumOptions().getBrowserArguments(browser.getId()).stream()
                .filter(BrowserArgument::isEnabled)
                .map(BrowserArgument::getArgument)
                .forEach(arguments::add);
        if (!arguments.isEmpty()) {
            options.addArguments(arguments);
        }
    }

    /**
     * Sets Firefox proxy preferences manually (required due to Firefox bugs).
     *
     * @param options the Firefox options to configure
     * @param proxyAddress the proxy address
     * @param proxyPort the proxy port
     */
    private static void setFirefoxProxyPreferences(
            FirefoxOptions options, String proxyAddress, int proxyPort) {
        // Some issues prevent the PROXY capability from being properly applied:
        // https://bugzilla.mozilla.org/show_bug.cgi?id=1282873
        // https://bugzilla.mozilla.org/show_bug.cgi?id=1369827
        // For now set the preferences manually:
        options.addPreference("network.proxy.type", 1);
        options.addPreference("network.proxy.http", proxyAddress);
        options.addPreference("network.proxy.http_port", proxyPort);
        options.addPreference("network.proxy.ssl", proxyAddress);
        options.addPreference("network.proxy.ssl_port", proxyPort);
        options.addPreference("network.proxy.share_proxy_settings", true);
        options.addPreference("network.proxy.no_proxies_on", "");
        // Fixes a problem with the HUD
        options.addPreference("browser.tabs.documentchannel", false);
        // And remove the PROXY capability:
        options.setCapability(CapabilityType.PROXY, (Object) null);
    }

    private static void configureFirefoxOptions(
            FirefoxOptions options,
            String proxyAddress,
            int proxyPort,
            int requester,
            boolean headless,
            String binaryPath,
            List<String> customArguments) {
        options.setCapability(BIDI_CAPABILITIY, true);
        setCommonOptions(options, proxyAddress, proxyPort);

        if (binaryPath != null && !binaryPath.isEmpty()) {
            options.setBinary(binaryPath);
        }

        // Keep proxying localhost on Firefox >= 67
        options.addPreference("network.proxy.allow_hijacking_localhost", true);
        // Ensure ServiceWorkers are enabled for the HUD.
        options.addPreference("dom.serviceWorkers.enabled", true);
        // Disable the captive checks/requests, mainly to avoid flooding
        // the AJAX Spider results (those requests are out of scope) but
        // also useful for other launched browsers.
        options.addPreference("network.captive-portal-service.enabled", false);

        if (requester == HttpSender.AJAX_SPIDER_INITIATOR
                || requester == HttpSender.ACTIVE_SCANNER_INITIATOR) {
            // Disable JSON viewer, otherwise AJAX Spider or scan rules will use it,
            // potentially invoking the "Save As" dialog which will hang waiting for the
            // user to click on a button.
            // https://developer.mozilla.org/en-US/docs/Tools/JSON_viewer
            options.addPreference("devtools.jsonview.enabled", false);
        }

        if (proxyAddress != null) {
            setFirefoxProxyPreferences(options, proxyAddress, proxyPort);
        }

        if (headless) {
            options.addArguments("-headless");
        }

        if (!customArguments.isEmpty()) {
            options.addArguments(customArguments);
        }
    }

    private static void configureBuiltInFirefoxOptions(
            FirefoxOptions options,
            String proxyAddress,
            int proxyPort,
            int requester,
            boolean headless,
            String binaryPath) {
        configureFirefoxOptions(
                options,
                proxyAddress,
                proxyPort,
                requester,
                headless,
                binaryPath,
                Collections.emptyList());
        addFirefoxArguments(options);
    }

    /**
     * Extracts enabled custom browser arguments from a CustomBrowser.
     *
     * @param customBrowser the custom browser
     * @return list of enabled argument strings
     */
    private static List<String> getCustomBrowserArguments(CustomBrowserImpl customBrowser) {
        return customBrowser.getArguments().stream()
                .filter(BrowserArgument::isEnabled)
                .map(BrowserArgument::getArgument)
                .collect(Collectors.toList());
    }

    private static RemoteWebDriver configureDriver(
            Browser browser, RemoteWebDriver driver, boolean enableExtensions) {
        driver.script().addConsoleMessageHandler(e -> WEBDRIVER_LOGGER.debug(e.getText()));

        if (enableExtensions) {
            WebExtension webExt = new WebExtension(driver);
            getSeleniumOptions().getEnabledBrowserExtensions(browser).stream()
                    .map(BrowserExtension::getPath)
                    .map(Path::toAbsolutePath)
                    .map(Path::toString)
                    .map(browser == Browser.CHROME ? ExtensionPath::new : ExtensionArchivePath::new)
                    .map(InstallExtensionParameters::new)
                    .forEach(webExt::install);
        }

        return driver;
    }

    private static WebDriver getWebDriverImpl(
            int requester,
            Browser browser,
            String proxyAddress,
            int proxyPort,
            Consumer<MutableCapabilities> consumer,
            boolean enableExtensions) {
        switch (browser) {
            case CHROME:
            case CHROME_HEADLESS:
                ChromeOptions chromeOptions = new ChromeOptions();
                String chromeBinary =
                        System.getProperty(SeleniumOptions.CHROME_BINARY_SYSTEM_PROPERTY);
                configureBuiltInChromiumOptions(
                        chromeOptions,
                        Browser.CHROME,
                        proxyAddress,
                        proxyPort,
                        browser == Browser.CHROME_HEADLESS,
                        chromeBinary);
                consumer.accept(chromeOptions);
                return configureDriver(
                        Browser.CHROME, new ChromeDriver(chromeOptions), enableExtensions);
            case EDGE, EDGE_HEADLESS:
                EdgeOptions edgeOptions = new EdgeOptions();
                String edgeBinary = System.getProperty(SeleniumOptions.EDGE_BINARY_SYSTEM_PROPERTY);
                configureBuiltInChromiumOptions(
                        edgeOptions,
                        Browser.EDGE,
                        proxyAddress,
                        proxyPort,
                        browser == Browser.EDGE_HEADLESS,
                        edgeBinary);
                consumer.accept(edgeOptions);
                return configureDriver(
                        Browser.CHROME, new EdgeDriver(edgeOptions), enableExtensions);
            case FIREFOX:
            case FIREFOX_HEADLESS:
                FirefoxOptions firefoxOptions = new FirefoxOptions();
                String firefoxBinary =
                        System.getProperty(SeleniumOptions.FIREFOX_BINARY_SYSTEM_PROPERTY);
                configureBuiltInFirefoxOptions(
                        firefoxOptions,
                        proxyAddress,
                        proxyPort,
                        requester,
                        browser == Browser.FIREFOX_HEADLESS,
                        firefoxBinary);
                consumer.accept(firefoxOptions);

                String fxProfile = getSeleniumOptions().getFirefoxDefaultProfile();
                if (!StringUtils.isEmpty(fxProfile)) {
                    ProfilesIni pi = new ProfilesIni();
                    try {
                        FirefoxProfile firefoxProfile = pi.getProfile(fxProfile);
                        firefoxOptions.setProfile(firefoxProfile);
                    } catch (Exception e) {
                        LOGGER.error(e.getMessage(), e);
                    }
                }

                return configureDriver(
                        Browser.FIREFOX, new FirefoxDriver(firefoxOptions), enableExtensions);
            case HTML_UNIT:
                DesiredCapabilities htmlunitCapabilities = new DesiredCapabilities();
                setCommonOptions(htmlunitCapabilities, proxyAddress, proxyPort);
                htmlunitCapabilities.setBrowserName(
                        org.openqa.selenium.remote.Browser.HTMLUNIT.browserName());

                consumer.accept(htmlunitCapabilities);
                return new HtmlUnitDriver(htmlunitCapabilities);
            case INTERNET_EXPLORER:
            case OPERA:
            case PHANTOM_JS:
                throw new WebDriverException("No longer supported.");
            case SAFARI:
                SafariOptions safariOptions = new SafariOptions();
                setCommonOptions(safariOptions, proxyAddress, proxyPort);

                consumer.accept(safariOptions);
                return new SafariDriver(safariOptions);
            default:
                throw new IllegalArgumentException("Unknown browser: " + browser);
        }
    }

    /**
     * Gets a {@code WebDriver} for the given requester and custom browser.
     *
     * @param requester the ID of the component requesting the {@code WebDriver}.
     * @param customBrowser the custom browser.
     * @param headless if true, the browser will run in headless mode.
     * @return the {@code WebDriver} to the given custom browser.
     */
    public static WebDriver getWebDriver(
            int requester, CustomBrowserImpl customBrowser, boolean headless) {
        return getWebDriver(requester, customBrowser, null, -1, false, headless);
    }

    /**
     * Gets a {@code WebDriver} for the given requester and custom browser, proxying through the
     * given address and port.
     *
     * @param requester the ID of the component requesting the {@code WebDriver}.
     * @param customBrowser the custom browser.
     * @param proxyAddress the address of the proxy.
     * @param proxyPort the port of the proxy.
     * @param enableExtensions if true then optional browser extensions will be enabled
     * @param headless if true, the browser will run in headless mode.
     * @return the {@code WebDriver} to the given custom browser, proxying through the given address
     *     and port.
     */
    public static WebDriver getWebDriver(
            int requester,
            CustomBrowserImpl customBrowser,
            String proxyAddress,
            int proxyPort,
            boolean enableExtensions,
            boolean headless) {
        return getWebDriver(
                requester,
                customBrowser,
                proxyAddress,
                proxyPort,
                c -> {},
                enableExtensions,
                headless);
    }

    /**
     * Gets a {@code WebDriver} for the given requester and custom browser, proxying through the
     * given address and port.
     *
     * @param requester the ID of the component requesting the {@code WebDriver}.
     * @param customBrowser the custom browser.
     * @param proxyAddress the address of the proxy.
     * @param proxyPort the port of the proxy.
     * @param consumer consumer to modify capabilities.
     * @param enableExtensions if true then optional browser extensions will be enabled
     * @param headless if true, the browser will run in headless mode.
     * @return the {@code WebDriver} to the given custom browser, proxying through the given address
     *     and port.
     */
    public static WebDriver getWebDriver(
            int requester,
            CustomBrowserImpl customBrowser,
            String proxyAddress,
            int proxyPort,
            Consumer<MutableCapabilities> consumer,
            boolean enableExtensions,
            boolean headless) {
        if (proxyAddress != null) {
            validateProxyAddressPort(proxyAddress, proxyPort);
        }

        WebDriver wd;
        try {
            wd =
                    getWebDriverImpl(
                            requester,
                            customBrowser,
                            proxyAddress,
                            proxyPort,
                            consumer,
                            enableExtensions,
                            headless);
            updateLaunchStats(requester, customBrowser, true);
        } catch (Exception e) {
            updateLaunchStats(requester, customBrowser, false);
            throw e;
        }
        webDrivers.add(wd);
        return wd;
    }

    private static void updateLaunchStats(
            int requester, CustomBrowserImpl customBrowser, boolean success) {
        String key = "stats.selenium.launch." + requester + ".custom." + customBrowser.getName();
        if (success) {
            Stats.incCounter("stats.selenium.launch.custom." + customBrowser.getName());
        } else {
            key += ".failure";
        }
        Stats.incCounter(key);
    }

    private static WebDriver getWebDriverImpl(
            int requester,
            CustomBrowserImpl customBrowser,
            String proxyAddress,
            int proxyPort,
            Consumer<MutableCapabilities> consumer,
            boolean enableExtensions,
            boolean headless) {
        if (!customBrowser.isConfigured()) {
            throw new IllegalArgumentException(
                    "Custom browser is not fully configured: " + customBrowser.getName());
        }

        switch (customBrowser.getBrowserType()) {
            case CHROMIUM:
                ChromeOptions chromeOptions = new ChromeOptions();
                configureChromiumOptions(
                        chromeOptions,
                        proxyAddress,
                        proxyPort,
                        headless,
                        customBrowser.getBinaryPath(),
                        getCustomBrowserArguments(customBrowser));
                consumer.accept(chromeOptions);

                // Set driver path if provided
                if (!customBrowser.getDriverPath().isEmpty()) {
                    System.setProperty("webdriver.chrome.driver", customBrowser.getDriverPath());
                }

                return configureDriver(
                        Browser.CHROME, new ChromeDriver(chromeOptions), enableExtensions);
            case FIREFOX:
                FirefoxOptions firefoxOptions = new FirefoxOptions();
                configureFirefoxOptions(
                        firefoxOptions,
                        proxyAddress,
                        proxyPort,
                        requester,
                        headless,
                        customBrowser.getBinaryPath(),
                        getCustomBrowserArguments(customBrowser));
                consumer.accept(firefoxOptions);

                // Set driver path if provided
                if (!customBrowser.getDriverPath().isEmpty()) {
                    System.setProperty("webdriver.gecko.driver", customBrowser.getDriverPath());
                }

                return configureDriver(
                        Browser.FIREFOX, new FirefoxDriver(firefoxOptions), enableExtensions);
            default:
                throw new IllegalArgumentException(
                        "Custom browser type is not supported: "
                                + customBrowser.getBrowserType()
                                + " for browser: "
                                + customBrowser.getName());
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
            String message = e.getMessage();
            if (message != null && message.contains("cannot find")) {
                return Constant.messages.getString(
                        "selenium.warn.message.browser.not.found", providedBrowserId);
            }
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
            case EDGE:
                return getMessages().getString("selenium.warn.message.failed.start.browser.edge");
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
        browsers.add(Browser.SAFARI);
        // Requires drivers, but hopefully they are already provided.
        browsers.add(Browser.CHROME);
        browsers.add(Browser.FIREFOX);

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
            case OPERA:
            case PHANTOM_JS:
                return false;
            case SAFARI:
                return Constant.isMacOsX();
            default:
                // All the rest should work on all platforms
                return true;
        }
    }

    /**
     * Register a browser hook. These are always executed synchronously.
     *
     * @param hook the hook to register
     */
    public void registerBrowserHook(BrowserHook hook) {
        Objects.requireNonNull(hook);
        this.browserHooks.add(hook);
    }

    /**
     * Deregister a browser hook.
     *
     * @param hook the hook to deregister
     */
    public void deregisterBrowserHook(BrowserHook hook) {
        Objects.requireNonNull(hook);
        this.browserHooks.remove(hook);
    }

    /**
     * Returns the profile manager for the specified browser.
     *
     * @param browser the browser
     * @return the profile manager for the specified browser, or null if one is not supported.
     * @since 15.14.0
     */
    public ProfileManager getProfileManager(Browser browser) {
        if (Browser.FIREFOX.equals(browser)) {
            return profileManagerMap.computeIfAbsent(
                    browser, s -> new FirefoxProfileManager(getOptions()));
        }
        return null;
    }

    /**
     * Sets the default Firefox profile name.
     *
     * @param profileName the profile name.
     * @since 15.14.0
     */
    public void setDefaultFirefoxProfile(String profileName) {
        if (getProfileManager(Browser.FIREFOX).getProfileDirectory(profileName) == null) {
            throw new IllegalArgumentException("Firefox profile does not exist: " + profileName);
        }
        this.getOptions().setFirefoxDefaultProfile(profileName);
    }

    /**
     * Add a custom browser
     *
     * @param browser the custom browser to add
     * @since 15.44.0
     */
    public void addCustomBrowser(CustomBrowser browser) {
        Objects.requireNonNull(browser);
        this.getOptions().addCustomBrowser(new CustomBrowserImpl(browser));
    }

    /**
     * Remove a custom browser
     *
     * @param name the name of the custom browser to remove
     * @return true if the browser was removed
     * @since 15.44.0
     */
    public boolean removeCustomBrowser(String name) {
        Objects.requireNonNull(name);
        return this.getOptions().removeCustomBrowser(name);
    }
}
