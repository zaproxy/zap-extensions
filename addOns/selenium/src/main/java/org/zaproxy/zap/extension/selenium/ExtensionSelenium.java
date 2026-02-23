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
import org.openqa.selenium.chrome.ChromeDriverService;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.chromium.ChromiumOptions;
import org.openqa.selenium.edge.EdgeDriver;
import org.openqa.selenium.edge.EdgeOptions;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.firefox.FirefoxOptions;
import org.openqa.selenium.firefox.FirefoxProfile;
import org.openqa.selenium.firefox.GeckoDriverService;
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
import org.zaproxy.zap.extension.selenium.DriverConfiguration.DriverType;
import org.zaproxy.zap.extension.selenium.internal.BrowserArgument;
import org.zaproxy.zap.extension.selenium.internal.BrowserPreference;
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
        // Safari disabled as it appears not to support proxying
        // addBuiltInProvider(Browser.SAFARI);

        providedBrowserUIList = new ArrayList<>();
        buildProvidedBrowserUIList();
    }

    /**
     * Registers custom browsers as WebDriver providers. This should be called after options are
     * loaded or when custom browsers are added/removed.
     */
    protected void registerCustomBrowsers() {
        // Remove existing custom browser providers
        List<SingleWebDriverProvider> toRemove =
                webDriverProviders.values().stream()
                        .filter(SingleWebDriverProvider::isCustom)
                        .toList();
        toRemove.forEach(p -> removeWebDriverProvider(p));

        // Register new custom browsers (both regular and headless versions)
        for (CustomBrowserImpl customBrowser : getOptions().getCustomBrowsers()) {
            try {
                addWebDriverProvider(new CustomBrowserWebDriverProvider(customBrowser, false));
                addWebDriverProvider(new CustomBrowserWebDriverProvider(customBrowser, true));
            } catch (Exception e) {
                LOGGER.warn("Failed to register custom browser: {}", customBrowser.getName(), e);
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

    protected SeleniumOptions getOptions() {
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
        return getWebDriver(
                providedBrowserId,
                DriverConfiguration.builder().requester(requester).enableExtensions(true).build());
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
        return getWebDriver(
                providedBrowserId,
                DriverConfiguration.builder()
                        .requester(requester)
                        .enableExtensions(enableExtensions)
                        .build());
    }

    public WebDriver getWebDriver(
            int requester, String providedBrowserId, String proxyAddress, int proxyPort) {
        return getWebDriver(
                providedBrowserId,
                DriverConfiguration.builder()
                        .requester(requester)
                        .proxyAddress(proxyAddress)
                        .proxyPort(proxyPort)
                        .enableExtensions(true)
                        .build());
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
        return getWebDriver(
                providedBrowserId,
                DriverConfiguration.builder()
                        .type(browserToType(Browser.getBrowserWithId(providedBrowserId)))
                        .requester(requester)
                        .proxyAddress(proxyAddress)
                        .proxyPort(proxyPort)
                        .enableExtensions(enableExtensions)
                        .build());
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
        return getWebDriver(
                providedBrowserId,
                DriverConfiguration.builder()
                        .type(browserToType(Browser.getBrowserWithId(providedBrowserId)))
                        .requester(requester)
                        .proxyAddress(serverInfo.getAddress())
                        .proxyPort(serverInfo.getPort())
                        .enableExtensions(enableExtensions)
                        .build());
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

    /**
     * Gets a {@code WebDriver} for the given browser ID and driver configuration.
     *
     * <p>Handles both built-in browsers (Chrome, Edge, Firefox) and custom browsers. The {@code
     * browserId} is the provided browser ID (e.g. {@code "chrome"}, {@code "firefox"}, {@code
     * "custom.MyBrowser"}, {@code "custom.MyBrowser-headless"}).
     *
     * @param browserId the ID of the provided browser (built-in or custom).
     * @param driverConf the driver configuration (e.g. proxy, requester). May be {@code null} to
     *     use defaults.
     * @return the {@code WebDriver} for the given browser.
     * @throws IllegalArgumentException if the browser ID is unknown, or if proxy is invalid when
     *     set.
     */
    public WebDriver getWebDriver(String browserId, DriverConfiguration driverConf) {
        if (driverConf.getProxyAddress() != null) {
            validateProxyAddressPort(driverConf.getProxyAddress(), driverConf.getProxyPort());
        }
        ProvidedBrowser provided = getProvidedBrowser(browserId);
        if (provided == null) {
            throw new IllegalArgumentException("Unknown browser: " + browserId);
        }
        SingleWebDriverProvider provider = webDriverProviders.get(provided.getProviderId());
        if (provider == null) {
            throw new IllegalArgumentException("Unknown browser: " + browserId);
        }
        Consumer<MutableCapabilities> consumer =
                driverConf.getConsumer() != null ? driverConf.getConsumer() : c -> {};
        int requester = driverConf.getRequester();
        String proxyAddress = driverConf.getProxyAddress();
        int proxyPort = driverConf.getProxyPort();
        boolean enableExtensions = driverConf.isEnableExtensions();
        WebDriver wd;
        DriverConfiguration config;
        String statsKey;

        if (provider instanceof BuiltInSingleWebDriverProvider builtinBrowserProv) {
            Browser browser = builtinBrowserProv.getBrowser();
            statsKey = "stats.selenium.launch." + requester + "." + browser.getId();
            config =
                    buildConfigFromBrowser(
                            browser,
                            requester,
                            proxyAddress,
                            proxyPort,
                            consumer,
                            enableExtensions,
                            driverConf.getArguments(),
                            driverConf.getPreferences());
        } else if (provider instanceof CustomBrowserWebDriverProvider customBrowserProv) {
            CustomBrowserImpl customBrowser = customBrowserProv.getCustomBrowser();
            boolean headless = browserId.endsWith("-headless");
            statsKey = "stats.selenium.launch." + requester + ".custom." + customBrowser.getName();
            config =
                    buildConfigFromCustomBrowser(
                            customBrowser,
                            requester,
                            proxyAddress,
                            proxyPort,
                            headless,
                            consumer,
                            enableExtensions,
                            driverConf.getArguments(),
                            driverConf.getPreferences());
        } else {
            throw new IllegalArgumentException(
                    "Unknown ProvidedBrowser: " + provided.getClass().getCanonicalName());
        }

        try {
            wd = createWebDriver(config);
            Stats.incCounter(statsKey);
        } catch (Exception e) {
            Stats.incCounter(statsKey + ".failure");
            throw e;
        }

        SeleniumScriptUtils ssu =
                new SeleniumScriptUtils(wd, requester, browserId, proxyAddress, proxyPort);

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
        return getWebDriverViaExtension(browser.getId(), DriverConfiguration.builder().build());
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
        return getWebDriverViaExtension(
                browser.getId(), DriverConfiguration.builder().requester(requester).build());
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
        return getWebDriverViaExtension(
                browser.getId(),
                DriverConfiguration.builder()
                        .type(browserToType(browser))
                        .proxyAddress(proxyAddress)
                        .proxyPort(proxyPort)
                        .build());
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
        return getWebDriverViaExtension(
                browser.getId(),
                DriverConfiguration.builder()
                        .requester(requester)
                        .type(browserToType(browser))
                        .proxyAddress(proxyAddress)
                        .proxyPort(proxyPort)
                        .build());
    }

    public static WebDriver getWebDriver(
            int requester,
            Browser browser,
            String proxyAddress,
            int proxyPort,
            boolean enableExtensions) {
        return getWebDriverViaExtension(
                browser.getId(),
                DriverConfiguration.builder()
                        .requester(requester)
                        .type(browserToType(browser))
                        .proxyAddress(proxyAddress)
                        .proxyPort(proxyPort)
                        .enableExtensions(enableExtensions)
                        .build());
    }

    public static WebDriver getWebDriver(
            Browser browser,
            String proxyAddress,
            int proxyPort,
            Consumer<MutableCapabilities> consumer) {
        return getWebDriverViaExtension(
                browser.getId(),
                DriverConfiguration.builder()
                        .type(browserToType(browser))
                        .proxyAddress(proxyAddress)
                        .proxyPort(proxyPort)
                        .consumer(consumer)
                        .build());
    }

    public static WebDriver getWebDriver(
            Browser browser,
            String proxyAddress,
            int proxyPort,
            Consumer<MutableCapabilities> consumer,
            boolean enableExtensions) {
        return getWebDriverViaExtension(
                browser.getId(),
                DriverConfiguration.builder()
                        .type(browserToType(browser))
                        .proxyAddress(proxyAddress)
                        .proxyPort(proxyPort)
                        .consumer(consumer)
                        .enableExtensions(enableExtensions)
                        .build());
    }

    public static WebDriver getWebDriver(
            int requester,
            Browser browser,
            String proxyAddress,
            int proxyPort,
            Consumer<MutableCapabilities> consumer,
            boolean enableExtensions) {
        var builder =
                DriverConfiguration.builder()
                        .type(browserToType(browser))
                        .requester(requester)
                        .consumer(consumer)
                        .enableExtensions(enableExtensions);
        if (proxyAddress != null) {
            builder.proxyAddress(proxyAddress).proxyPort(proxyPort);
        }
        return getWebDriverViaExtension(browser.getId(), builder.build());
    }

    /**
     * Gets a {@code WebDriver} for the given browser ID and driver configuration by resolving the
     * extension and delegating to {@link #getWebDriver(String, DriverConfiguration)}. Used by
     * static delegating methods in this class.
     */
    private static WebDriver getWebDriverViaExtension(
            String browserId, DriverConfiguration driverConf) {
        ExtensionSelenium extension =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionSelenium.class);
        if (extension == null) {
            throw new IllegalStateException("Selenium extension is not loaded.");
        }
        DriverConfiguration conf =
                driverConf != null ? driverConf : DriverConfiguration.builder().build();
        return extension.getWebDriver(browserId, conf);
    }

    private static WebDriver createWebDriver(DriverConfiguration conf) {
        switch (conf.getType()) {
            case CHROMIUM:
            case EDGE:
                boolean isEdge = DriverType.EDGE.equals(conf.getType());
                ChromiumOptions<?> chromiumOptions =
                        isEdge ? new EdgeOptions() : new ChromeOptions();
                configureChromiumOptions(
                        chromiumOptions,
                        conf.getProxyAddress(),
                        conf.getProxyPort(),
                        conf.isHeadless(),
                        conf.getBinaryPath(),
                        conf.getArguments());
                applyChromiumPreferences(chromiumOptions, conf.getPreferences());
                conf.getConsumer().accept(chromiumOptions);

                if (isEdge) {
                    return configureDriver(
                            Browser.EDGE,
                            new EdgeDriver((EdgeOptions) chromiumOptions),
                            conf.isEnableExtensions());
                }
                ChromeDriver chromeDriver;
                if (StringUtils.isNotEmpty(conf.getDriverPath())) {
                    ChromeDriverService chromeService =
                            new ChromeDriverService.Builder()
                                    .usingDriverExecutable(new File(conf.getDriverPath()))
                                    .build();
                    chromeDriver = new ChromeDriver(chromeService, (ChromeOptions) chromiumOptions);
                } else {
                    chromeDriver = new ChromeDriver((ChromeOptions) chromiumOptions);
                }
                return configureDriver(Browser.CHROME, chromeDriver, conf.isEnableExtensions());

            case FIREFOX:
                FirefoxOptions firefoxOptions = new FirefoxOptions();
                configureFirefoxOptions(
                        firefoxOptions,
                        conf.getProxyAddress(),
                        conf.getProxyPort(),
                        conf.getRequester(),
                        conf.isHeadless(),
                        conf.getBinaryPath(),
                        conf.getArguments());
                applyFirefoxPreferences(firefoxOptions, conf.getPreferences());
                addFirefoxArguments(firefoxOptions);
                conf.getConsumer().accept(firefoxOptions);

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

                FirefoxDriver firefoxDriver;
                if (StringUtils.isNotEmpty(conf.getDriverPath())) {
                    GeckoDriverService geckoService =
                            new GeckoDriverService.Builder()
                                    .usingDriverExecutable(new File(conf.getDriverPath()))
                                    .build();
                    firefoxDriver = new FirefoxDriver(geckoService, firefoxOptions);
                } else {
                    firefoxDriver = new FirefoxDriver(firefoxOptions);
                }
                return configureDriver(Browser.FIREFOX, firefoxDriver, conf.isEnableExtensions());

            case HTML_UNIT:
                DesiredCapabilities htmlunitCapabilities = new DesiredCapabilities();
                setCommonOptions(htmlunitCapabilities, conf.getProxyAddress(), conf.getProxyPort());
                htmlunitCapabilities.setBrowserName(
                        org.openqa.selenium.remote.Browser.HTMLUNIT.browserName());
                conf.getConsumer().accept(htmlunitCapabilities);
                return new HtmlUnitDriver(htmlunitCapabilities);

            case SAFARI:
                SafariOptions safariOptions = new SafariOptions();
                setCommonOptions(safariOptions, conf.getProxyAddress(), conf.getProxyPort());
                conf.getConsumer().accept(safariOptions);
                return new SafariDriver(safariOptions);

            default:
                throw new WebDriverException("No longer supported.");
        }
    }

    private static DriverType browserToType(Browser browser) {
        return switch (browser) {
            case CHROME -> DriverConfiguration.DriverType.CHROMIUM;
            case CHROME_HEADLESS -> DriverConfiguration.DriverType.CHROMIUM;
            case EDGE -> DriverConfiguration.DriverType.EDGE;
            case EDGE_HEADLESS -> DriverConfiguration.DriverType.EDGE;
            case FIREFOX -> DriverConfiguration.DriverType.FIREFOX;
            case FIREFOX_HEADLESS -> DriverConfiguration.DriverType.FIREFOX;
            case HTML_UNIT -> DriverConfiguration.DriverType.HTML_UNIT;
            case SAFARI -> DriverConfiguration.DriverType.SAFARI;
            default -> null;
        };
    }

    protected static DriverConfiguration buildConfigFromBrowser(
            Browser browser,
            int requester,
            String proxyAddress,
            int proxyPort,
            Consumer<MutableCapabilities> consumer,
            boolean enableExtensions,
            List<String> extraArguments,
            Map<String, String> extraPreferences) {
        boolean headless;
        Browser baseBrowser;
        switch (browser) {
            case CHROME_HEADLESS:
                baseBrowser = Browser.CHROME;
                headless = true;
                break;
            case EDGE_HEADLESS:
                baseBrowser = Browser.EDGE;
                headless = true;
                break;
            case FIREFOX_HEADLESS:
                baseBrowser = Browser.FIREFOX;
                headless = true;
                break;
            default:
                baseBrowser = browser;
                headless = false;
        }
        String binaryPath = System.getProperty(SeleniumOptions.CHROME_BINARY_SYSTEM_PROPERTY);
        if (baseBrowser == Browser.EDGE) {
            binaryPath = System.getProperty(SeleniumOptions.EDGE_BINARY_SYSTEM_PROPERTY);
        } else if (baseBrowser == Browser.FIREFOX) {
            binaryPath = System.getProperty(SeleniumOptions.FIREFOX_BINARY_SYSTEM_PROPERTY);
        }

        List<String> arguments = new ArrayList<>();
        if (baseBrowser == Browser.CHROME || baseBrowser == Browser.EDGE) {
            getSeleniumOptions().getBrowserArguments(baseBrowser.getId()).stream()
                    .filter(BrowserArgument::isEnabled)
                    .map(BrowserArgument::getArgument)
                    .forEach(arguments::add);
        }
        if (extraArguments != null && !extraArguments.isEmpty()) {
            arguments.addAll(extraArguments);
        }

        Map<String, String> preferences = new HashMap<>();
        getSeleniumOptions().getBrowserPreferences(baseBrowser.getId()).stream()
                .filter(BrowserPreference::isEnabled)
                .forEach(
                        p -> {
                            if (p.getName() != null && !p.getName().isEmpty()) {
                                preferences.put(p.getName().trim(), p.getValue());
                            }
                        });
        if (extraPreferences != null && !extraPreferences.isEmpty()) {
            preferences.putAll(extraPreferences);
        }

        return DriverConfiguration.builder()
                .requester(requester)
                .type(browserToType(browser))
                .proxyAddress(proxyAddress)
                .proxyPort(proxyPort)
                .headless(headless)
                .binaryPath(binaryPath)
                .driverPath("")
                .arguments(arguments)
                .preferences(preferences)
                .consumer(consumer)
                .enableExtensions(enableExtensions)
                .build();
    }

    protected static DriverConfiguration buildConfigFromCustomBrowser(
            CustomBrowserImpl customBrowser,
            int requester,
            String proxyAddress,
            int proxyPort,
            boolean headless,
            Consumer<MutableCapabilities> consumer,
            boolean enableExtensions,
            List<String> extraArguments,
            Map<String, String> extraPreferences) {
        List<String> arguments = new ArrayList<>(getCustomBrowserArguments(customBrowser));
        if (extraArguments != null && !extraArguments.isEmpty()) {
            arguments.addAll(extraArguments);
        }

        String binaryPath;
        String driverPath;
        DriverType type;

        switch (customBrowser.getBrowserType()) {
            case CHROMIUM:
                type = DriverType.CHROMIUM;
                binaryPath =
                        StringUtils.isNotEmpty(customBrowser.getBinaryPath())
                                ? customBrowser.getBinaryPath()
                                : getSeleniumOptions().getChromeBinaryPath();
                driverPath = getEffectiveChromiumDriverPath(customBrowser);
                break;
            case FIREFOX:
                type = DriverType.FIREFOX;
                binaryPath =
                        StringUtils.isNotEmpty(customBrowser.getBinaryPath())
                                ? customBrowser.getBinaryPath()
                                : getSeleniumOptions().getFirefoxBinaryPath();
                driverPath = getEffectiveFirefoxDriverPath(customBrowser);
                break;
            default:
                throw new IllegalArgumentException(
                        "Custom browser type is not supported: "
                                + customBrowser.getBrowserType()
                                + " for browser: "
                                + customBrowser.getName());
        }

        Map<String, String> preferences = new HashMap<>();
        customBrowser.getPreferences().stream()
                .filter(BrowserPreference::isEnabled)
                .forEach(
                        p -> {
                            if (p.getName() != null && !p.getName().isEmpty()) {
                                preferences.put(p.getName().trim(), p.getValue());
                            }
                        });
        if (extraPreferences != null && !extraPreferences.isEmpty()) {
            preferences.putAll(extraPreferences);
        }

        return DriverConfiguration.builder()
                .requester(requester)
                .type(type)
                .proxyAddress(proxyAddress)
                .proxyPort(proxyPort)
                .headless(headless)
                .binaryPath(binaryPath)
                .driverPath(driverPath != null ? driverPath : "")
                .arguments(arguments)
                .preferences(preferences)
                .consumer(consumer)
                .enableExtensions(enableExtensions)
                .build();
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

    private static void applyChromiumPreferences(
            ChromiumOptions<?> options, Map<String, String> preferences) {
        if (preferences == null || preferences.isEmpty()) {
            return;
        }
        Map<String, Object> prefs = new HashMap<>();
        for (Map.Entry<String, String> entry : preferences.entrySet()) {
            String name = entry.getKey();
            if (name != null && !name.isEmpty()) {
                prefs.put(name.trim(), coercePreferenceValue(entry.getValue()));
            }
        }
        if (!prefs.isEmpty()) {
            options.setExperimentalOption("prefs", prefs);
        }
    }

    private static void applyFirefoxPreferences(
            FirefoxOptions options, Map<String, String> preferences) {
        if (preferences == null) {
            return;
        }
        for (Map.Entry<String, String> entry : preferences.entrySet()) {
            String name = entry.getKey();
            if (name != null && !name.isEmpty()) {
                options.addPreference(name.trim(), coercePreferenceValue(entry.getValue()));
            }
        }
    }

    private static Object coercePreferenceValue(String value) {
        if (value == null) {
            return "";
        }
        String v = value.trim();
        if ("true".equalsIgnoreCase(v)) {
            return true;
        }
        if ("false".equalsIgnoreCase(v)) {
            return false;
        }
        try {
            return Integer.parseInt(v);
        } catch (NumberFormatException e) {
            // not an integer
        }
        return v;
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
        // Needed to load the extensions.
        options.addArguments("--remote-debugging-pipe");
        options.addArguments("--enable-unsafe-extension-debugging");

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

        if (headless) {
            options.addArguments("-headless");
        }

        if (!customArguments.isEmpty()) {
            options.addArguments(customArguments);
        }
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

    /**
     * Returns the driver path to use for a custom Chromium browser: the custom browser's path if
     * set, otherwise the default Chrome driver path from options or bundled.
     */
    private static String getEffectiveChromiumDriverPath(CustomBrowserImpl customBrowser) {
        if (StringUtils.isNotEmpty(customBrowser.getDriverPath())) {
            return customBrowser.getDriverPath();
        }
        String path = getSeleniumOptions().getChromeDriverPath();
        if (StringUtils.isNotEmpty(path)) {
            return path;
        }
        path = Browser.getBundledWebDriverPath(Browser.CHROME);
        return path != null ? path : "";
    }

    /**
     * Returns the driver path to use for a custom Firefox browser: the custom browser's path if
     * set, otherwise the default Firefox driver path from options or bundled.
     */
    private static String getEffectiveFirefoxDriverPath(CustomBrowserImpl customBrowser) {
        if (StringUtils.isNotEmpty(customBrowser.getDriverPath())) {
            return customBrowser.getDriverPath();
        }
        String path = getSeleniumOptions().getFirefoxDriverPath();
        if (StringUtils.isNotEmpty(path)) {
            return path;
        }
        path = Browser.getBundledWebDriverPath(Browser.FIREFOX);
        return path != null ? path : "";
    }

    private static RemoteWebDriver configureDriver(
            Browser browser, RemoteWebDriver driver, boolean enableExtensions) {
        driver.script().addConsoleMessageHandler(e -> WEBDRIVER_LOGGER.debug(e.getText()));
        if (enableExtensions) {
            WebExtension webExt = new WebExtension(driver);
            boolean isChromium =
                    browser == Browser.CHROME
                            || browser == Browser.CHROME_HEADLESS
                            || browser == Browser.EDGE
                            || browser == Browser.EDGE_HEADLESS;
            getSeleniumOptions()
                    .getEnabledBrowserExtensions(isChromium ? Browser.CHROME : browser)
                    .stream()
                    .map(BrowserExtension::getPath)
                    .map(Path::toAbsolutePath)
                    .map(Path::toString)
                    .map(isChromium ? ExtensionPath::new : ExtensionArchivePath::new)
                    .map(InstallExtensionParameters::new)
                    .forEach(webExt::install);
        }

        return driver;
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
            if (e.getMessage().contains("cannot find")) {
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
        // Safari disabled as it appears not to support proxying
        // browsers.add(Browser.SAFARI);
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
            case SAFARI:
                // Disabled as it appears not to currently support proxying
                // return Constant.isMacOsX();
                return false;
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
        Objects.requireNonNull(browser.getName());
        Objects.requireNonNull(browser.getBrowserType());
        this.getOptions().addCustomBrowser(new CustomBrowserImpl(browser));
        registerCustomBrowsers();
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
        boolean res = this.getOptions().removeCustomBrowser(name);
        registerCustomBrowsers();
        return res;
    }
}
