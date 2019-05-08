/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.quickstart.launch;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import org.apache.commons.httpclient.URI;
import org.apache.log4j.Logger;
import org.openqa.selenium.WebDriver;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.network.HttpStatusCode;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.Version;
import org.zaproxy.zap.control.AddOn;
import org.zaproxy.zap.extension.AddOnInstallationStatusListener;
import org.zaproxy.zap.extension.api.API;
import org.zaproxy.zap.extension.quickstart.ExtensionQuickStart;
import org.zaproxy.zap.extension.quickstart.QuickStartParam;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.utils.DisplayUtils;

public class ExtensionQuickStartLaunch extends ExtensionAdaptor
        implements AddOnInstallationStatusListener {

    private static final String DEFAULT_VALUE_URL_FIELD = "http://";

    public static final String NAME = "ExtensionQuickStartLaunch";
    private static final String DEFAULT_LAUNCH_PAGE_URL_PREFIX = "https://bit.ly/owaspzap-start-";
    private static final String DEV_LAUNCH_PAGE = "dev";
    protected static final String PAGE_LOCALE_SEPARATOR =
            "<!-- - - - - - - - - %< - - - - - - - - -->\n";
    protected static final String PAGE_LOCALE_PREFIX = "<!-- Locale = ";
    protected static final String PAGE_LOCALE_POSTFIX = " -->";
    protected static final String PAGE_LOCALE_DEFAULT = "Default";
    private static final Logger LOGGER = Logger.getLogger(ExtensionQuickStartLaunch.class);

    public static final String RESOURCES = "/org/zaproxy/zap/extension/quickstart/resources";

    private static final ImageIcon CHROME_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            ExtensionQuickStart.class.getResource(RESOURCES + "/chrome.png")));
    private static final ImageIcon CHROMIUM_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            ExtensionQuickStart.class.getResource(RESOURCES + "/chromium.png")));
    private static final ImageIcon FIREFOX_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            ExtensionQuickStart.class.getResource(RESOURCES + "/firefox.png")));
    private static final ImageIcon SAFARI_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            ExtensionQuickStart.class.getResource(RESOURCES + "/safari.png")));

    private String defaultLaunchContent;

    private QuickStartLaunchAPI api;
    private OptionsQuickStartLaunchPanel optionsPanel;
    private LaunchPanel launchPanel;

    private JButton launchToolbarButton;

    private static final List<Class<? extends Extension>> DEPENDENCIES;

    static {
        List<Class<? extends Extension>> dependencies = new ArrayList<>(2);
        dependencies.add(ExtensionQuickStart.class);
        dependencies.add(ExtensionSelenium.class);
        DEPENDENCIES = Collections.unmodifiableList(dependencies);
    }

    public ExtensionQuickStartLaunch() {
        super(NAME);
    }

    @Override
    public boolean supportsDb(String type) {
        return true;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        this.api = new QuickStartLaunchAPI(this);
        extensionHook.addApiImplementor(api);
        extensionHook.addAddOnInstallationStatusListener(this);

        if (getView() != null) {
            extensionHook.getHookView().addMainToolBarComponent(getLaunchToolbarButton());
            extensionHook.getHookView().addOptionPanel(getOptionsPanel());

            this.launchPanel =
                    new LaunchPanel(
                            this,
                            this.getExtQuickStart(),
                            this.getExtQuickStart().getQuickStartPanel());
            this.getExtQuickStart().setLaunchPanel(this.launchPanel);
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        if (getView() != null) {
            this.getExtQuickStart().setLaunchPanel(null);
        }
    }

    @Override
    public void postInit() {
        if (this.launchPanel != null) {
            this.launchPanel.postInit();
        }
    }

    @Override
    public void optionsLoaded() {
        super.optionsLoaded();
        if (View.isInitialised()) {
            // Always init in case the user changes to use the default home page
            // later
            defaultLaunchContent = Constant.messages.getString("quickstart.launch.html");
            setToolbarButtonIcon(
                    this.getExtQuickStart().getQuickStartParam().getLaunchDefaultBrowser());
        }

        if (!this.getExtQuickStart().getQuickStartParam().isLaunchZapStartPage()) {
            // Dont request the online version if the user has opted out
            return;
        }

        new Thread("ZAP-LaunchPageFetcher") {
            @Override
            public void run() {
                // Try to read the default launch page
                HttpMessage msg;
                String launchPageUrl = getLaunchPageURL();
                try {
                    HttpSender httpSender =
                            new HttpSender(
                                    Model.getSingleton().getOptionsParam().getConnectionParam(),
                                    true,
                                    HttpSender.CHECK_FOR_UPDATES_INITIATOR);
                    httpSender.setFollowRedirect(true);
                    msg =
                            new HttpMessage(
                                    new URI(launchPageUrl, true),
                                    Model.getSingleton().getOptionsParam().getConnectionParam());
                    httpSender.sendAndReceive(msg, true);
                    if (msg.getResponseHeader().getStatusCode() == HttpStatusCode.OK) {
                        /*
                         * This is split into different locales, so split up
                         */
                        String combinedDefaultContent = msg.getResponseBody().toString();
                        String zapLocale = Constant.getLocale().toString();
                        String[] localeContents =
                                combinedDefaultContent.split(PAGE_LOCALE_SEPARATOR);
                        for (String locContent : localeContents) {
                            // First line should be a comment including the
                            // locale name
                            if (locContent.startsWith(PAGE_LOCALE_PREFIX)) {
                                String locale =
                                        locContent.substring(
                                                PAGE_LOCALE_PREFIX.length(),
                                                locContent.indexOf(PAGE_LOCALE_POSTFIX));
                                if (PAGE_LOCALE_DEFAULT.equals(locale)) {
                                    // The default one should be first
                                    defaultLaunchContent = locContent;
                                } else if (zapLocale.equals(locale)) {
                                    // Found the right one for this locale
                                    defaultLaunchContent = locContent;
                                    break;
                                }
                            } else {
                                LOGGER.debug("No locale comment?? " + locContent);
                            }
                        }
                    } else {
                        LOGGER.debug(
                                "Response from "
                                        + launchPageUrl
                                        + " : "
                                        + msg.getResponseHeader().getStatusCode());
                    }
                } catch (Exception e) {
                    LOGGER.debug(
                            "Failed to read from " + launchPageUrl + " : " + e.getMessage(), e);
                }
            }
        }.start();
    }

    private String getLaunchPageURL() {
        String page = DEV_LAUNCH_PAGE;
        if (!Constant.isDevBuild() && !Constant.isDailyBuild()) {
            // Converts the ZAP version to something like 2-8
            try {
                Version zapVersion = new Version(Constant.PROGRAM_VERSION);
                page = zapVersion.getMajorVersion() + "-" + zapVersion.getMinorVersion();
            } catch (IllegalArgumentException e) {
                LOGGER.error("Failed to parse ZAP version " + Constant.PROGRAM_VERSION, e);
            }
        }

        return DEFAULT_LAUNCH_PAGE_URL_PREFIX + page;
    }

    private OptionsQuickStartLaunchPanel getOptionsPanel() {
        if (optionsPanel == null) {
            optionsPanel = new OptionsQuickStartLaunchPanel();
        }
        return optionsPanel;
    }

    private JButton getLaunchToolbarButton() {
        if (launchToolbarButton == null) {
            launchToolbarButton = new JButton();
            launchToolbarButton.setToolTipText(
                    Constant.messages.getString("quickstart.toolbar.button.tooltip.launch"));
            launchToolbarButton.addActionListener(
                    new ActionListener() {

                        @Override
                        public void actionPerformed(ActionEvent e) {
                            launchBrowser(
                                    launchPanel.getSelectedBrowser(), launchPanel.getUrlValue());
                        }
                    });
        }
        return launchToolbarButton;
    }

    protected void setToolbarButtonIcon(String browser) {
        if ("firefox".equalsIgnoreCase(browser)) {
            launchToolbarButton.setIcon(FIREFOX_ICON);
        } else if ("chrome".equalsIgnoreCase(browser)) {
            launchToolbarButton.setIcon(CHROME_ICON);
        } else if ("safari".equalsIgnoreCase(browser)) {
            launchToolbarButton.setIcon(SAFARI_ICON);
        } else {
            launchToolbarButton.setIcon(CHROMIUM_ICON);
        }
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public String getAuthor() {
        return Constant.ZAP_TEAM;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("quickstart.launch.desc");
    }

    @Override
    public URL getURL() {
        try {
            return new URL(Constant.ZAP_HOMEPAGE);
        } catch (MalformedURLException e) {
            return null;
        }
    }

    private ExtensionQuickStart getExtQuickStart() {
        return Control.getSingleton().getExtensionLoader().getExtension(ExtensionQuickStart.class);
    }

    public ExtensionSelenium getExtSelenium() {
        return Control.getSingleton().getExtensionLoader().getExtension(ExtensionSelenium.class);
    }

    protected void launchBrowser(String browserName, String url) {
        new Thread(
                        new Runnable() {
                            @Override
                            public void run() {
                                try {
                                    WebDriver wd =
                                            getExtSelenium().getProxiedBrowserByName(browserName);
                                    if (wd != null) {
                                        QuickStartParam params =
                                                getExtQuickStart().getQuickStartParam();
                                        if (url != null
                                                && url.length() > 0
                                                && !url.equals(DEFAULT_VALUE_URL_FIELD)) {
                                            wd.get(url);
                                        } else if (params.isLaunchZapStartPage()) {
                                            wd.get(
                                                    API.getInstance()
                                                            .getBaseURL(
                                                                    API.Format.OTHER,
                                                                    QuickStartLaunchAPI.API_PREFIX,
                                                                    API.RequestType.other,
                                                                    QuickStartLaunchAPI
                                                                            .OTHER_START_PAGE,
                                                                    true));
                                        } else if (!params.isLaunchBlankStartPage()) {
                                            wd.get(params.getLaunchStartPage());
                                        }
                                        // Use the same browser next time, as long
                                        // as it worked
                                        params.setLaunchDefaultBrowser(browserName);
                                        params.getConfig().save();
                                    }
                                } catch (Exception e1) {
                                    LOGGER.error(e1.getMessage(), e1);
                                }
                            }
                        },
                        "ZAP-BrowserLauncher")
                .start();
    }

    public String getDefaultLaunchContent() {
        return defaultLaunchContent;
    }

    @Override
    public void addOnInstalled(AddOn addOn) {
        // Not currently supported
    }

    @Override
    public void addOnSoftUninstalled(AddOn addOn, boolean successfully) {}

    @Override
    public void addOnUninstalled(AddOn addOn, boolean successfully) {
        if (getView() != null) {
            if (addOn.getId().equals("hud")) {
                this.launchPanel.hudAddOnUninstalled();
            }
        }
    }
}
