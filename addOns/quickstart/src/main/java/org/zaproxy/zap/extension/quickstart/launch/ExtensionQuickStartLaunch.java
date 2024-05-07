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

import java.util.List;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.WebDriver;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.OptionsChangedListener;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.AddOnInstallationStatusListener;
import org.zaproxy.zap.extension.AddOnInstallationStatusListener.StatusUpdate;
import org.zaproxy.zap.extension.api.API;
import org.zaproxy.zap.extension.quickstart.ExtensionQuickStart;
import org.zaproxy.zap.extension.quickstart.QuickStartParam;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.utils.DisplayUtils;

public class ExtensionQuickStartLaunch extends ExtensionAdaptor
        implements AddOnInstallationStatusListener, OptionsChangedListener {

    private static final String DEFAULT_VALUE_URL_FIELD = "http://";

    public static final String NAME = "ExtensionQuickStartLaunch";
    private static final Logger LOGGER = LogManager.getLogger(ExtensionQuickStartLaunch.class);

    public static final String RESOURCES = "/org/zaproxy/zap/extension/quickstart/resources";

    private OptionsQuickStartLaunchPanel optionsPanel;
    private LaunchPanel launchPanel;

    private JButton launchToolbarButton;

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(ExtensionQuickStart.class, ExtensionSelenium.class);

    private ImageIcon chromeIcon;
    private ImageIcon chromiumIcon;
    private ImageIcon firefoxIcon;
    private ImageIcon safariIcon;

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
        extensionHook.addApiImplementor(new QuickStartLaunchAPI(this));
        extensionHook.addAddOnInstallationStatusListener(this);
        extensionHook.addOptionsChangedListener(this);

        if (hasView()) {
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
        if (hasView()) {
            this.getExtQuickStart().setLaunchPanel(null);
            launchPanel.unload();
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
            setToolbarButtonIcon(
                    this.getExtQuickStart().getQuickStartParam().getLaunchDefaultBrowser());
            if (this.launchPanel != null) {
                this.launchPanel.optionsChanged();
            }
        }
    }

    @Override
    public void optionsChanged(OptionsParam optionsParam) {
        if (this.launchPanel != null) {
            this.launchPanel.optionsChanged();
        }
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
            launchToolbarButton.addActionListener(e -> launchPanel.launchBrowser());
        }
        return launchToolbarButton;
    }

    protected void setToolbarButtonIcon(String browser) {
        initBrowserIcons();

        if ("firefox".equalsIgnoreCase(browser)) {
            launchToolbarButton.setIcon(firefoxIcon);
        } else if ("chrome".equalsIgnoreCase(browser)) {
            launchToolbarButton.setIcon(chromeIcon);
        } else if ("safari".equalsIgnoreCase(browser)) {
            launchToolbarButton.setIcon(safariIcon);
        } else {
            launchToolbarButton.setIcon(chromiumIcon);
        }
    }

    private void initBrowserIcons() {
        chromeIcon =
                DisplayUtils.getScaledIcon(
                        new ImageIcon(getClass().getResource(RESOURCES + "/chrome.png")));

        chromiumIcon =
                DisplayUtils.getScaledIcon(
                        new ImageIcon(getClass().getResource(RESOURCES + "/chromium.png")));
        firefoxIcon =
                DisplayUtils.getScaledIcon(
                        new ImageIcon(getClass().getResource(RESOURCES + "/firefox.png")));
        safariIcon =
                DisplayUtils.getScaledIcon(
                        new ImageIcon(getClass().getResource(RESOURCES + "/safari.png")));
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("quickstart.launch.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("quickstart.launch.desc");
    }

    private ExtensionQuickStart getExtQuickStart() {
        return Control.getSingleton().getExtensionLoader().getExtension(ExtensionQuickStart.class);
    }

    public ExtensionSelenium getExtSelenium() {
        return Control.getSingleton().getExtensionLoader().getExtension(ExtensionSelenium.class);
    }

    protected void launchBrowser(String browserName, String url) {
        new Thread(
                        () -> {
                            try {
                                WebDriver wd =
                                        getExtSelenium().getProxiedBrowserByName(browserName);
                                if (wd != null) {
                                    QuickStartParam params =
                                            getExtQuickStart().getQuickStartParam();
                                    accessUrl(wd, params, url);
                                    // Use the same browser next time, as long
                                    // as it worked
                                    params.setLaunchDefaultBrowser(browserName);
                                    params.getConfig().save();
                                }
                            } catch (Exception e1) {
                                ExtensionSelenium extSel = getExtSelenium();
                                View.getSingleton()
                                        .showWarningDialog(
                                                extSel.getWarnMessageFailedToStart(
                                                        browserName, e1));
                                LOGGER.error(e1.getMessage(), e1);
                            }
                        },
                        "ZAP-BrowserLauncher")
                .start();
    }

    private static void accessUrl(WebDriver wd, QuickStartParam params, String userUrl) {
        String url = null;
        if (userUrl != null && userUrl.length() > 0 && !userUrl.equals(DEFAULT_VALUE_URL_FIELD)) {
            url = userUrl;
        } else if (params.isLaunchZapStartPage()) {
            url =
                    API.getInstance()
                            .getBaseURL(
                                    API.Format.OTHER,
                                    QuickStartLaunchAPI.API_PREFIX,
                                    API.RequestType.other,
                                    QuickStartLaunchAPI.OTHER_START_PAGE,
                                    true);
        } else if (!params.isLaunchBlankStartPage()) {
            url = params.getLaunchStartPage();
        }

        if (url != null) {
            try {
                wd.get(url);
            } catch (Exception e) {
                View.getSingleton()
                        .showWarningDialog(
                                Constant.messages.getString(
                                        "quickstart.launch.start.url.access.error", url));
                LOGGER.warn("Failed to access the URL {}, cause: {}", url, e.getMessage());
            }
        }
    }

    public String getDefaultLaunchContent() {
        // This is no longer read from a link
        return Constant.messages.getString("quickstart.launch.html");
    }

    @Override
    public void update(StatusUpdate statusUpdate) {
        if (statusUpdate.getStatus() == StatusUpdate.Status.UNINSTALLED
                && hasView()
                && statusUpdate.getAddOn().getId().equals("hud")) {
            this.launchPanel.hudAddOnUninstalled();
        }
    }
}
