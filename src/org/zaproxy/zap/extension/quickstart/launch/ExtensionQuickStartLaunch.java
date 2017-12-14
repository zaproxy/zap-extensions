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
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.quickstart.launch;

import java.awt.Insets;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.swing.ComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;

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
import org.zaproxy.zap.extension.api.API;
import org.zaproxy.zap.extension.quickstart.ExtensionQuickStart;
import org.zaproxy.zap.extension.quickstart.QuickStartPanelContentProvider;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.extension.selenium.ProvidedBrowserUI;
import org.zaproxy.zap.extension.selenium.ProvidedBrowsersComboBoxModel;
import org.zaproxy.zap.view.LayoutHelper;

public class ExtensionQuickStartLaunch extends ExtensionAdaptor implements
        QuickStartPanelContentProvider {

    public static final String NAME = "ExtensionQuickStartLaunch";
    private static final String DEFAULT_LAUNCH_PAGE_URL = "https://bit.ly/owaspzap-start-2-7";
    private static final String PAGE_LOCALE_SEPARATOR = "<!-- - - - - - - - - %< - - - - - - - - -->\n";
    private static final String PAGE_LOCALE_PREFIX = "<!-- Locale = ";
    private static final String PAGE_LOCALE_POSTFIX = " -->";
    private static final String PAGE_LOCALE_DEFAULT = "Default";
    private static final Logger LOGGER = Logger
            .getLogger(ExtensionQuickStartLaunch.class);

    private String defaultLaunchContent;

    private QuickStartLaunchAPI api;
    private OptionsQuickStartLaunchPanel optionsPanel;
    private QuickStartLaunchParam alertParam;

    private JButton launchButton;
    private JComboBox<ProvidedBrowserUI> browserComboBox;
    private JLabel exploreLabel;
    private JLabel spacerLabel;

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
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        this.api = new QuickStartLaunchAPI(this);
        extensionHook.addApiImplementor(api);
        extensionHook.addOptionsParamSet(getQuickStartLaunchParam());

        if (getView() != null) {
            extensionHook.getHookView().addOptionPanel(getOptionsPanel());
            this.getExtQuickStart().addContentProvider(this);
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        if (getView() != null) {
            this.getExtQuickStart().removeContentProvider(this);
        }
    }

    @Override
    public void postInit() {
        if (getView() != null) {
            // Plugable browsers (like JxBrowser) can be added after this add-ons 
            // options have been loaded
            String def = this.getQuickStartLaunchParam().getDefaultBrowser();
            if (def == null || def.length() == 0) {
                // no default
                return;
            }
            ComboBoxModel<ProvidedBrowserUI> model = this.getBrowserComboBox().getModel();
            for (int idx = 0; idx < model.getSize(); idx++) {
                ProvidedBrowserUI el = model.getElementAt(idx);
                if (el.getName().equals(def)) {
                    model.setSelectedItem(el);
                    break;
                }
            }
        }
    }

    @Override
    public void optionsLoaded() {
        super.optionsLoaded();
        if (View.isInitialised()) {
            // Always init in case the user changes to use the default home page
            // later
            defaultLaunchContent = Constant.messages
                    .getString("quickstart.launch.html");
        }

        if (!getQuickStartLaunchParam().isZapStartPage()) {
            // Dont request the online version if the user has opted out
            return;
        }
        
            
        new Thread("ZAP-LaunchPageFetcher") {
            @Override
            public void run() {
                // Try to read the default launch page
                HttpMessage msg;
                try {
                    HttpSender httpSender = new HttpSender(Model.getSingleton()
                            .getOptionsParam().getConnectionParam(), true,
                            HttpSender.CHECK_FOR_UPDATES_INITIATOR);
                    httpSender.setFollowRedirect(true);
                    msg = new HttpMessage(
                            new URI(DEFAULT_LAUNCH_PAGE_URL, true), Model
                                    .getSingleton().getOptionsParam()
                                    .getConnectionParam());
                    httpSender.sendAndReceive(msg, true);
                    if (msg.getResponseHeader().getStatusCode() == HttpStatusCode.OK) {
                        /*
                         * This is split into different locales, so split up
                         */
                        String combinedDefaultContent = msg.getResponseBody()
                                .toString();
                        String zapLocale = Constant.getLocale().toString();
                        String[] localeContents = combinedDefaultContent
                                .split(PAGE_LOCALE_SEPARATOR);
                        for (String locContent : localeContents) {
                            // First line should be a comment including the
                            // locale name
                            if (locContent.startsWith(PAGE_LOCALE_PREFIX)) {
                                String locale = locContent.substring(
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
                                LOGGER.debug("No locale comment?? "
                                        + locContent);

                            }
                        }
                    } else {
                        LOGGER.debug("Response from " + DEFAULT_LAUNCH_PAGE_URL
                                + " : "
                                + msg.getResponseHeader().getStatusCode());
                    }
                } catch (Exception e) {
                    LOGGER.debug("Failed to read from "
                            + DEFAULT_LAUNCH_PAGE_URL + " : " + e.getMessage(),
                            e);
                }

            }
        }.start();
    }

    private OptionsQuickStartLaunchPanel getOptionsPanel() {
        if (optionsPanel == null) {
            optionsPanel = new OptionsQuickStartLaunchPanel();
        }
        return optionsPanel;
    }

    private QuickStartLaunchParam getQuickStartLaunchParam() {
        if (alertParam == null) {
            alertParam = new QuickStartLaunchParam();
        }
        return alertParam;
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
        return Control.getSingleton().getExtensionLoader()
                .getExtension(ExtensionQuickStart.class);
    }

    private ExtensionSelenium getExtSelenium() {
        return Control.getSingleton().getExtensionLoader()
                .getExtension(ExtensionSelenium.class);
    }

    private JButton getLaunchButton() {
        if (launchButton == null) {
            launchButton = new JButton();
            launchButton.setText(Constant.messages
                    .getString("quickstart.button.label.launch"));
            launchButton.setToolTipText(Constant.messages
                    .getString("quickstart.button.tooltip.launch"));

            launchButton.addActionListener(new java.awt.event.ActionListener() {
                @Override
                public void actionPerformed(java.awt.event.ActionEvent e) {
                    new Thread(new Runnable() {
                        @Override
                        public void run() {
                            try {
                                WebDriver wd = getExtSelenium()
                                        .getProxiedBrowserByName(
                                                getBrowserComboBox()
                                                        .getSelectedItem()
                                                        .toString());
                                if (wd != null) {
                                    if (getQuickStartLaunchParam()
                                            .isZapStartPage()) {
                                        wd.get(API.getInstance().getBaseURL(
                                                        API.Format.OTHER,
                                                        QuickStartLaunchAPI.API_PREFIX,
                                                        API.RequestType.other,
                                                        QuickStartLaunchAPI.OTHER_START_PAGE,
                                                        true));
                                    } else if (!getQuickStartLaunchParam()
                                            .isBlankStartPage()) {
                                        wd.get(getQuickStartLaunchParam()
                                                .getStartPage());
                                    }
                                    // Use the same browser next time, as long
                                    // as it worked
                                    getQuickStartLaunchParam()
                                            .setDefaultBrowser(
                                                    getBrowserComboBox()
                                                            .getSelectedItem()
                                                            .toString());
                                    getQuickStartLaunchParam().getConfig().save();
                                }
                            } catch (Exception e1) {
                                LOGGER.error(e1.getMessage(), e1);
                            }
                        }
                    }, "ZAP-BrowserLauncher").start();
                }
            });
        }
        return launchButton;
    }

    private JComboBox<ProvidedBrowserUI> getBrowserComboBox() {
        if (browserComboBox == null) {
            browserComboBox = new JComboBox<ProvidedBrowserUI>();
            ProvidedBrowsersComboBoxModel model = getExtSelenium().createProvidedBrowsersComboBoxModel();
            model.setIncludeHeadless(false);
            model.setIncludeUnconfigured(false);
            browserComboBox.setModel(model);
        }
        return browserComboBox;
    }

    private JLabel getExploreLabel() {
        if (exploreLabel == null) {
            exploreLabel = new JLabel(
                    Constant.messages.getString("quickstart.label.explore"));
        }
        return exploreLabel;
    }

    private JLabel getSpacerLabel() {
        if (spacerLabel == null) {
            spacerLabel = new JLabel(" ");
        }
        return spacerLabel;
    }

    @Override
    public int addToPanel(JPanel panel, int offset) {
        panel.add(getExploreLabel(), LayoutHelper.getGBC(0, ++offset, 1, 0.0D,
                new Insets(5, 5, 5, 5)));
        panel.add(getLaunchButton(), LayoutHelper.getGBC(1, offset, 1, 0.0D));
        panel.add(getBrowserComboBox(), LayoutHelper.getGBC(2, offset, 1, 0.0D));
        panel.add(getSpacerLabel(), LayoutHelper.getGBC(0, ++offset, 1, 0.0D));
        return offset;
    }

    @Override
    public void removeFromPanel(JPanel panel) {
        panel.remove(getExploreLabel());
        panel.remove(getLaunchButton());
        panel.remove(getBrowserComboBox());
        panel.remove(getSpacerLabel());
    }

    public String getDefaultLaunchContent() {
        return defaultLaunchContent;
    }

}
