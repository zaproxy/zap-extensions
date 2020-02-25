/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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

import java.awt.Color;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;
import javax.swing.ComboBoxModel;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import org.apache.commons.httpclient.URI;
import org.jdesktop.swingx.JXPanel;
import org.jdesktop.swingx.ScrollableSizeHint;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.eventBus.EventConsumer;
import org.zaproxy.zap.extension.quickstart.ExtensionQuickStart;
import org.zaproxy.zap.extension.quickstart.PlugableHud;
import org.zaproxy.zap.extension.quickstart.QuickStartHelper;
import org.zaproxy.zap.extension.quickstart.QuickStartPanel;
import org.zaproxy.zap.extension.quickstart.QuickStartSubPanel;
import org.zaproxy.zap.extension.selenium.Browser;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.extension.selenium.ProvidedBrowserUI;
import org.zaproxy.zap.extension.selenium.ProvidedBrowsersComboBoxModel;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.LayoutHelper;
import org.zaproxy.zap.view.NodeSelectDialog;

public class LaunchPanel extends QuickStartSubPanel implements EventConsumer {

    private static final long serialVersionUID = 1L;
    private static final String DEFAULT_BROWSER_ID = Browser.FIREFOX.getId();

    private static final String EVENT_HUD_ENABLED_FOR_DESKTOP = "desktop.enabled";
    private static final String EVENT_HUD_DISABLED_FOR_DESKTOP = "desktop.disabled";

    private ExtensionQuickStartLaunch extLaunch;
    private JXPanel contentPanel;
    private JButton selectButton;
    private JComboBox<String> urlField;
    private JButton launchButton;
    private JComboBox<ProvidedBrowserUI> browserComboBox;
    private ProvidedBrowsersComboBoxModel allBrowserModel;
    private ProvidedBrowsersComboBoxModel hudBrowserModel;
    private JCheckBox hudCheckbox;
    private JLabel hudIsInScopeOnly;
    private JLabel exploreLabel;
    private int hudOffset;

    public LaunchPanel(
            ExtensionQuickStartLaunch extLaunch,
            ExtensionQuickStart extension,
            QuickStartPanel qsp) {
        super(extension, qsp);
        this.extLaunch = extLaunch;
        ZAP.getEventBus()
                .registerConsumer(
                        this,
                        "org.zaproxy.zap.extension.hud.HudEventPublisher",
                        new String[] {
                            EVENT_HUD_ENABLED_FOR_DESKTOP, EVENT_HUD_DISABLED_FOR_DESKTOP
                        });
    }

    @Override
    public String getTitleKey() {
        return "quickstart.launch.panel.title";
    }

    @Override
    public JPanel getDescriptionPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBackground(Color.WHITE);
        panel.add(
                QuickStartHelper.getWrappedLabel("quickstart.launch.panel.message1"),
                LayoutHelper.getGBC(0, 0, 2, 1.0D, DisplayUtils.getScaledInsets(5, 5, 5, 5)));
        panel.add(
                QuickStartHelper.getWrappedLabel("quickstart.launch.panel.message2"),
                LayoutHelper.getGBC(0, 1, 2, 1.0D, DisplayUtils.getScaledInsets(5, 5, 5, 5)));
        panel.add(
                new JLabel(" "),
                LayoutHelper.getGBC(
                        0, 2, 2, 1.0D, DisplayUtils.getScaledInsets(5, 5, 5, 5))); // Spacer
        return panel;
    }

    private ExtensionQuickStart getExtQuickStart() {
        return Control.getSingleton().getExtensionLoader().getExtension(ExtensionQuickStart.class);
    }

    public ExtensionSelenium getExtSelenium() {
        return Control.getSingleton().getExtensionLoader().getExtension(ExtensionSelenium.class);
    }

    @Override
    public JPanel getContentPanel() {
        if (this.contentPanel == null) {
            contentPanel = new JXPanel(new GridBagLayout());
            contentPanel.setScrollableHeightHint(ScrollableSizeHint.PREFERRED_STRETCH);
            contentPanel.setBackground(Color.white);
            int offset = 0;
            contentPanel.add(
                    new JLabel(Constant.messages.getString("quickstart.label.exploreurl")),
                    LayoutHelper.getGBC(0, ++offset, 1, 0.0D, new Insets(5, 5, 5, 5)));

            JPanel urlSelectPanel = new JPanel(new GridBagLayout());
            selectButton = new JButton(Constant.messages.getString("all.button.select"));
            selectButton.setIcon(
                    DisplayUtils.getScaledIcon(
                            new ImageIcon(
                                    View.class.getResource("/resource/icon/16/094.png")))); // Globe
            // icon
            selectButton.addActionListener(
                    new java.awt.event.ActionListener() {
                        @Override
                        public void actionPerformed(java.awt.event.ActionEvent e) {
                            NodeSelectDialog nsd =
                                    new NodeSelectDialog(View.getSingleton().getMainFrame());
                            SiteNode node = null;
                            try {
                                node =
                                        Model.getSingleton()
                                                .getSession()
                                                .getSiteTree()
                                                .findNode(
                                                        new URI(
                                                                getUrlField()
                                                                        .getSelectedItem()
                                                                        .toString(),
                                                                false));
                            } catch (Exception e2) {
                                // Ignore
                            }
                            node = nsd.showDialog(node);
                            if (node != null && node.getHistoryReference() != null) {
                                try {
                                    getUrlField()
                                            .setSelectedItem(
                                                    node.getHistoryReference().getURI().toString());
                                } catch (Exception e1) {
                                    // Ignore
                                }
                            }
                        }
                    });

            urlSelectPanel.add(this.getUrlField(), LayoutHelper.getGBC(0, 0, 1, 0.5D));
            urlSelectPanel.add(selectButton, LayoutHelper.getGBC(1, 0, 1, 0.0D));
            contentPanel.add(urlSelectPanel, LayoutHelper.getGBC(1, offset, 3, 0.25D));

            contentPanel.add(
                    new JLabel(Constant.messages.getString("quickstart.label.hud")),
                    LayoutHelper.getGBC(0, ++offset, 1, 0.0D, new Insets(5, 5, 5, 5)));
            hudOffset = offset;

            contentPanel.add(
                    getExploreLabel(),
                    LayoutHelper.getGBC(0, ++offset, 1, 0.0D, new Insets(5, 5, 5, 5)));
            contentPanel.add(getLaunchButton(), LayoutHelper.getGBC(1, offset, 1, 0.0D));
            contentPanel.add(getBrowserComboBox(), LayoutHelper.getGBC(2, offset, 1, 0.0D));
        }
        return this.contentPanel;
    }

    private JCheckBox getHudCheckbox() {
        if (hudCheckbox == null) {
            hudCheckbox = new JCheckBox();
            PlugableHud hud = getExtQuickStart().getHudProvider();
            if (hud == null) {
                hudCheckbox.setEnabled(false);
            } else {
                hudCheckbox.setSelected(hud.isHudEnabled());
                hudCheckbox.addActionListener(
                        new ActionListener() {

                            @Override
                            public void actionPerformed(ActionEvent ev) {
                                hud.setHudEnabledForDesktop(hudCheckbox.isSelected());
                                setBrowserOptions(hudCheckbox.isSelected());
                            }
                        });
            }
        }
        return hudCheckbox;
    }

    private JLabel getHudIsInScopeOnly() {
        if (hudIsInScopeOnly == null) {
            hudIsInScopeOnly = new JLabel();
            setHudIsInScopeOnlyText();
        }
        return hudIsInScopeOnly;
    }

    private void setHudIsInScopeOnlyText() {
        if (hudIsInScopeOnly != null) {
            PlugableHud hud = getExtQuickStart().getHudProvider();
            if (hud != null) {
                if (hud.isInScopeOnly()) {
                    hudIsInScopeOnly.setText(
                            Constant.messages.getString("quickstart.label.hud.warn.scope"));
                } else {
                    hudIsInScopeOnly.setText("");
                }
            }
        }
    }

    protected void hudAddOnUninstalled() {
        getHudCheckbox().setSelected(false);
        getHudCheckbox().setEnabled(false);
        getHudIsInScopeOnly().setText("");
    }

    private JButton getLaunchButton() {
        if (launchButton == null) {
            launchButton = new JButton();
            launchButton.setText(Constant.messages.getString("quickstart.button.label.launch"));
            launchButton.setToolTipText(
                    Constant.messages.getString("quickstart.button.tooltip.launch"));

            launchButton.addActionListener(
                    new java.awt.event.ActionListener() {
                        @Override
                        public void actionPerformed(java.awt.event.ActionEvent e) {
                            getExtQuickStart().getQuickStartParam().addRecentUrl(getUrlValue());
                            extLaunch.launchBrowser(getSelectedBrowser(), getUrlValue());
                        }
                    });
        }
        return launchButton;
    }

    public void postInit() {
        // Plugable browsers (like JxBrowser) can be added after this add-ons
        // options have been loaded
        String def = this.getExtQuickStart().getQuickStartParam().getLaunchDefaultBrowser();
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

        JPanel hudPanel = new JPanel(new GridBagLayout());
        hudPanel.setBackground(Color.WHITE);
        hudPanel.add(getHudCheckbox(), LayoutHelper.getGBC(0, 0, 1, 0));
        hudPanel.add(getHudIsInScopeOnly(), LayoutHelper.getGBC(1, 0, 1, 0));
        hudPanel.add(new JLabel(), LayoutHelper.getGBC(1, 0, 2, 1.0));

        this.getContentPanel().add(hudPanel, LayoutHelper.getGBC(1, hudOffset, 3, 0.25D));

        PlugableHud hud = getExtQuickStart().getHudProvider();
        if (hud != null) {
            // Build up a model just with the browsers supported by the HUD
            List<ProvidedBrowserUI> hudBrowsers = new ArrayList<ProvidedBrowserUI>();
            List<String> browserIds = hud.getSupportedBrowserIds();
            for (int i = 0; i < allBrowserModel.getSize(); i++) {
                ProvidedBrowserUI browser = allBrowserModel.getElementAt(i);
                if (browserIds.contains(browser.getBrowser().getProviderId())) {
                    hudBrowsers.add(browser);
                }
            }
            hudBrowserModel = new ProvidedBrowsersComboBoxModel(hudBrowsers);
            setBrowserOptions(this.getHudCheckbox().isSelected());
        }
    }

    protected String getSelectedBrowser() {
        return getBrowserComboBox().getSelectedItem().toString();
    }

    protected String getUrlValue() {
        Object item = getUrlField().getSelectedItem();
        if (item != null) {
            return item.toString();
        }
        return null;
    }

    private JComboBox<String> getUrlField() {
        if (urlField == null) {
            urlField = new JComboBox<String>();
            urlField.setEditable(true);
            urlField.setModel(this.getExtensionQuickStart().getUrlModel());
        }
        return urlField;
    }

    private JComboBox<ProvidedBrowserUI> getBrowserComboBox() {
        if (browserComboBox == null) {
            browserComboBox = new JComboBox<ProvidedBrowserUI>();
            allBrowserModel = getExtSelenium().createProvidedBrowsersComboBoxModel();
            allBrowserModel.setIncludeHeadless(false);
            allBrowserModel.setIncludeUnconfigured(false);
            browserComboBox.setModel(allBrowserModel);
            browserComboBox.addActionListener(
                    new ActionListener() {

                        @Override
                        public void actionPerformed(ActionEvent ae) {
                            extLaunch.setToolbarButtonIcon(
                                    browserComboBox.getSelectedItem().toString());
                        }
                    });
        }
        return browserComboBox;
    }

    private void setBrowserOptions(boolean hudEnabled) {
        if (hudBrowserModel != null) {
            Object selected = browserComboBox.getModel().getSelectedItem();
            if (hudEnabled) {
                browserComboBox.setModel(hudBrowserModel);
                if (getExtQuickStart()
                        .getHudProvider()
                        .getSupportedBrowserIds()
                        .contains(selected)) {
                    browserComboBox.getModel().setSelectedItem(selected);
                } else {
                    hudBrowserModel.setSelectedBrowser(DEFAULT_BROWSER_ID);
                }
            } else {
                browserComboBox.setModel(allBrowserModel);
                // New model will be a superset
                browserComboBox.getModel().setSelectedItem(selected);
            }
        }
    }

    private JLabel getExploreLabel() {
        if (exploreLabel == null) {
            exploreLabel = new JLabel(Constant.messages.getString("quickstart.label.explore"));
        }
        return exploreLabel;
    }

    @Override
    public void eventReceived(Event event) {
        if (event.getEventType().equals(EVENT_HUD_ENABLED_FOR_DESKTOP)) {
            getHudCheckbox().setSelected(true);
        } else if (event.getEventType().equals(EVENT_HUD_DISABLED_FOR_DESKTOP)) {
            getHudCheckbox().setSelected(false);
        }
    }

    @Override
    public ImageIcon getIcon() {
        return ExtensionQuickStart.HUD_ICON;
    }

    @Override
    public JPanel getFooterPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBackground(Color.WHITE);
        panel.add(
                new JLabel(Constant.messages.getString("quickstart.panel.launch.manual")),
                LayoutHelper.getGBC(0, 0, 5, 1.0D, new Insets(5, 5, 5, 5)));
        return panel;
    }

    public void optionsChanged() {
        this.setHudIsInScopeOnlyText();
    }
}
