/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.zap.extension.quickstart;

import java.awt.Cursor;
import java.awt.Font;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.font.TextAttribute;
import java.util.HashMap;
import java.util.Map;
import javax.swing.ImageIcon;
import javax.swing.JLabel;
import javax.swing.JPanel;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.utils.DesktopUtils;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.Stats;
import org.zaproxy.zap.view.LayoutHelper;

public class SupportPanel extends QuickStartSubPanel {
    private static final long serialVersionUID = 1L;

    private static final String ZAP_SUPPORT_LINK = "https://www.zaproxy.org/support/";
    private static final String ZAP_SUPPORT_PACKAGES_LINK = ZAP_SUPPORT_LINK + "#support-packages";
    private static final String ZAP_SUPPORT_SPONSORED_LINK =
            ZAP_SUPPORT_LINK + "#sponsored-developments";
    private static final String ZAP_SUPPORT_CONSULTANCY_LINK = ZAP_SUPPORT_LINK + "#consultancy";
    private static final String USER_GROUP_LINK = "https://groups.google.com/group/zaproxy-users";

    private ImageIcon icon;
    private JPanel contentPanel;
    private JLabel lowerPadding;
    private int paddingY;

    public SupportPanel(ExtensionQuickStart extension, QuickStartPanel qsp) {
        super(extension, qsp);
    }

    @Override
    public String getTitleKey() {
        return "quickstart.support.panel.title";
    }

    @Override
    public JPanel getDescriptionPanel() {
        JPanel panel = new QuickStartBackgroundPanel();
        panel.add(
                QuickStartHelper.getWrappedLabel("quickstart.support.panel.message1"),
                LayoutHelper.getGBC(0, 0, 2, 1.0D, DisplayUtils.getScaledInsets(5, 5, 5, 5)));
        panel.add(
                new JLabel(" "),
                LayoutHelper.getGBC(
                        0, 2, 2, 1.0D, DisplayUtils.getScaledInsets(5, 5, 5, 5))); // Spacer
        return panel;
    }

    private JLabel ulJLabel(String text) {
        JLabel label = new JLabel(text);
        Font font = label.getFont();
        Map<TextAttribute, Object> attributes = new HashMap<>(font.getAttributes());
        attributes.put(TextAttribute.UNDERLINE, TextAttribute.UNDERLINE_ON);
        label.setFont(font.deriveFont(attributes));
        return label;
    }

    @Override
    public JPanel getContentPanel() {
        if (contentPanel == null) {
            contentPanel = new QuickStartBackgroundPanel();
            int formPanelY = 0;

            contentPanel.add(
                    new JLabel(Constant.messages.getString("quickstart.support.commercial")),
                    LayoutHelper.getGBC(
                            0, ++formPanelY, 1, 0.0D, DisplayUtils.getScaledInsets(5, 5, 5, 5)));
            contentPanel.add(
                    new JLabel(""),
                    LayoutHelper.getGBC(
                            2,
                            formPanelY,
                            1,
                            1.0D,
                            DisplayUtils.getScaledInsets(5, 5, 5, 5))); // Spacer

            contentPanel.add(
                    getOnlineLink("quickstart.support.packages", ZAP_SUPPORT_PACKAGES_LINK),
                    LayoutHelper.getGBC(
                            1, ++formPanelY, 1, 0.0D, DisplayUtils.getScaledInsets(5, 5, 5, 5)));

            contentPanel.add(
                    getOnlineLink("quickstart.support.sponsored", ZAP_SUPPORT_SPONSORED_LINK),
                    LayoutHelper.getGBC(
                            1, ++formPanelY, 1, 0.0D, DisplayUtils.getScaledInsets(5, 5, 5, 5)));

            contentPanel.add(
                    getOnlineLink("quickstart.support.consultancy", ZAP_SUPPORT_CONSULTANCY_LINK),
                    LayoutHelper.getGBC(
                            1, ++formPanelY, 1, 0.0D, DisplayUtils.getScaledInsets(5, 5, 5, 5)));

            contentPanel.add(
                    new JLabel(Constant.messages.getString("quickstart.support.community")),
                    LayoutHelper.getGBC(
                            0, ++formPanelY, 1, 0.0D, DisplayUtils.getScaledInsets(5, 5, 5, 5)));
            contentPanel.add(
                    new JLabel(""),
                    LayoutHelper.getGBC(
                            2,
                            formPanelY,
                            1,
                            1.0D,
                            DisplayUtils.getScaledInsets(5, 5, 5, 5))); // Spacer

            contentPanel.add(
                    getOnlineLink("quickstart.link.usergroup", USER_GROUP_LINK),
                    LayoutHelper.getGBC(
                            1, ++formPanelY, 1, 0.0D, DisplayUtils.getScaledInsets(5, 5, 5, 5)));

            paddingY = ++formPanelY;
            this.replacePadding();
        }

        return contentPanel;
    }

    private JLabel getOnlineLink(String key, String url) {
        JLabel label = ulJLabel(Constant.messages.getString(key));
        label.setIcon(
                DisplayUtils.getScaledIcon(
                        new ImageIcon(
                                getClass()
                                        .getResource(
                                                ExtensionQuickStart.RESOURCES
                                                        + "/document-globe.png"))));
        label.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        label.addMouseListener(
                new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e) {
                        Stats.incCounter("stats.ui.link.support");
                        DesktopUtils.openUrlInBrowser(url);
                    }
                });
        return label;
    }

    private void replacePadding() {
        if (contentPanel != null) {
            // this may or may not be present
            if (this.lowerPadding == null) {
                lowerPadding = new JLabel("");
            } else {
                contentPanel.remove(this.lowerPadding);
            }
            contentPanel.add(
                    lowerPadding,
                    LayoutHelper.getGBC(0, paddingY, 1, 0.0D, 1.0D)); // Padding at bottom
        }
    }

    @Override
    public ImageIcon getIcon() {
        if (icon == null) {
            icon =
                    DisplayUtils.getScaledIcon(
                            new ImageIcon(
                                    getClass()
                                            .getResource(
                                                    ExtensionQuickStart.RESOURCES
                                                            + "/zap-cs64x64.png")));
        }
        return icon;
    }

    @Override
    public JPanel getFooterPanel() {
        return null;
    }
}
