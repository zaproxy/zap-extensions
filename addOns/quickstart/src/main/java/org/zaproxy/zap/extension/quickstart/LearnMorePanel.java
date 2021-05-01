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
package org.zaproxy.zap.extension.quickstart;

import java.awt.Cursor;
import java.awt.Desktop;
import java.awt.Font;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.font.TextAttribute;
import java.io.File;
import java.util.HashMap;
import java.util.Map;
import javax.swing.ImageIcon;
import javax.swing.JLabel;
import javax.swing.JPanel;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.help.ExtensionHelp;
import org.zaproxy.zap.utils.DesktopUtils;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.LayoutHelper;

public class LearnMorePanel extends QuickStartSubPanel {
    private static final long serialVersionUID = 1L;

    private static final String WEBSITE_LINK = "https://www.zaproxy.org/";
    private static final String FAQ_LINK = "https://www.zaproxy.org/faq/";
    private static final String GETTING_STARTED_LINK = "https://www.zaproxy.org/getting-started/";
    private static final String USER_GROUP_LINK = "https://groups.google.com/group/zaproxy-users";
    private static final String USER_GUIDE_LINK = "https://www.zaproxy.org/docs/desktop/";
    private static final String ZAP_IN_TEN_LINK = "https://www.alldaydevops.com/zap-in-ten";

    private JPanel contentPanel;
    private JLabel lowerPadding;
    private int paddingY;

    public LearnMorePanel(ExtensionQuickStart extension, QuickStartPanel qsp) {
        super(extension, qsp);
    }

    @Override
    public String getTitleKey() {
        return "quickstart.learn.panel.title";
    }

    @Override
    public JPanel getDescriptionPanel() {
        JPanel panel = new QuickStartBackgroundPanel();
        panel.add(
                QuickStartHelper.getWrappedLabel("quickstart.learn.panel.message1"),
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

            ExtensionHelp extHelp =
                    Control.getSingleton().getExtensionLoader().getExtension(ExtensionHelp.class);
            boolean isHelpAvailable = extHelp != null && extHelp.isHelpAvailable();
            boolean isGuideAvailable = Constant.messages.containsKey("gettingStarted.file");
            File guide = null;
            if (isGuideAvailable) {
                guide =
                        new File(
                                Constant.getZapHome()
                                        + File.separator
                                        + "lang"
                                        + File.separator
                                        + Constant.messages.getString("gettingStarted.file"));
                if (!guide.canRead()) {
                    isGuideAvailable = false;
                }
            }
            // Keep the compiler happy
            final File finalGuide = guide;

            if (isHelpAvailable || isGuideAvailable) {

                contentPanel.add(
                        new JLabel(Constant.messages.getString("quickstart.links.local")),
                        LayoutHelper.getGBC(
                                0, formPanelY, 1, 0.0D, DisplayUtils.getScaledInsets(5, 5, 5, 5)));
                contentPanel.add(
                        new JLabel(""),
                        LayoutHelper.getGBC(
                                2,
                                formPanelY,
                                1,
                                1.0D,
                                DisplayUtils.getScaledInsets(5, 5, 5, 5))); // Spacer

                if (isGuideAvailable) {
                    JLabel qsLabel =
                            ulJLabel(Constant.messages.getString("quickstart.link.startguide"));
                    qsLabel.setIcon(ExtensionQuickStart.PDF_DOC_ICON);
                    qsLabel.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
                    qsLabel.addMouseListener(
                            new MouseAdapter() {
                                @Override
                                public void mouseClicked(MouseEvent e) {
                                    try {
                                        Desktop.getDesktop().open(finalGuide);
                                    } catch (Exception ex) {
                                        View.getSingleton()
                                                .showWarningDialog(
                                                        LearnMorePanel.this,
                                                        Constant.messages.getString(
                                                                "quickstart.link.warning.nostartguide",
                                                                ex.getMessage()));
                                    }
                                }
                            });
                    contentPanel.add(
                            qsLabel,
                            LayoutHelper.getGBC(
                                    1,
                                    ++formPanelY,
                                    1,
                                    0.0D,
                                    DisplayUtils.getScaledInsets(5, 5, 5, 5)));
                }

                if (isHelpAvailable) {
                    JLabel helpLabel =
                            ulJLabel(Constant.messages.getString("quickstart.link.userguide"));
                    helpLabel.setIcon(ExtensionHelp.getHelpIcon());
                    helpLabel.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
                    helpLabel.addMouseListener(
                            new MouseAdapter() {
                                @Override
                                public void mouseClicked(MouseEvent e) {
                                    ExtensionHelp.showHelp();
                                }
                            });
                    contentPanel.add(
                            helpLabel,
                            LayoutHelper.getGBC(
                                    1,
                                    ++formPanelY,
                                    1,
                                    0.0D,
                                    DisplayUtils.getScaledInsets(5, 5, 5, 5)));
                }
            }

            contentPanel.add(
                    new JLabel(Constant.messages.getString("quickstart.links.online")),
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
                    getOnlineLink("quickstart.link.website", WEBSITE_LINK),
                    LayoutHelper.getGBC(
                            1, ++formPanelY, 1, 0.0D, DisplayUtils.getScaledInsets(5, 5, 5, 5)));

            contentPanel.add(
                    getOnlineLink("quickstart.link.zapinten", ZAP_IN_TEN_LINK),
                    LayoutHelper.getGBC(
                            1, ++formPanelY, 1, 0.0D, DisplayUtils.getScaledInsets(5, 5, 5, 5)));

            if (!isGuideAvailable) {
                // Link to the online version instead
                contentPanel.add(
                        getOnlineLink("quickstart.link.startguide", GETTING_STARTED_LINK),
                        LayoutHelper.getGBC(
                                1,
                                ++formPanelY,
                                1,
                                0.0D,
                                DisplayUtils.getScaledInsets(5, 5, 5, 5)));
                // TODO move link if/when we detect the add-on is installed
            }
            if (!isHelpAvailable) {
                // Link to the online version instead
                contentPanel.add(
                        getOnlineLink("quickstart.link.userguide", USER_GUIDE_LINK),
                        LayoutHelper.getGBC(
                                1,
                                ++formPanelY,
                                1,
                                0.0D,
                                DisplayUtils.getScaledInsets(5, 5, 5, 5)));
                // TODO move link if/when we detect the add-on is installed
            }
            contentPanel.add(
                    getOnlineLink("quickstart.link.usergroup", USER_GROUP_LINK),
                    LayoutHelper.getGBC(
                            1, ++formPanelY, 1, 0.0D, DisplayUtils.getScaledInsets(5, 5, 5, 5)));
            contentPanel.add(
                    getOnlineLink("quickstart.link.faq", FAQ_LINK),
                    LayoutHelper.getGBC(
                            1, ++formPanelY, 1, 0.0D, DisplayUtils.getScaledInsets(5, 5, 5, 5)));

            paddingY = ++formPanelY;
            this.replacePadding();
        }

        return contentPanel;
    }

    private JLabel getOnlineLink(String key, String url) {
        JLabel label = ulJLabel(Constant.messages.getString(key));
        label.setIcon(ExtensionQuickStart.ONLINE_DOC_ICON);
        label.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        label.addMouseListener(
                new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e) {
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
        return ExtensionQuickStart.HELP_ICON;
    }

    @Override
    public JPanel getFooterPanel() {
        return null;
    }
}
