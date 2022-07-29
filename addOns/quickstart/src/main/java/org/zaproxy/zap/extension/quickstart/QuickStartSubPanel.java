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

import java.awt.GridBagConstraints;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.border.EtchedBorder;
import org.jdesktop.swingx.ScrollableSizeHint;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.utils.FontUtils.Size;
import org.zaproxy.zap.view.LayoutHelper;

@SuppressWarnings("serial")
public abstract class QuickStartSubPanel extends QuickStartBackgroundPanel {

    private static final long serialVersionUID = 1L;

    private ExtensionQuickStart extension;
    private QuickStartPanel qsp;
    private JButton backButton = null;

    public QuickStartSubPanel(ExtensionQuickStart extension, QuickStartPanel qsp) {
        super();
        this.extension = extension;
        this.qsp = qsp;
        initialize();
    }

    private void initialize() {
        this.setScrollableHeightHint(ScrollableSizeHint.PREFERRED_STRETCH);
        this.setBorder(BorderFactory.createEtchedBorder(EtchedBorder.RAISED));

        JPanel topPanel = new QuickStartBackgroundPanel();
        topPanel.setLayout(new BoxLayout(topPanel, BoxLayout.X_AXIS));
        topPanel.add(getBackButton());
        JLabel topTitle = new JLabel(Constant.messages.getString(this.getTitleKey()));
        topTitle.setBackground(topPanel.getBackground());
        topTitle.setFont(FontUtils.getFont(Size.much_larger));
        topPanel.add(Box.createHorizontalGlue());
        topPanel.add(topTitle);
        topPanel.add(Box.createHorizontalGlue());

        int panelY = 0;
        topPanel.add(new JLabel(this.getIcon()));
        this.add(
                topPanel,
                LayoutHelper.getGBC(0, panelY, 2, 1.0D, DisplayUtils.getScaledInsets(5, 5, 5, 5)));

        this.add(
                this.getDescriptionPanel(),
                LayoutHelper.getGBC(
                        0, ++panelY, 2, 1.0D, DisplayUtils.getScaledInsets(5, 5, 5, 5)));

        // The scaled insets indents the form in a way that means its not resized when
        // the progress is updated
        this.add(
                this.getContentPanel(),
                LayoutHelper.getGBC(
                        0,
                        ++panelY,
                        1,
                        1.0D,
                        0.0D,
                        GridBagConstraints.BOTH,
                        GridBagConstraints.CENTER,
                        DisplayUtils.getScaledInsets(10, 40, 10, 40)));

        JPanel footerPanel = this.getFooterPanel();
        if (footerPanel != null) {
            this.add(
                    footerPanel,
                    LayoutHelper.getGBC(
                            0, ++panelY, 2, 1.0D, DisplayUtils.getScaledInsets(5, 5, 5, 5)));
        }

        this.add(
                new JLabel(),
                LayoutHelper.getGBC(
                        0,
                        ++panelY,
                        0,
                        0.0D,
                        1.0D,
                        GridBagConstraints.BOTH,
                        GridBagConstraints.CENTER,
                        DisplayUtils.getScaledInsets(0, 0, 0, 0)));
    }

    public ExtensionQuickStart getExtensionQuickStart() {
        return this.extension;
    }

    private JButton getBackButton() {
        if (backButton == null) {
            backButton = new JButton();
            backButton.setFont(FontUtils.getFont(Size.larger));
            backButton.setText(Constant.messages.getString("quickstart.button.label.back"));
            backButton.setToolTipText(
                    Constant.messages.getString("quickstart.button.tooltip.back"));

            backButton.addActionListener(e -> qsp.backToMainPanel());
        }
        return backButton;
    }

    public abstract String getTitleKey();

    public abstract ImageIcon getIcon();

    public abstract JPanel getDescriptionPanel();

    public abstract JPanel getContentPanel();

    public abstract JPanel getFooterPanel();
}
