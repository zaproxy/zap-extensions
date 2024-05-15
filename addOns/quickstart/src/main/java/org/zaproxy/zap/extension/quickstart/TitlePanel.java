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

import java.awt.GridBagConstraints;
import javax.swing.BoxLayout;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.utils.FontUtils.Size;
import org.zaproxy.zap.view.LayoutHelper;

@SuppressWarnings("serial")
public class TitlePanel extends QuickStartBackgroundPanel {

    private static final long serialVersionUID = 1L;

    public TitlePanel(String title, JButton backButton, ImageIcon icon) {
        JLabel topTitle = new JLabel(title);
        topTitle.setBackground(getBackground());
        topTitle.setFont(FontUtils.getFont(Size.much_larger));

        JPanel leftPanel = new JPanel();
        leftPanel.setBackground(getBackground());
        leftPanel.setLayout(new BoxLayout(leftPanel, BoxLayout.X_AXIS));

        if (backButton != null) {
            leftPanel.add(backButton);
            leftPanel.add(new JLabel(icon));
        } else {
            leftPanel.add(
                    new JLabel(
                            DisplayUtils.getScaledIcon(
                                    new ImageIcon(
                                            getClass()
                                                    .getResource(
                                                            ExtensionQuickStart.RESOURCES
                                                                    + "/blank.png")))));
        }
        add(
                leftPanel,
                LayoutHelper.getGBC(
                        0,
                        0,
                        1,
                        0,
                        0,
                        GridBagConstraints.NONE,
                        GridBagConstraints.WEST,
                        getInsets()));
        add(
                topTitle,
                LayoutHelper.getGBC(
                        1,
                        0,
                        1,
                        100,
                        100,
                        GridBagConstraints.NONE,
                        GridBagConstraints.CENTER,
                        getInsets()));
        add(
                QuickStartPanel.getOsfImageLabel(),
                LayoutHelper.getGBC(
                        2,
                        0,
                        1,
                        0,
                        0,
                        GridBagConstraints.NONE,
                        GridBagConstraints.EAST,
                        getInsets()));
    }

    public TitlePanel(String title) {
        this(title, null, null);
    }
}
