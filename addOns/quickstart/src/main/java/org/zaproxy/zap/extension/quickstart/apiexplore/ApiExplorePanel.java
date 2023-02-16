/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.zap.extension.quickstart.apiexplore;

import java.awt.FlowLayout;
import javax.swing.AbstractButton;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.zap.extension.api.API;
import org.zaproxy.zap.extension.quickstart.ExtensionQuickStart;
import org.zaproxy.zap.extension.quickstart.QuickStartBackgroundPanel;
import org.zaproxy.zap.extension.quickstart.QuickStartHelper;
import org.zaproxy.zap.extension.quickstart.QuickStartPanel;
import org.zaproxy.zap.extension.quickstart.QuickStartSubPanel;
import org.zaproxy.zap.extension.quickstart.launch.ExtensionQuickStartLaunch;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.LayoutHelper;

public class ApiExplorePanel extends QuickStartSubPanel {

    private static final long serialVersionUID = 1L;
    private static final ImageIcon ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            ApiExplorePanel.class.getResource(
                                    "/org/zaproxy/zap/extension/quickstart/resources/api-explore_64px.png")));

    private JButton graphiQlButton;

    public ApiExplorePanel(ExtensionQuickStart extension, QuickStartPanel qsp) {
        super(extension, qsp);
    }

    @Override
    public String getTitleKey() {
        return "quickstart.apiExplore.panel.title";
    }

    @Override
    public ImageIcon getIcon() {
        return ICON;
    }

    @Override
    public JPanel getDescriptionPanel() {
        JPanel panel = new QuickStartBackgroundPanel();
        panel.add(
                QuickStartHelper.getWrappedLabel("quickstart.apiExplore.panel.message1"),
                LayoutHelper.getGBC(0, 0, 2, 1.0D, DisplayUtils.getScaledInsets(5, 5, 5, 5)));
        panel.add(
                new JLabel(" "),
                LayoutHelper.getGBC(
                        0, 1, 2, 1.0D, DisplayUtils.getScaledInsets(5, 5, 5, 5))); // Spacer
        return panel;
    }

    @Override
    public JPanel getContentPanel() {
        JPanel panel = new JPanel(new FlowLayout());
        panel.setBackground(getBackground());
        panel.add(getGraphiQlButton());
        return panel;
    }

    private JButton getGraphiQlButton() {
        if (graphiQlButton == null) {
            graphiQlButton = new JButton();
            graphiQlButton.setText(Constant.messages.getString("quickstart.graphiql.button.name"));
            graphiQlButton.setIcon(
                    DisplayUtils.getScaledIcon(
                            getClass()
                                    .getResource(
                                            "/org/zaproxy/zap/extension/quickstart/resources/graphql_64px.png")));
            graphiQlButton.setVerticalTextPosition(AbstractButton.BOTTOM);
            graphiQlButton.setHorizontalTextPosition(AbstractButton.CENTER);
            graphiQlButton.setToolTipText(
                    Constant.messages.getString("quickstart.graphiql.button.tooltip"));
            graphiQlButton.setPreferredSize(DisplayUtils.getScaledDimension(150, 120));
            var extQuickStartLaunch =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionQuickStartLaunch.class);
            graphiQlButton.addActionListener(
                    e ->
                            extQuickStartLaunch.launchBrowser(
                                    "http://zap/graphiql?"
                                            + API.API_NONCE_PARAM
                                            + '='
                                            + API.getInstance().getLongLivedNonce("/graphiql")));
        }
        return graphiQlButton;
    }

    @Override
    public JPanel getFooterPanel() {
        return null;
    }
}
