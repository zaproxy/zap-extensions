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

import java.awt.Component;
import java.util.List;
import javax.swing.AbstractButton;
import javax.swing.JButton;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.addon.graphql.ExtensionGraphQl;
import org.zaproxy.zap.extension.quickstart.ExtensionQuickStart;
import org.zaproxy.zap.extension.quickstart.launch.ExtensionQuickStartLaunch;
import org.zaproxy.zap.utils.DisplayUtils;

public class ExtensionApiExplore extends ExtensionAdaptor {

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(ExtensionGraphQl.class, ExtensionQuickStartLaunch.class);

    private ApiExplorePanel apiExplorePanel;
    private JButton apiExploreButton;

    @Override
    public String getUIName() {
        return Constant.messages.getString("quickstart.apiExplore.extension.uiName");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("quickstart.apiExplore.extension.desc");
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        if (hasView()) {
            var buttonPanel = getExtQuickStart().getQuickStartPanel().getButtonPanel();
            for (Component component : buttonPanel.getComponents()) {
                if (component instanceof JButton) {
                    var button = (JButton) component;
                    if (Constant.messages
                            .getString("quickstart.apiExplore.button.name")
                            .equals(button.getText())) {
                        buttonPanel.remove(button);
                        break;
                    }
                }
            }
            var buttonCount = buttonPanel.getComponentCount();
            buttonPanel.add(getApiExploreButton(), buttonCount - 1);
            buttonPanel.revalidate();
            buttonPanel.repaint();
        }
    }

    private JButton getApiExploreButton() {
        if (apiExploreButton == null) {
            apiExploreButton = new JButton();
            apiExploreButton.setText(
                    Constant.messages.getString("quickstart.apiExplore.button.name"));
            apiExploreButton.setIcon(getApiExplorePanel().getIcon());
            apiExploreButton.setVerticalTextPosition(AbstractButton.BOTTOM);
            apiExploreButton.setHorizontalTextPosition(AbstractButton.CENTER);
            apiExploreButton.setToolTipText(
                    Constant.messages.getString("quickstart.apiExplore.button.tooltip"));
            apiExploreButton.setPreferredSize(DisplayUtils.getScaledDimension(150, 120));
            apiExploreButton.addActionListener(
                    e ->
                            getExtQuickStart()
                                    .getQuickStartPanel()
                                    .showSubPanel(getApiExplorePanel()));
        }
        return apiExploreButton;
    }

    private ApiExplorePanel getApiExplorePanel() {
        if (apiExplorePanel == null) {
            apiExplorePanel =
                    new ApiExplorePanel(
                            getExtQuickStart(), getExtQuickStart().getQuickStartPanel());
        }
        return apiExplorePanel;
    }

    private ExtensionQuickStart getExtQuickStart() {
        return Control.getSingleton().getExtensionLoader().getExtension(ExtensionQuickStart.class);
    }
}
