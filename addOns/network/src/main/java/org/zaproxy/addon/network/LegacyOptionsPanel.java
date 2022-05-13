/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.network;

import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JLabel;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.parosproxy.paros.view.View;

class LegacyOptionsPanel extends AbstractParamPanel {

    private static final long serialVersionUID = 1L;

    LegacyOptionsPanel(String sourceKey, AbstractParamPanel newPanel) {
        setName(Constant.messages.getString("network.ui.options.legacy." + sourceKey));

        JLabel label =
                new JLabel(
                        Constant.messages.getString(
                                "network.ui.options.legacy." + sourceKey + ".moved"));
        JButton button =
                new JButton(Constant.messages.getString("network.ui.options.legacy.opennew"));
        button.addActionListener(
                e -> View.getSingleton().getOptionsDialog(null).showParamPanel(newPanel, ""));

        GroupLayout layout = new GroupLayout(this);
        setLayout(layout);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        layout.setHorizontalGroup(
                layout.createParallelGroup().addComponent(label).addComponent(button));

        layout.setVerticalGroup(
                layout.createSequentialGroup().addComponent(label).addComponent(button));
    }

    @Override
    public void initParam(Object obj) {}

    @Override
    public void saveParam(Object obj) throws Exception {}
}
