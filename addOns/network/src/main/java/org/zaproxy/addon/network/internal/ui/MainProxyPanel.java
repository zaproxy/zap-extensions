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
package org.zaproxy.addon.network.internal.ui;

import java.awt.Component;
import javax.swing.Box;
import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.network.internal.server.http.LocalServerConfig;
import org.zaproxy.zap.utils.NetworkUtils;
import org.zaproxy.zap.utils.ZapPortNumberSpinner;

public class MainProxyPanel extends JPanel {

    private static final long serialVersionUID = 1L;

    private final JComboBox<String> addressComboBox;
    private final ZapPortNumberSpinner portNumberSpinner;
    private final LocalServerPropertiesDialogue propertiesDialogue;

    public MainProxyPanel() {
        GroupLayout layout = new GroupLayout(this);
        setLayout(layout);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        JLabel addressLabel =
                new JLabel(
                        Constant.messages.getString(
                                "network.ui.options.localservers.add.field.address"));
        addressComboBox = new JComboBox<>();
        addressComboBox.setEditable(true);
        addressComboBox.addItem(LocalServerConfig.DEFAULT_ADDRESS);
        addressComboBox.addItem("127.0.0.1");
        addressComboBox.addItem("::1");
        addressComboBox.addItem("0.0.0.0");
        NetworkUtils.getAvailableAddresses(false).forEach(addressComboBox::addItem);
        addressLabel.setLabelFor(addressComboBox);

        JLabel portLabel =
                new JLabel(
                        Constant.messages.getString(
                                "network.ui.options.localservers.add.field.port"));
        portNumberSpinner = new ZapPortNumberSpinner(LocalServerConfig.DEFAULT_PORT);
        portLabel.setLabelFor(portNumberSpinner);

        propertiesDialogue =
                new LocalServerPropertiesDialogue(View.getSingleton().getOptionsDialog(null));
        Component glue = Box.createGlue();
        JButton propertiesButton =
                new JButton(
                        Constant.messages.getString(
                                "network.ui.options.localservers.modify.main.button"));
        propertiesButton.addActionListener(e -> propertiesDialogue.setVisible(true));

        layout.setHorizontalGroup(
                layout.createParallelGroup()
                        .addGroup(
                                layout.createSequentialGroup()
                                        .addGroup(
                                                layout.createParallelGroup(
                                                                GroupLayout.Alignment.TRAILING)
                                                        .addComponent(addressLabel)
                                                        .addComponent(portLabel))
                                        .addGroup(
                                                layout.createParallelGroup(
                                                                GroupLayout.Alignment.LEADING)
                                                        .addComponent(addressComboBox)
                                                        .addComponent(portNumberSpinner)))
                        .addGroup(
                                layout.createSequentialGroup()
                                        .addComponent(glue)
                                        .addComponent(propertiesButton)));

        layout.setVerticalGroup(
                layout.createSequentialGroup()
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(addressLabel)
                                        .addComponent(addressComboBox))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(portLabel)
                                        .addComponent(portNumberSpinner))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(glue)
                                        .addComponent(propertiesButton)));
    }

    public void setServerConfig(LocalServerConfig serverConfig) {
        addressComboBox.setSelectedItem(serverConfig.getAddress());
        portNumberSpinner.setValue(serverConfig.getPort());
        propertiesDialogue.setServerConfig(serverConfig);
    }

    public LocalServerConfig getServerConfig() {
        LocalServerConfig serverConfig = new LocalServerConfig();
        serverConfig.setAddress((String) addressComboBox.getSelectedItem());
        serverConfig.setPort(portNumberSpinner.getValue());
        propertiesDialogue.update(serverConfig);
        return serverConfig;
    }

    public void validateFields() {
        String address = (String) addressComboBox.getSelectedItem();
        if (address == null || address.isEmpty()) {
            addressComboBox.setSelectedItem(LocalServerConfig.DEFAULT_ANY_ADDRESS);
        }
    }
}
