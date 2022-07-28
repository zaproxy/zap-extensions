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

import java.awt.Dialog;
import javax.swing.GroupLayout;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.network.internal.server.http.LocalServerConfig;
import org.zaproxy.zap.utils.NetworkUtils;
import org.zaproxy.zap.utils.ZapPortNumberSpinner;
import org.zaproxy.zap.view.AbstractFormDialog;

@SuppressWarnings("serial")
public class AddLocalServerDialog extends AbstractFormDialog {

    private static final long serialVersionUID = 1L;

    protected final JPanel fieldsPanel;
    protected final JComboBox<String> addressComboBox;
    protected final ZapPortNumberSpinner portNumberSpinner;
    protected final LocalServerPropertiesPanel propertiesPanel;
    protected final AddressValidator addressValidator;
    protected LocalServerConfig serverConfig;

    public AddLocalServerDialog(AddressValidator addressValidator, Dialog owner) {
        this(
                addressValidator,
                owner,
                Constant.messages.getString("network.ui.options.localservers.add.title"));
    }

    protected AddLocalServerDialog(AddressValidator addressValidator, Dialog owner, String title) {
        super(owner, title, false);

        this.addressValidator = addressValidator;

        fieldsPanel = new JPanel();

        GroupLayout layout = new GroupLayout(fieldsPanel);
        fieldsPanel.setLayout(layout);
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

        propertiesPanel = new LocalServerPropertiesPanel(true);

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
                        .addComponent(propertiesPanel));

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
                        .addComponent(propertiesPanel));

        initView();
        setConfirmButtonEnabled(true);
    }

    @Override
    protected JPanel getFieldsPanel() {
        return fieldsPanel;
    }

    @Override
    protected String getConfirmButtonLabel() {
        return Constant.messages.getString("network.ui.options.localservers.add.button");
    }

    @Override
    protected void init() {
        addressComboBox.setSelectedIndex(0);
        portNumberSpinner.setValue(LocalServerConfig.DEFAULT_PORT);
        propertiesPanel.reset();
        serverConfig = null;
    }

    @Override
    protected boolean validateFields() {
        String address = (String) addressComboBox.getSelectedItem();
        if (address == null || address.isEmpty()) {
            addressComboBox.setSelectedItem(LocalServerConfig.DEFAULT_ANY_ADDRESS);
        }

        if (!propertiesPanel.validateFields()) {
            return false;
        }

        if (serverConfig != null
                && serverConfig.getPort() == portNumberSpinner.getValue()
                && serverConfig.getAddress().equals(address)) {
            return true;
        }
        return addressValidator.validate(this, address, portNumberSpinner.getValue());
    }

    @Override
    protected void performAction() {
        boolean enable = serverConfig != null ? serverConfig.isEnabled() : true;
        serverConfig = new LocalServerConfig();
        serverConfig.setEnabled(enable);
        serverConfig.setAddress((String) addressComboBox.getSelectedItem());
        serverConfig.setPort(portNumberSpinner.getValue());
        serverConfig.setAddress((String) addressComboBox.getSelectedItem());
        propertiesPanel.update(serverConfig);
    }

    public LocalServerConfig getServerConfig() {
        LocalServerConfig serverConfig = this.serverConfig;
        this.serverConfig = null;
        return serverConfig;
    }
}
