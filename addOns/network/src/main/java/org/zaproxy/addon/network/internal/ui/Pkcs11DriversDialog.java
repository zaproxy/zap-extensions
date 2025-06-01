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

import java.awt.Window;
import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JPanel;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractDialog;
import org.zaproxy.addon.network.internal.client.Pkcs11Drivers;

@SuppressWarnings("serial")
public class Pkcs11DriversDialog extends AbstractDialog {

    private static final long serialVersionUID = 1L;

    private final Pkcs11Drivers drivers;

    private final Pkcs11DriverTablePanel tablePanel;

    public Pkcs11DriversDialog(Window owner) {
        super(owner, true);

        drivers = new Pkcs11Drivers();
        tablePanel = new Pkcs11DriverTablePanel(this, drivers);

        setTitle(
                Constant.messages.getString(
                        "network.ui.options.clientcertificates.pkcs11drivers.title"));

        JButton closeButton = new JButton();
        closeButton.setText(Constant.messages.getString("all.button.close"));
        closeButton.addActionListener(e -> dispose());

        JPanel panel = new JPanel();
        GroupLayout layout = new GroupLayout(panel);
        panel.setLayout(layout);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        layout.setHorizontalGroup(
                layout.createParallelGroup()
                        .addComponent(tablePanel)
                        .addComponent(closeButton, GroupLayout.Alignment.TRAILING));
        layout.setVerticalGroup(
                layout.createSequentialGroup().addComponent(tablePanel).addComponent(closeButton));

        setContentPane(panel);
        pack();
    }

    @Override
    public void dispose() {
        drivers.save();
        super.dispose();
    }

    public Pkcs11Drivers getDrivers() {
        return drivers;
    }
}
