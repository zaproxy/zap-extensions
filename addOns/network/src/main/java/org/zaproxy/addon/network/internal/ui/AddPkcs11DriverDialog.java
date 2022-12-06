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
import java.io.File;
import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.filechooser.FileNameExtensionFilter;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.network.internal.client.Pkcs11Driver;
import org.zaproxy.zap.utils.ZapNumberSpinner;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.AbstractFormDialog;

@SuppressWarnings("serial")
public class AddPkcs11DriverDialog extends AbstractFormDialog {

    private static final long serialVersionUID = 1L;

    protected final JPanel fieldsPanel;
    protected final ZapTextField nameTextField;
    protected final ZapTextField libraryTextField;
    protected final ZapNumberSpinner slotNumberSpinner;
    protected final ZapNumberSpinner slotListIndexNumberSpinner;

    protected Pkcs11Driver pkcs11Driver;

    public AddPkcs11DriverDialog(Dialog owner) {
        this(owner, Constant.messages.getString("network.ui.options.pkcs11driver.add.title"));
    }

    protected AddPkcs11DriverDialog(Dialog owner, String title) {
        super(owner, title, false);

        fieldsPanel = new JPanel();

        GroupLayout layout = new GroupLayout(fieldsPanel);
        fieldsPanel.setLayout(layout);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        JLabel nameLabel =
                new JLabel(
                        Constant.messages.getString(
                                "network.ui.options.pkcs11driver.add.field.name"));
        nameTextField = new ZapTextField(25);
        nameLabel.setLabelFor(nameTextField);

        JLabel libraryLabel =
                new JLabel(
                        Constant.messages.getString(
                                "network.ui.options.pkcs11driver.add.field.library"));
        libraryTextField = new ZapTextField(25);
        libraryLabel.setLabelFor(libraryTextField);

        ConsumerDocumentListener documentListener =
                new ConsumerDocumentListener(
                        e -> {
                            setConfirmButtonEnabled(
                                    nameTextField.getDocument().getLength() > 0
                                            && libraryTextField.getDocument().getLength() > 0);
                        });
        nameTextField.getDocument().addDocumentListener(documentListener);
        libraryTextField.getDocument().addDocumentListener(documentListener);

        JButton fileChooserButton =
                new JButton(
                        Constant.messages.getString(
                                "network.ui.options.pkcs11driver.add.field.library.select"));
        fileChooserButton.addActionListener(
                e -> {
                    JFileChooser fileChooser = new JFileChooser();
                    fileChooser.setFileFilter(
                            new FileNameExtensionFilter("DLL/dylib/so", "dll", "dylib", "so"));
                    fileChooser.setSelectedFile(new File(libraryTextField.getText()));

                    if (fileChooser.showOpenDialog(owner) == JFileChooser.APPROVE_OPTION) {
                        libraryTextField.setText(fileChooser.getSelectedFile().toString());
                    }
                });

        JLabel slotLabel =
                new JLabel(
                        Constant.messages.getString(
                                "network.ui.options.pkcs11driver.add.field.slot"));
        slotNumberSpinner = new ZapNumberSpinner(0, 0, Integer.MAX_VALUE);
        nameLabel.setLabelFor(slotNumberSpinner);

        JLabel slotListIndexLabel =
                new JLabel(
                        Constant.messages.getString(
                                "network.ui.options.pkcs11driver.add.field.slotlistindex"));
        slotListIndexNumberSpinner = new ZapNumberSpinner(0, 0, Integer.MAX_VALUE);
        nameLabel.setLabelFor(slotListIndexNumberSpinner);

        layout.setHorizontalGroup(
                layout.createSequentialGroup()
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                        .addComponent(nameLabel)
                                        .addComponent(libraryLabel)
                                        .addComponent(slotLabel)
                                        .addComponent(slotListIndexLabel))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                        .addComponent(nameTextField)
                                        .addGroup(
                                                layout.createSequentialGroup()
                                                        .addComponent(libraryTextField)
                                                        .addComponent(fileChooserButton))
                                        .addComponent(slotNumberSpinner)
                                        .addComponent(slotListIndexNumberSpinner)));

        layout.setVerticalGroup(
                layout.createSequentialGroup()
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(nameLabel)
                                        .addComponent(nameTextField))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(libraryLabel)
                                        .addComponent(libraryTextField)
                                        .addComponent(fileChooserButton))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(slotLabel)
                                        .addComponent(slotNumberSpinner))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(slotListIndexLabel)
                                        .addComponent(slotListIndexNumberSpinner)));

        initView();
    }

    @Override
    protected JPanel getFieldsPanel() {
        return fieldsPanel;
    }

    @Override
    protected String getConfirmButtonLabel() {
        return Constant.messages.getString("network.ui.options.pkcs11driver.add.button");
    }

    @Override
    protected void init() {
        nameTextField.setText("");
        nameTextField.discardAllEdits();
        libraryTextField.setText("");
        libraryTextField.discardAllEdits();
        slotNumberSpinner.setValue(0);
        slotListIndexNumberSpinner.setValue(0);
        pkcs11Driver = null;
    }

    @Override
    protected void performAction() {
        pkcs11Driver =
                new Pkcs11Driver(
                        nameTextField.getText(),
                        libraryTextField.getText(),
                        slotNumberSpinner.getValue(),
                        slotListIndexNumberSpinner.getValue());
    }

    public Pkcs11Driver getPkcs11Driver() {
        Pkcs11Driver pkcs11Driver = this.pkcs11Driver;
        this.pkcs11Driver = null;
        return pkcs11Driver;
    }
}
