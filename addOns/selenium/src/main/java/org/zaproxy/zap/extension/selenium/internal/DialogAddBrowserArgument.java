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
package org.zaproxy.zap.extension.selenium.internal;

import java.awt.Dialog;
import java.util.List;
import javax.swing.GroupLayout;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.AbstractFormDialog;

@SuppressWarnings("serial")
class DialogAddBrowserArgument extends AbstractFormDialog {

    private static final long serialVersionUID = 1L;

    private ZapTextField descriptionTextField;
    private JCheckBox enabledCheckBox;

    protected BrowserArgument browserArgument;
    private List<BrowserArgument> browserArguments;

    public DialogAddBrowserArgument(Dialog owner) {
        super(owner, Constant.messages.getString("selenium.options.browser.arguments.add.title"));
    }

    protected DialogAddBrowserArgument(Dialog owner, String title) {
        super(owner, title);
    }

    @Override
    protected JPanel getFieldsPanel() {
        JPanel fieldsPanel = new JPanel();

        GroupLayout layout = new GroupLayout(fieldsPanel);
        fieldsPanel.setLayout(layout);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        JLabel descriptionLabel = createLabel("argument", getArgumentTextField());
        JLabel enabledLabel = createLabel("enabled", getEnabledCheckBox());

        layout.setHorizontalGroup(
                layout.createSequentialGroup()
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                        .addComponent(descriptionLabel)
                                        .addComponent(enabledLabel))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                        .addComponent(getArgumentTextField())
                                        .addComponent(getEnabledCheckBox())));

        layout.setVerticalGroup(
                layout.createSequentialGroup()
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(descriptionLabel)
                                        .addComponent(getArgumentTextField()))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(enabledLabel)
                                        .addComponent(getEnabledCheckBox())));

        setConfirmButtonEnabled(false);

        return fieldsPanel;
    }

    private static JLabel createLabel(String key, JComponent field) {
        JLabel label =
                new JLabel(
                        Constant.messages.getString(
                                "selenium.options.browser.arguments.field." + key));
        label.setLabelFor(field);
        return label;
    }

    @Override
    protected String getConfirmButtonLabel() {
        return Constant.messages.getString("selenium.options.browser.arguments.add.button");
    }

    @Override
    protected void init() {
        reset(getArgumentTextField());
        getEnabledCheckBox().setSelected(true);
        browserArgument = null;
    }

    @Override
    protected boolean validateFields() {
        String argument = getArgumentTextField().getText().trim();
        for (BrowserArgument e : browserArguments) {
            if (argument.equals(e.getArgument())) {
                JOptionPane.showMessageDialog(
                        this,
                        Constant.messages.getString(
                                "selenium.options.browser.arguments.duplicated"),
                        Constant.messages.getString(
                                "selenium.options.browser.arguments.duplicated.title"),
                        JOptionPane.INFORMATION_MESSAGE);
                getArgumentTextField().requestFocusInWindow();
                return false;
            }
        }

        return true;
    }

    @Override
    protected void performAction() {
        browserArgument =
                new BrowserArgument(
                        getArgumentTextField().getText(), getEnabledCheckBox().isSelected());
    }

    @Override
    protected void clearFields() {
        reset(getArgumentTextField());

        getEnabledCheckBox().setSelected(true);
    }

    private static void reset(ZapTextField textField) {
        textField.setText("");
        textField.discardAllEdits();
    }

    public BrowserArgument getElem() {
        return browserArgument;
    }

    protected ZapTextField getArgumentTextField() {
        if (descriptionTextField == null) {
            descriptionTextField = new ZapTextField(25);
            descriptionTextField
                    .getDocument()
                    .addDocumentListener(
                            new DocumentListener() {

                                @Override
                                public void removeUpdate(DocumentEvent e) {
                                    checkAndEnableConfirmButton();
                                }

                                @Override
                                public void insertUpdate(DocumentEvent e) {
                                    checkAndEnableConfirmButton();
                                }

                                @Override
                                public void changedUpdate(DocumentEvent e) {
                                    checkAndEnableConfirmButton();
                                }

                                private void checkAndEnableConfirmButton() {
                                    setConfirmButtonEnabled(
                                            getArgumentTextField().getDocument().getLength() > 0);
                                }
                            });
        }
        return descriptionTextField;
    }

    protected JCheckBox getEnabledCheckBox() {
        if (enabledCheckBox == null) {
            enabledCheckBox = new JCheckBox();
        }
        return enabledCheckBox;
    }

    public void setBrowserArguments(List<BrowserArgument> browserArguments) {
        this.browserArguments = browserArguments;
    }

    public void clear() {
        this.browserArguments = null;
        this.browserArgument = null;
    }
}
