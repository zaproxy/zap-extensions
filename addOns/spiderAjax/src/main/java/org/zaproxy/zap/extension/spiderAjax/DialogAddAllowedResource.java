/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.zap.extension.spiderAjax;

import java.awt.Dialog;
import java.util.List;
import javax.swing.GroupLayout;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.AbstractFormDialog;

class DialogAddAllowedResource extends AbstractFormDialog {

    private static final long serialVersionUID = -5209887319253495735L;

    private static final String DIALOG_TITLE =
            Constant.messages.getString("spiderajax.options.dialog.allowedResources.add.title");

    private static final String CONFIRM_BUTTON_LABEL =
            Constant.messages.getString(
                    "spiderajax.options.dialog.allowedResources.add.button.confirm");

    private static final String REGEX_FIELD_LABEL =
            Constant.messages.getString(
                    "spiderajax.options.dialog.allowedResources.field.label.regex");
    private static final String ENABLED_FIELD_LABEL =
            Constant.messages.getString(
                    "spiderajax.options.dialog.allowedResources.field.label.enabled");

    private static final String TITLE_DISPLAY_REGEX_REPEATED_DIALOG =
            Constant.messages.getString(
                    "spiderajax.options.dialog.allowedResources.warning.name.repeated.title");
    private static final String TEXT_DISPLAY_REGEX_REPEATED_DIALOG =
            Constant.messages.getString(
                    "spiderajax.options.dialog.allowedResources.warning.name.repeated.text");

    private static final String TITLE_WARNING_INVALID_REGEX =
            Constant.messages.getString(
                    "spiderajax.options.dialog.allowedResources.warning.invalid.regex.title");

    private ZapTextField regexTextField;
    private JCheckBox enabledCheckBox;

    protected AllowedResource allowedResource;
    private List<AllowedResource> allowedResources;

    private ConfirmButtonValidatorDocListener confirmButtonValidatorDocListener;

    public DialogAddAllowedResource(Dialog owner) {
        super(owner, DIALOG_TITLE);
    }

    protected DialogAddAllowedResource(Dialog owner, String title) {
        super(owner, title);
    }

    @Override
    protected JPanel getFieldsPanel() {
        JPanel fieldsPanel = new JPanel();

        GroupLayout layout = new GroupLayout(fieldsPanel);
        fieldsPanel.setLayout(layout);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        JLabel regexLabel = new JLabel(REGEX_FIELD_LABEL);
        JLabel enabledLabel = new JLabel(ENABLED_FIELD_LABEL);

        layout.setHorizontalGroup(
                layout.createSequentialGroup()
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                        .addComponent(regexLabel)
                                        .addComponent(enabledLabel))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                        .addComponent(getRegexTextField())
                                        .addComponent(getEnabledCheckBox())));

        layout.setVerticalGroup(
                layout.createSequentialGroup()
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(regexLabel)
                                        .addComponent(getRegexTextField()))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(enabledLabel)
                                        .addComponent(getEnabledCheckBox())));

        return fieldsPanel;
    }

    @Override
    protected String getConfirmButtonLabel() {
        return CONFIRM_BUTTON_LABEL;
    }

    @Override
    protected void init() {
        getRegexTextField().setText("");
        getEnabledCheckBox().setSelected(true);
        allowedResource = null;
    }

    @Override
    protected boolean validateFields() {
        if (!validateDuplicatedRegex(getRegexTextField().getText())) {
            return false;
        }

        if (!validateRegex(getRegexTextField())) {
            return false;
        }

        return true;
    }

    protected boolean validateDuplicatedRegex(String regex) {
        for (AllowedResource allowedResource : allowedResources) {
            if (regex.equals(allowedResource.getPattern().pattern())) {
                JOptionPane.showMessageDialog(
                        this,
                        TEXT_DISPLAY_REGEX_REPEATED_DIALOG,
                        TITLE_DISPLAY_REGEX_REPEATED_DIALOG,
                        JOptionPane.INFORMATION_MESSAGE);
                getRegexTextField().requestFocusInWindow();
                return false;
            }
        }
        return true;
    }

    private boolean validateRegex(ZapTextField regexTextField) {
        try {
            AllowedResource.createDefaultPattern(regexTextField.getText());
        } catch (IllegalArgumentException e) {
            JOptionPane.showMessageDialog(
                    this,
                    Constant.messages.getString(
                            "spiderajax.options.dialog.allowedResources.warning.invalid.regex.text",
                            e.getLocalizedMessage()),
                    TITLE_WARNING_INVALID_REGEX,
                    JOptionPane.WARNING_MESSAGE);
            regexTextField.requestFocusInWindow();
            return false;
        }
        return true;
    }

    @Override
    protected void performAction() {
        allowedResource =
                new AllowedResource(
                        AllowedResource.createDefaultPattern(getRegexTextField().getText()),
                        getEnabledCheckBox().isSelected());
    }

    @Override
    protected void clearFields() {
        getRegexTextField().setText("");
        getRegexTextField().discardAllEdits();
    }

    public AllowedResource getAllowedResource() {
        return allowedResource;
    }

    protected ZapTextField getRegexTextField() {
        if (regexTextField == null) {
            regexTextField = new ZapTextField(25);
            regexTextField
                    .getDocument()
                    .addDocumentListener(getConfirmButtonValidatorDocListener());
        }

        return regexTextField;
    }

    protected JCheckBox getEnabledCheckBox() {
        if (enabledCheckBox == null) {
            enabledCheckBox = new JCheckBox();
        }

        return enabledCheckBox;
    }

    public void setAllowedResources(List<AllowedResource> allowedResources) {
        this.allowedResources = allowedResources;
    }

    public void clear() {
        this.allowedResources = null;
        this.allowedResource = null;
    }

    private ConfirmButtonValidatorDocListener getConfirmButtonValidatorDocListener() {
        if (confirmButtonValidatorDocListener == null) {
            confirmButtonValidatorDocListener = new ConfirmButtonValidatorDocListener();
        }

        return confirmButtonValidatorDocListener;
    }

    private class ConfirmButtonValidatorDocListener implements DocumentListener {

        @Override
        public void insertUpdate(DocumentEvent e) {
            checkAndEnableConfirmButton();
        }

        @Override
        public void removeUpdate(DocumentEvent e) {
            checkAndEnableConfirmButton();
        }

        @Override
        public void changedUpdate(DocumentEvent e) {
            checkAndEnableConfirmButton();
        }

        private void checkAndEnableConfirmButton() {
            setConfirmButtonEnabled(getRegexTextField().getDocument().getLength() > 0);
        }
    }
}
