/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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

class DialogAddElem extends AbstractFormDialog {

    private static final long serialVersionUID = 4460797449668634319L;

    private static final String DIALOG_TITLE =
            Constant.messages.getString("spiderajax.options.dialog.elem.add.title");

    private static final String CONFIRM_BUTTON_LABEL =
            Constant.messages.getString("spiderajax.options.dialog.elem.add.button.confirm");

    private static final String NAME_FIELD_LABEL =
            Constant.messages.getString("spiderajax.options.dialog.elem.field.label.name");
    private static final String ENABLED_FIELD_LABEL =
            Constant.messages.getString("spiderajax.options.dialog.elem.field.label.enabled");

    private static final String TITLE_NAME_REPEATED_DIALOG =
            Constant.messages.getString(
                    "spiderajax.options.dialog.elem.warning.name.repeated.title");
    private static final String TEXT_NAME_REPEATED_DIALOG =
            Constant.messages.getString(
                    "spiderajax.options.dialog.elem.warning.name.repeated.text");

    private ZapTextField nameTextField;
    private JCheckBox enabledCheckBox;

    protected AjaxSpiderParamElem elem;
    private List<AjaxSpiderParamElem> elems;

    public DialogAddElem(Dialog owner) {
        super(owner, DIALOG_TITLE);
    }

    protected DialogAddElem(Dialog owner, String title) {
        super(owner, title);
    }

    @Override
    protected JPanel getFieldsPanel() {
        JPanel fieldsPanel = new JPanel();

        GroupLayout layout = new GroupLayout(fieldsPanel);
        fieldsPanel.setLayout(layout);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        JLabel nameLabel = new JLabel(NAME_FIELD_LABEL);
        JLabel enabledLabel = new JLabel(ENABLED_FIELD_LABEL);

        layout.setHorizontalGroup(
                layout.createSequentialGroup()
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                        .addComponent(nameLabel)
                                        .addComponent(enabledLabel))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                        .addComponent(getNameTextField())
                                        .addComponent(getEnabledCheckBox())));

        layout.setVerticalGroup(
                layout.createSequentialGroup()
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(nameLabel)
                                        .addComponent(getNameTextField()))
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
        getNameTextField().setText("");
        getEnabledCheckBox().setSelected(true);
        elem = null;
    }

    @Override
    protected boolean validateFields() {
        String elemName = getNameTextField().getText();
        for (AjaxSpiderParamElem e : elems) {
            if (elemName.equalsIgnoreCase(e.getName())) {
                JOptionPane.showMessageDialog(
                        this,
                        TEXT_NAME_REPEATED_DIALOG,
                        TITLE_NAME_REPEATED_DIALOG,
                        JOptionPane.INFORMATION_MESSAGE);
                getNameTextField().requestFocusInWindow();
                return false;
            }
        }

        return true;
    }

    @Override
    protected void performAction() {
        elem =
                new AjaxSpiderParamElem(
                        getNameTextField().getText(), getEnabledCheckBox().isSelected());
    }

    @Override
    protected void clearFields() {
        getNameTextField().setText("");
        getNameTextField().discardAllEdits();
    }

    public AjaxSpiderParamElem getElem() {
        return elem;
    }

    protected ZapTextField getNameTextField() {
        if (nameTextField == null) {
            nameTextField = new ZapTextField(25);
            nameTextField
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
                                            getNameTextField().getDocument().getLength() > 0);
                                }
                            });
        }

        return nameTextField;
    }

    protected JCheckBox getEnabledCheckBox() {
        if (enabledCheckBox == null) {
            enabledCheckBox = new JCheckBox();
        }

        return enabledCheckBox;
    }

    public void setElems(List<AjaxSpiderParamElem> elems) {
        this.elems = elems;
    }

    public void clear() {
        this.elems = null;
        this.elem = null;
    }
}
