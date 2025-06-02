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
package org.zaproxy.zap.extension.spiderAjax.internal;

import java.awt.Dialog;
import java.util.List;
import javax.swing.GroupLayout;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.spiderAjax.AjaxSpiderParam;
import org.zaproxy.zap.utils.SortedComboBoxModel;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.AbstractFormDialog;

@SuppressWarnings("serial")
class DialogAddExcludedElement extends AbstractFormDialog {

    private static final long serialVersionUID = 1L;

    private ZapTextField descriptionTextField;
    private JComboBox<String> elementComboBox;
    private ZapTextField xpathTextField;
    private ZapTextField textTextField;
    private ZapTextField attributeNameTextField;
    private ZapTextField attributeValueTextField;
    private JLabel enabledLabel;
    private JCheckBox enabledCheckBox;

    protected ExcludedElement excludedElement;
    private List<ExcludedElement> excludedElements;

    public DialogAddExcludedElement(Dialog owner) {
        super(owner, Constant.messages.getString("spiderajax.excludedelements.ui.add.title"));
    }

    protected DialogAddExcludedElement(Dialog owner, String title) {
        super(owner, title);
    }

    @Override
    protected JPanel getFieldsPanel() {
        JPanel fieldsPanel = new JPanel();

        GroupLayout layout = new GroupLayout(fieldsPanel);
        fieldsPanel.setLayout(layout);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        JLabel descriptionLabel = createLabel("description", getDescriptionTextField());
        JLabel nameLabel = createLabel("element", getElementComboBox());
        JLabel xpathLabel = createLabel("xpath", getXpathTextField());
        JLabel textLabel = createLabel("text", getTextTextField());
        JLabel attributeNameLabel = createLabel("attributeName", getAttributeNameTextField());
        JLabel attributeValueLabel = createLabel("attributeValue", getAttributeValueTextField());

        layout.setHorizontalGroup(
                layout.createSequentialGroup()
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                        .addComponent(descriptionLabel)
                                        .addComponent(nameLabel)
                                        .addComponent(xpathLabel)
                                        .addComponent(textLabel)
                                        .addComponent(attributeNameLabel)
                                        .addComponent(attributeValueLabel)
                                        .addComponent(getEnabledLabel()))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                        .addComponent(getDescriptionTextField())
                                        .addComponent(getElementComboBox())
                                        .addComponent(getXpathTextField())
                                        .addComponent(getTextTextField())
                                        .addComponent(getAttributeNameTextField())
                                        .addComponent(getAttributeValueTextField())
                                        .addComponent(getEnabledCheckBox())));

        layout.setVerticalGroup(
                layout.createSequentialGroup()
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(descriptionLabel)
                                        .addComponent(getDescriptionTextField()))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(nameLabel)
                                        .addComponent(getElementComboBox()))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(xpathLabel)
                                        .addComponent(getXpathTextField()))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(textLabel)
                                        .addComponent(getTextTextField()))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(attributeNameLabel)
                                        .addComponent(getAttributeNameTextField()))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(attributeValueLabel)
                                        .addComponent(getAttributeValueTextField()))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(getEnabledLabel())
                                        .addComponent(getEnabledCheckBox())));

        setConfirmButtonEnabled(true);

        return fieldsPanel;
    }

    public void setEnableable(boolean enableable) {
        getEnabledLabel().setVisible(enableable);
        getEnabledCheckBox().setVisible(enableable);
        if (!enableable) {
            getEnabledCheckBox().setSelected(true);
        }
    }

    private static JLabel createLabel(String key, JComponent field) {
        JLabel label =
                new JLabel(
                        Constant.messages.getString("spiderajax.excludedelements.ui.field." + key));
        label.setLabelFor(field);
        return label;
    }

    @Override
    protected String getConfirmButtonLabel() {
        return Constant.messages.getString("spiderajax.excludedelements.ui.add.button");
    }

    @Override
    protected void init() {
        getElementComboBox().setSelectedIndex(0);
        getEnabledCheckBox().setSelected(true);
        excludedElement = null;
    }

    @Override
    protected boolean validateFields() {
        return validate(null);
    }

    protected boolean validate(ExcludedElement oldElement) {
        ExcludedElement.ValidationResult result =
                ExcludedElement.validate(oldElement, createExcludedElement(), excludedElements);
        switch (result) {
            case EMPTY_DESCRIPTION:
                warnInvalid(getDescriptionTextField(), "description");
                break;

            case EMPTY_ELEMENT:
                warnInvalid(getElementComboBox(), "element");
                break;

            case MISSING_DATA:
                showInvalidElementWarn("spiderajax.excludedelements.ui.warn.invalid.missingdata");
                break;

            case MISSING_ATTRIBUTE_FIELD:
                showInvalidElementWarn(
                        "spiderajax.excludedelements.ui.warn.invalid.incompleteattribute");
                break;

            case DUPLICATED:
                JOptionPane.showMessageDialog(
                        this,
                        Constant.messages.getString(
                                "spiderajax.excludedelements.ui.warn.duplicated.text"),
                        Constant.messages.getString(
                                "spiderajax.excludedelements.ui.warn.duplicated.title"),
                        JOptionPane.INFORMATION_MESSAGE);
                getDescriptionTextField().requestFocusInWindow();
                break;

            case VALID:
            default:
                break;
        }

        return result == ExcludedElement.ValidationResult.VALID;
    }

    private ExcludedElement createExcludedElement() {
        ExcludedElement element = new ExcludedElement();
        element.setDescription(getDescriptionTextField().getText());
        element.setElement((String) getElementComboBox().getSelectedItem());
        element.setXpath(getXpathTextField().getText());
        element.setText(getTextTextField().getText());
        element.setAttributeName(getAttributeNameTextField().getText());
        element.setAttributeValue(getAttributeValueTextField().getText());
        element.setEnabled(getEnabledCheckBox().isSelected());
        return element;
    }

    private void warnInvalid(JComponent textField, String key) {
        showInvalidElementWarn("spiderajax.excludedelements.ui.warn.invalid." + key);
        textField.requestFocusInWindow();
    }

    private void showInvalidElementWarn(String keyMessage) {
        JOptionPane.showMessageDialog(
                this,
                Constant.messages.getString(keyMessage),
                Constant.messages.getString("spiderajax.excludedelements.ui.warn.invalid.title"),
                JOptionPane.INFORMATION_MESSAGE);
    }

    @Override
    protected void performAction() {
        excludedElement = createExcludedElement();
    }

    @Override
    protected void clearFields() {
        reset(getDescriptionTextField());
        getElementComboBox().setSelectedIndex(0);
        reset(getXpathTextField());
        reset(getTextTextField());
        reset(getAttributeNameTextField());
        reset(getAttributeValueTextField());

        getEnabledCheckBox().setSelected(true);
    }

    private static void reset(ZapTextField textField) {
        textField.setText("");
        textField.discardAllEdits();
    }

    public ExcludedElement getElem() {
        return excludedElement;
    }

    protected ZapTextField getDescriptionTextField() {
        if (descriptionTextField == null) {
            descriptionTextField = new ZapTextField(25);
        }
        return descriptionTextField;
    }

    protected JComboBox<String> getElementComboBox() {
        if (elementComboBox == null) {
            elementComboBox =
                    new JComboBox<>(new SortedComboBoxModel<>(AjaxSpiderParam.DEFAULT_ELEMS_NAMES));
            elementComboBox.setEditable(true);
        }
        return elementComboBox;
    }

    protected ZapTextField getXpathTextField() {
        if (xpathTextField == null) {
            xpathTextField = new ZapTextField(25);
        }
        return xpathTextField;
    }

    protected ZapTextField getTextTextField() {
        if (textTextField == null) {
            textTextField = new ZapTextField(25);
        }
        return textTextField;
    }

    protected ZapTextField getAttributeNameTextField() {
        if (attributeNameTextField == null) {
            attributeNameTextField = new ZapTextField(25);
        }
        return attributeNameTextField;
    }

    protected ZapTextField getAttributeValueTextField() {
        if (attributeValueTextField == null) {
            attributeValueTextField = new ZapTextField(25);
        }
        return attributeValueTextField;
    }

    protected JCheckBox getEnabledCheckBox() {
        if (enabledCheckBox == null) {
            enabledCheckBox = new JCheckBox();
        }
        return enabledCheckBox;
    }

    protected JLabel getEnabledLabel() {
        if (enabledLabel == null) {
            enabledLabel = createLabel("enabled", getEnabledCheckBox());
        }
        return enabledLabel;
    }

    public void setElems(List<ExcludedElement> elems) {
        this.excludedElements = elems;
    }

    public void clear() {
        this.excludedElements = null;
        this.excludedElement = null;
    }
}
