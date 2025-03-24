/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.addon.authhelper.internal;

import com.bastiaanjansen.otp.HMACAlgorithm;
import java.awt.Dialog;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;
import javax.swing.DefaultComboBoxModel;
import javax.swing.GroupLayout;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.commonlib.internal.TotpSupport;
import org.zaproxy.zap.utils.ZapNumberSpinner;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.AbstractFormDialog;

@SuppressWarnings("serial")
class DialogAddStep extends AbstractFormDialog {

    private static final long serialVersionUID = 1L;

    private ZapTextField descriptionTextField;
    private JComboBox<AuthenticationStep.Type> typeComboBox;
    private ZapTextField cssSelectorTextField;
    private ZapTextField xpathTextField;
    private ZapTextField valueTextField;
    private ZapNumberSpinner timeoutNumberSpinner;

    private JLabel totpSecretLabel;
    private ZapTextField totpSecretTextField;
    private JLabel totpPeriodLabel;
    private ZapNumberSpinner totpPeriodNumberSpinner;
    private JLabel totpDigitsLabel;
    private ZapNumberSpinner totpDigitsNumberSpinner;
    private JLabel totpAlgorithmLabel;
    private JComboBox<String> totpAlgorithmComboBox;

    private JLabel enabledLabel;
    private JCheckBox enabledCheckBox;

    protected AuthenticationStep step;
    private List<AuthenticationStep> steps;

    public DialogAddStep(Dialog owner) {
        super(
                owner,
                Constant.messages.getString("authhelper.auth.method.browser.steps.ui.add.title"));
    }

    protected DialogAddStep(Dialog owner, String title) {
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
        JLabel typeLabel = createLabel("type", getTypeComboBox());
        JLabel cssSelectorLabel = createLabel("cssselector", getCssSelectorTextField());
        JLabel xpathLabel = createLabel("xpath", getXpathTextField());
        JLabel valueLabel = createLabel("value", getValueTextField());
        JLabel timeoutLabel = createLabel("timeout", getTimeoutNumberSpinner());

        totpSecretLabel = createLabel("totpsecret", getTotpSecretTextField());
        totpPeriodLabel = createLabel("totpperiod", getTotpPeriodNumberSpinner());
        totpDigitsLabel = createLabel("totpdigits", getTotpDigitsNumberSpinner());
        totpAlgorithmLabel = createLabel("totpalgorithm", getTotpAlgorithmComboBox());

        layout.setHorizontalGroup(
                layout.createSequentialGroup()
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                        .addComponent(descriptionLabel)
                                        .addComponent(typeLabel)
                                        .addComponent(cssSelectorLabel)
                                        .addComponent(xpathLabel)
                                        .addComponent(valueLabel)
                                        .addComponent(timeoutLabel)
                                        .addComponent(totpSecretLabel)
                                        .addComponent(totpPeriodLabel)
                                        .addComponent(totpDigitsLabel)
                                        .addComponent(totpAlgorithmLabel)
                                        .addComponent(getEnabledLabel()))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                        .addComponent(getDescriptionTextField())
                                        .addComponent(getTypeComboBox())
                                        .addComponent(getCssSelectorTextField())
                                        .addComponent(getXpathTextField())
                                        .addComponent(getValueTextField())
                                        .addComponent(getTimeoutNumberSpinner())
                                        .addComponent(getTotpSecretTextField())
                                        .addComponent(getTotpPeriodNumberSpinner())
                                        .addComponent(getTotpDigitsNumberSpinner())
                                        .addComponent(getTotpAlgorithmComboBox())
                                        .addComponent(getEnabledCheckBox())));

        layout.setVerticalGroup(
                layout.createSequentialGroup()
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(descriptionLabel)
                                        .addComponent(getDescriptionTextField()))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(typeLabel)
                                        .addComponent(getTypeComboBox()))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(cssSelectorLabel)
                                        .addComponent(getCssSelectorTextField()))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(xpathLabel)
                                        .addComponent(getXpathTextField()))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(valueLabel)
                                        .addComponent(getValueTextField()))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(timeoutLabel)
                                        .addComponent(getTimeoutNumberSpinner()))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(totpSecretLabel)
                                        .addComponent(getTotpSecretTextField()))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(totpPeriodLabel)
                                        .addComponent(getTotpPeriodNumberSpinner()))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(totpDigitsLabel)
                                        .addComponent(getTotpDigitsNumberSpinner()))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(totpAlgorithmLabel)
                                        .addComponent(getTotpAlgorithmComboBox()))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(getEnabledLabel())
                                        .addComponent(getEnabledCheckBox())));

        setConfirmButtonEnabled(true);

        return fieldsPanel;
    }

    public void setEnableable(boolean enableable) {
        if (TotpSupport.isTotpInCore()) {
            totpSecretLabel.setVisible(enableable);
            getTotpSecretTextField().setVisible(enableable);
            totpPeriodLabel.setVisible(enableable);
            getTotpPeriodNumberSpinner().setVisible(enableable);
            totpDigitsLabel.setVisible(enableable);
            getTotpDigitsNumberSpinner().setVisible(enableable);
            totpAlgorithmLabel.setVisible(enableable);
            getTotpAlgorithmComboBox().setVisible(enableable);
        }

        getEnabledLabel().setVisible(enableable);
        getEnabledCheckBox().setVisible(enableable);
        if (!enableable) {
            getEnabledCheckBox().setSelected(true);
        }
    }

    private static JLabel createLabel(String key, JComponent field) {
        JLabel label =
                new JLabel(
                        Constant.messages.getString(
                                "authhelper.auth.method.browser.steps.ui.field." + key));
        label.setLabelFor(field);
        return label;
    }

    @Override
    protected String getConfirmButtonLabel() {
        return Constant.messages.getString("authhelper.auth.method.browser.steps.ui.add.button");
    }

    @Override
    protected void init() {
        getTypeComboBox().setSelectedIndex(0);
        getEnabledCheckBox().setSelected(true);
        step = null;
    }

    @Override
    protected boolean validateFields() {
        return validate(null);
    }

    protected boolean validate(AuthenticationStep oldStep) {
        AuthenticationStep.ValidationResult result =
                AuthenticationStep.validate(oldStep, createStep(), steps);
        switch (result) {
            case DUPLICATED:
                JOptionPane.showMessageDialog(
                        this,
                        Constant.messages.getString(
                                "authhelper.auth.method.browser.steps.ui.duplicated.text"),
                        Constant.messages.getString(
                                "authhelper.auth.method.browser.steps.ui.duplicated.title"),
                        JOptionPane.INFORMATION_MESSAGE);
                getDescriptionTextField().requestFocusInWindow();
                break;

            case EMPTY_DESCRIPTION:
                warnInvalid(getDescriptionTextField(), "description");
                break;

            case INVALID_TIMEOUT:
                warnInvalid(getTimeoutNumberSpinner(), "invalidtimeout");
                break;

            case INVALID_TOTP_ALGORITHM:
                warnInvalid(getTotpAlgorithmComboBox(), "invalidtotpalgorithm");
                break;

            case INVALID_TOTP_DIGITS:
                warnInvalid(getTotpDigitsNumberSpinner(), "invalidtotpdigits");
                break;

            case INVALID_TOTP_PERIOD:
                warnInvalid(getTotpPeriodNumberSpinner(), "invalidtotpperiod");
                break;

            case NO_CSS_OR_XPATH:
                warnInvalid(getCssSelectorTextField(), "nocssorxpath");
                break;

            case NO_TOTP_SECRET:
                warnInvalid(getTotpSecretTextField(), "nototpsecret");
                break;

            case NO_TYPE:
                warnInvalid(getTypeComboBox(), "notype");
                break;

            case NO_VALUE:
                warnInvalid(getValueTextField(), "novalue");
                break;

            case VALID:
            default:
                break;
        }

        return result == AuthenticationStep.ValidationResult.VALID;
    }

    private AuthenticationStep createStep() {
        AuthenticationStep newStep = new AuthenticationStep();
        newStep.setDescription(getDescriptionTextField().getText());
        newStep.setType((AuthenticationStep.Type) getTypeComboBox().getSelectedItem());
        newStep.setCssSelector(getCssSelectorTextField().getText());
        newStep.setXpath(getXpathTextField().getText());
        newStep.setValue(getValueTextField().getText());
        newStep.setTimeout(getTimeoutNumberSpinner().getValue());

        if (TotpSupport.isTotpInCore() && !getTotpSecretTextField().isVisible()) {
            // Secret is read from the user credentials.
            getTotpSecretTextField().setText("UserCredentials");
        }
        newStep.setTotpSecret(getTotpSecretTextField().getText());
        newStep.setTotpPeriod(getTotpPeriodNumberSpinner().getValue());
        newStep.setTotpDigits(getTotpDigitsNumberSpinner().getValue());
        newStep.setTotpAlgorithm((String) getTotpAlgorithmComboBox().getSelectedItem());

        newStep.setEnabled(getEnabledCheckBox().isSelected());
        newStep.setOrder(getStepOrder());
        return newStep;
    }

    protected int getStepOrder() {
        return steps.size() + 1;
    }

    private void warnInvalid(JComponent textField, String key) {
        showInvalidStepWarn("authhelper.auth.method.browser.steps.ui.warn.invalid." + key);
        textField.requestFocusInWindow();
    }

    private void showInvalidStepWarn(String keyMessage) {
        JOptionPane.showMessageDialog(
                this,
                Constant.messages.getString(keyMessage),
                Constant.messages.getString(
                        "authhelper.auth.method.browser.steps.ui.warn.invalid.title"),
                JOptionPane.INFORMATION_MESSAGE);
    }

    @Override
    protected void performAction() {
        step = createStep();
    }

    @Override
    protected void clearFields() {
        reset(getDescriptionTextField());
        getTypeComboBox().setSelectedIndex(0);
        reset(getCssSelectorTextField());
        reset(getXpathTextField());
        reset(getValueTextField());
        getTimeoutNumberSpinner().setValue(0);

        reset(getTotpSecretTextField());
        getTotpPeriodNumberSpinner().setValue(30);
        getTotpDigitsNumberSpinner().setValue(6);
        getTotpAlgorithmComboBox().setSelectedIndex(0);

        getEnabledCheckBox().setSelected(true);
    }

    private static void reset(ZapTextField textField) {
        textField.setText("");
        textField.discardAllEdits();
    }

    public AuthenticationStep getStep() {
        return step;
    }

    protected ZapTextField getDescriptionTextField() {
        if (descriptionTextField == null) {
            descriptionTextField = new ZapTextField(25);
        }
        return descriptionTextField;
    }

    protected JComboBox<AuthenticationStep.Type> getTypeComboBox() {
        if (typeComboBox == null) {
            DefaultComboBoxModel<AuthenticationStep.Type> model = new DefaultComboBoxModel<>();
            Stream.of(AuthenticationStep.Type.values())
                    .sorted(Comparator.comparing(AuthenticationStep.Type::toString))
                    .forEach(model::addElement);
            typeComboBox = new JComboBox<>(model);
        }
        return typeComboBox;
    }

    protected ZapTextField getCssSelectorTextField() {
        if (cssSelectorTextField == null) {
            cssSelectorTextField = new ZapTextField(25);
        }
        return cssSelectorTextField;
    }

    protected ZapTextField getXpathTextField() {
        if (xpathTextField == null) {
            xpathTextField = new ZapTextField(25);
        }
        return xpathTextField;
    }

    protected ZapTextField getValueTextField() {
        if (valueTextField == null) {
            valueTextField = new ZapTextField(25);
        }
        return valueTextField;
    }

    protected ZapNumberSpinner getTimeoutNumberSpinner() {
        if (timeoutNumberSpinner == null) {
            timeoutNumberSpinner = new ZapNumberSpinner(1, 1000, Integer.MAX_VALUE);
        }
        return timeoutNumberSpinner;
    }

    protected JCheckBox getEnabledCheckBox() {
        if (enabledCheckBox == null) {
            enabledCheckBox = new JCheckBox();
        }
        return enabledCheckBox;
    }

    protected ZapTextField getTotpSecretTextField() {
        if (totpSecretTextField == null) {
            totpSecretTextField = new ZapTextField(25);
        }
        return totpSecretTextField;
    }

    protected ZapNumberSpinner getTotpPeriodNumberSpinner() {
        if (totpPeriodNumberSpinner == null) {
            totpPeriodNumberSpinner = new ZapNumberSpinner(1, 30, Integer.MAX_VALUE);
        }
        return totpPeriodNumberSpinner;
    }

    protected ZapNumberSpinner getTotpDigitsNumberSpinner() {
        if (totpDigitsNumberSpinner == null) {
            totpDigitsNumberSpinner = new ZapNumberSpinner(1, 6, Integer.MAX_VALUE);
        }
        return totpDigitsNumberSpinner;
    }

    protected JComboBox<String> getTotpAlgorithmComboBox() {
        if (totpAlgorithmComboBox == null) {
            DefaultComboBoxModel<String> model = new DefaultComboBoxModel<>();
            Stream.of(HMACAlgorithm.values()).map(HMACAlgorithm::name).forEach(model::addElement);
            totpAlgorithmComboBox = new JComboBox<>(model);
        }
        return totpAlgorithmComboBox;
    }

    protected JLabel getEnabledLabel() {
        if (enabledLabel == null) {
            enabledLabel = createLabel("enabled", getEnabledCheckBox());
        }
        return enabledLabel;
    }

    public void setSteps(List<AuthenticationStep> steps) {
        this.steps = steps;
    }

    public void clear() {
        this.steps = null;
        this.step = null;
    }
}
