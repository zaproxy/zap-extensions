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

import java.awt.Dialog;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.utils.ZapTextField;

class DialogModifyStep extends DialogAddStep {

    private static final long serialVersionUID = 1L;

    protected DialogModifyStep(Dialog owner) {
        super(
                owner,
                Constant.messages.getString(
                        "authhelper.auth.method.browser.steps.ui.modify.title"));
    }

    @Override
    protected String getConfirmButtonLabel() {
        return Constant.messages.getString("authhelper.auth.method.browser.steps.ui.modify.button");
    }

    public void setStep(AuthenticationStep step) {
        this.step = step;
    }

    @Override
    protected int getStepOrder() {
        return step.getOrder();
    }

    @Override
    protected boolean validateFields() {
        return validate(step);
    }

    @Override
    protected void init() {
        setText(step.getDescription(), getDescriptionTextField());
        getTypeComboBox().setSelectedItem(step.getType());
        setText(step.getCssSelector(), getCssSelectorTextField());
        setText(step.getXpath(), getXpathTextField());
        setText(step.getValue(), getValueTextField());
        getTimeoutNumberSpinner().setValue(step.getTimeout());

        setText(step.getTotpSecret(), getTotpSecretTextField());
        getTotpPeriodNumberSpinner().setValue(step.getTotpPeriod());
        getTotpDigitsNumberSpinner().setValue(step.getTotpDigits());
        getTotpAlgorithmComboBox().setSelectedItem(step.getTotpAlgorithm());

        getEnabledCheckBox().setSelected(step.isEnabled());
    }

    private static void setText(String text, ZapTextField textField) {
        textField.setText(text);
        textField.discardAllEdits();
    }
}
