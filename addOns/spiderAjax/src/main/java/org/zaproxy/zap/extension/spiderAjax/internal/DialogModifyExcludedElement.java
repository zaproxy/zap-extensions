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
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.utils.ZapTextField;

class DialogModifyExcludedElement extends DialogAddExcludedElement {

    private static final long serialVersionUID = 1L;

    protected DialogModifyExcludedElement(Dialog owner) {
        super(owner, Constant.messages.getString("spiderajax.excludedelements.ui.modify.title"));
    }

    @Override
    protected String getConfirmButtonLabel() {
        return Constant.messages.getString("spiderajax.excludedelements.ui.modify.button");
    }

    public void setElem(ExcludedElement excludedElement) {
        this.excludedElement = excludedElement;
    }

    @Override
    protected boolean validateFields() {
        return validate(excludedElement);
    }

    @Override
    protected void init() {
        setText(excludedElement.getDescription(), getDescriptionTextField());
        getElementComboBox().setSelectedItem(excludedElement.getElement());
        setText(excludedElement.getXpath(), getXpathTextField());
        setText(excludedElement.getText(), getTextTextField());
        setText(excludedElement.getAttributeName(), getAttributeNameTextField());
        setText(excludedElement.getAttributeValue(), getAttributeValueTextField());

        getEnabledCheckBox().setSelected(excludedElement.isEnabled());
    }

    private static void setText(String text, ZapTextField textField) {
        textField.setText(text);
        textField.discardAllEdits();
    }
}
