/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.formhandler;

import java.awt.Dialog;
import org.parosproxy.paros.Constant;

class DialogModifyField extends DialogAddField {

    private static final long serialVersionUID = 6675509994290748494L;

    private static final String DIALOG_TITLE =
            Constant.messages.getString("formhandler.options.dialog.field.modify.title");

    private static final String CONFIRM_BUTTON_LABEL =
            Constant.messages.getString("formhandler.options.dialog.field.modify.button.confirm");

    protected DialogModifyField(Dialog owner) {
        super(owner, DIALOG_TITLE);
    }

    @Override
    protected String getConfirmButtonLabel() {
        return CONFIRM_BUTTON_LABEL;
    }

    public void setField(FormHandlerParamField field) {
        this.field = field;
    }

    @Override
    protected boolean validateFields() {
        if (field.getName().equalsIgnoreCase(getNameTextField().getText())) {
            return true;
        }
        return super.validateFields();
    }

    @Override
    protected void init() {
        getNameTextField().setText(field.getName());
        getNameTextField().discardAllEdits();

        getValueTextField().setText(field.getValue());
        getValueTextField().discardAllEdits();

        getEnabledCheckBox().setSelected(field.isEnabled());
    }
}
