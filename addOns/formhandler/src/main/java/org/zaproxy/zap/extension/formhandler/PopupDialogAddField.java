/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
import java.util.Set;
import javax.swing.JComboBox;
import org.parosproxy.paros.control.Control;

@SuppressWarnings("serial")
class PopupDialogAddField extends DialogAddField {

    private static final long serialVersionUID = 4460797449668634319L;

    private ExtensionFormHandler extFormHandler =
            Control.getSingleton().getExtensionLoader().getExtension(ExtensionFormHandler.class);

    private JComboBox<String> valueField;

    protected PopupDialogAddField(Dialog owner, String name, Set<String> values) {
        super(owner);
        getNameTextField().setText(name);
        for (String value : values) {
            getValueField().addItem(value);
        }
        super.getEnabledCheckBox().setSelected(true);
        super.getEnabledCheckBox().setEnabled(false);
        this.pack();
    }

    @Override
    protected void init() {
        // Do nothing
    }

    /*
     * Confirms the fields do not already exist
     */
    @Override
    protected boolean validateFields() {
        String fieldName = getNameTextField().getText().toLowerCase();
        for (String field :
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionFormHandler.class)
                        .getFormHandlerFieldNames()) {
            if (fieldName.equals(field)) {
                super.showNameRepeatedDialog();
                getNameTextField().requestFocusInWindow();
                return false;
            }
        }

        return true;
    }

    /**
     * When the Add button is clicked, create a new field. This field will be created with the name,
     * value and enabled input by the user. The name will always be lower case.
     */
    @Override
    protected void performAction() {
        extFormHandler.addFormHandlerFieldName(
                getNameTextField().getText().toLowerCase(),
                getValueField().getSelectedItem().toString());
    }

    @Override
    protected JComboBox<String> getValueField() {
        if (valueField == null) {
            valueField = new JComboBox<>();
            valueField.setEditable(true);
        }

        return valueField;
    }
}
