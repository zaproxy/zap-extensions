/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.zest.dialogs;

import java.awt.Dimension;
import java.awt.Window;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.zest.ZestScriptWrapper;
import org.zaproxy.zap.extension.zest.ZestZapUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class ZestParameterDialog extends StandardFieldsDialog implements ZestDialog {

    private static final String FIELD_PARAM_NAME = "zest.dialog.param.label.name";
    private static final String FIELD_PARAM_VALUE = "zest.dialog.param.label.value";

    private static final long serialVersionUID = 1L;

    private ZestScriptWrapper script = null;
    private ScriptTokensTableModel model = null;
    private boolean add = true;
    private int index = -1;

    public ZestParameterDialog(ScriptTokensTableModel model, Window owner, Dimension dim) {
        super(owner, "zest.dialog.param.add.title", dim);
        this.model = model;
    }

    public void init(
            ZestScriptWrapper script,
            String name,
            String value,
            boolean add,
            int index,
            boolean canBeEmpty) {
        this.script = script;
        this.add = add;
        this.index = index;
        if (add) {
            this.setTitle(Constant.messages.getString("zest.dialog.param.add.title"));
        } else {
            this.setTitle(Constant.messages.getString("zest.dialog.param.edit.title"));
        }

        this.removeAllFields();

        this.addTextField(FIELD_PARAM_NAME, name);
        this.addTextField(FIELD_PARAM_VALUE, value);
        this.addPadding();

        setFieldMainPopupMenu(FIELD_PARAM_NAME);
        setFieldMainPopupMenu(FIELD_PARAM_VALUE);
    }

    @Override
    public void save() {
        if (add) {
            this.model.add(
                    this.getStringValue(FIELD_PARAM_NAME), this.getStringValue(FIELD_PARAM_VALUE));
        } else {
            this.model.replace(
                    this.index,
                    this.getStringValue(FIELD_PARAM_NAME),
                    this.getStringValue(FIELD_PARAM_VALUE));
        }
    }

    @Override
    public String validateFields() {

        if (!ZestZapUtils.isValidVariableName(this.getStringValue(FIELD_PARAM_NAME))) {
            return Constant.messages.getString("zest.dialog.param.error.name");
        }
        return null;
    }

    @Override
    public ZestScriptWrapper getScript() {
        return this.script;
    }
}
