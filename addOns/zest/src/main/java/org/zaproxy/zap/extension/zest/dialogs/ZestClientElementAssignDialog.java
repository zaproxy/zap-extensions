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
package org.zaproxy.zap.extension.zest.dialogs;

import java.awt.Dimension;
import java.awt.Frame;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestScriptWrapper;
import org.zaproxy.zap.extension.zest.ZestZapUtils;
import org.zaproxy.zest.core.v1.ZestClientElement;
import org.zaproxy.zest.core.v1.ZestClientElementAssign;
import org.zaproxy.zest.core.v1.ZestStatement;

public class ZestClientElementAssignDialog extends ZestClientElementDialog {

    private static final String FIELD_VARIABLE = "zest.dialog.assign.label.variable";
    private static final long serialVersionUID = 1L;

    public ZestClientElementAssignDialog(ExtensionZest ext, Frame owner, Dimension dim) {
        super(ext, owner, "zest.dialog.clientElementAssign.add.title", dim);
    }

    @Override
    public void init(
            ZestScriptWrapper script,
            ScriptNode parent,
            ScriptNode child,
            ZestStatement req,
            ZestClientElement client,
            boolean add) {
        super.init(script, parent, child, req, client, add);

        this.addTextField(
                FIELD_ATTRIBUTE, ((ZestClientElementAssign) this.getClient()).getAttribute());
        this.addTextField(
                FIELD_VARIABLE, ((ZestClientElementAssign) this.getClient()).getVariableName());

        if (add) {
            this.setTitle(Constant.messages.getString("zest.dialog.clientElementAssign.add.title"));
        } else {
            this.setTitle(
                    Constant.messages.getString("zest.dialog.clientElementAssign.edit.title"));
        }
        setFieldMainPopupMenu(FIELD_ATTRIBUTE);
    }

    @Override
    public void saveFields() {
        ((ZestClientElementAssign) this.getClient())
                .setAttribute(this.getStringValue(FIELD_ATTRIBUTE));
        ((ZestClientElementAssign) this.getClient())
                .setVariableName(this.getStringValue(FIELD_VARIABLE));
    }

    @Override
    public String validateFields() {
        if (!ZestZapUtils.isValidVariableName(this.getStringValue(FIELD_VARIABLE))
                && !getScript()
                        .getZestScript()
                        .getVariableNames()
                        .contains(this.getStringValue(FIELD_VARIABLE))) {
            return Constant.messages.getString("zest.dialog.assign.error.variable");
        }
        return super.validateFields();
    }
}
