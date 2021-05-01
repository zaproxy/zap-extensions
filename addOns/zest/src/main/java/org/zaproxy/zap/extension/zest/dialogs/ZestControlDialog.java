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
import java.awt.Frame;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestScriptWrapper;
import org.zaproxy.zap.view.StandardFieldsDialog;
import org.zaproxy.zest.core.v1.ZestControl;
import org.zaproxy.zest.core.v1.ZestControlReturn;
import org.zaproxy.zest.core.v1.ZestRequest;
import org.zaproxy.zest.core.v1.ZestStatement;

public class ZestControlDialog extends StandardFieldsDialog implements ZestDialog {

    private static final String FIELD_VALUE = "zest.dialog.return.label.value";

    private static final long serialVersionUID = 1L;

    private ExtensionZest extension = null;
    private ScriptNode parent = null;
    private ScriptNode child = null;
    private ZestScriptWrapper script = null;
    private ZestStatement request = null;
    private ZestControl control = null;
    private boolean add = false;

    public ZestControlDialog(ExtensionZest ext, Frame owner, Dimension dim) {
        super(owner, "zest.dialog.action.add.title", dim);
        this.extension = ext;
    }

    public void init(
            ZestScriptWrapper script,
            ScriptNode parent,
            ScriptNode child,
            ZestRequest req,
            ZestControl control,
            boolean add) {
        this.script = script;
        this.add = add;
        this.parent = parent;
        this.child = child;
        this.request = req;
        this.control = control;

        this.removeAllFields();

        if (add) {
            this.setTitle(Constant.messages.getString("zest.dialog.return.add.title"));
        } else {
            this.setTitle(Constant.messages.getString("zest.dialog.return.edit.title"));
        }

        if (control instanceof ZestControlReturn) {
            ZestControlReturn za = (ZestControlReturn) control;
            this.addTextField(FIELD_VALUE, za.getValue());
            setFieldMainPopupMenu(FIELD_VALUE);
        }
        this.addPadding();
    }

    @Override
    public void save() {
        if (control instanceof ZestControlReturn) {
            ZestControlReturn za = (ZestControlReturn) control;
            za.setValue(this.getStringValue(FIELD_VALUE));
        }

        if (add) {
            if (request == null) {
                extension.addToParent(parent, control);
            } else {
                extension.addAfterRequest(parent, child, request, control);
            }
        } else {
            extension.updated(child);
            extension.display(child, false);
        }
    }

    @Override
    public String validateFields() {
        // Nothing to do
        return null;
    }

    @Override
    public ZestScriptWrapper getScript() {
        return this.script;
    }
}
