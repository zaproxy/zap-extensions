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
import org.zaproxy.zap.view.StandardFieldsDialog;
import org.zaproxy.zest.core.v1.ZestClientWindowHandle;
import org.zaproxy.zest.core.v1.ZestStatement;

public class ZestClientWindowHandleDialog extends StandardFieldsDialog implements ZestDialog {

    private static final String FIELD_WINDOW_HANDLE = "zest.dialog.client.label.windowHandle";
    private static final String FIELD_URL = "zest.dialog.client.label.url";
    private static final String FIELD_REGEX = "zest.dialog.client.label.regex";

    private static final long serialVersionUID = 1L;

    private ExtensionZest extension = null;
    private ScriptNode parent = null;
    private ScriptNode child = null;
    private ZestScriptWrapper script = null;
    private ZestStatement request = null;
    private ZestClientWindowHandle client = null;
    private boolean add = false;

    public ZestClientWindowHandleDialog(ExtensionZest ext, Frame owner, Dimension dim) {
        super(owner, "zest.dialog.clientWindowHandle.add.title", dim);
        this.extension = ext;
    }

    public void init(
            ZestScriptWrapper script,
            ScriptNode parent,
            ScriptNode child,
            ZestStatement req,
            ZestClientWindowHandle client,
            boolean add) {
        this.script = script;
        this.add = add;
        this.parent = parent;
        this.child = child;
        this.request = req;
        this.client = client;

        this.removeAllFields();

        if (add) {
            this.setTitle(Constant.messages.getString("zest.dialog.clientWindowHandle.add.title"));
        } else {
            this.setTitle(Constant.messages.getString("zest.dialog.clientWindowHandle.edit.title"));
        }

        this.addTextField(FIELD_WINDOW_HANDLE, client.getWindowHandle());
        this.addTextField(FIELD_URL, client.getUrl());
        this.addCheckBoxField(FIELD_REGEX, client.isRegex());

        setFieldMainPopupMenu(FIELD_URL);
    }

    @Override
    public void save() {
        client.setWindowHandle(this.getStringValue(FIELD_WINDOW_HANDLE));
        client.setUrl(this.getStringValue(FIELD_URL));
        client.setRegex(this.getBoolValue(FIELD_REGEX));

        if (add) {
            if (request == null) {
                extension.addToParent(parent, client);
            } else {
                extension.addAfterRequest(parent, child, request, client);
            }
        } else {
            extension.updated(child);
            extension.display(child, false);
        }
    }

    @Override
    public String validateFields() {
        if (!ZestZapUtils.isValidVariableName(this.getStringValue(FIELD_WINDOW_HANDLE))) {
            return Constant.messages.getString("zest.dialog.client.error.windowHandle");
        }
        return null;
    }

    @Override
    public ZestScriptWrapper getScript() {
        return this.script;
    }
}
