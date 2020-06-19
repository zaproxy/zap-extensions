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
import org.mozilla.zest.core.v1.ZestClientElement;
import org.mozilla.zest.core.v1.ZestClientElementSendKeys;
import org.mozilla.zest.core.v1.ZestStatement;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestScriptWrapper;

public class ZestClientElementSendKeysDialog extends ZestClientElementDialog {

    private static final String FIELD_VALUE = "zest.dialog.client.label.value";

    private static final long serialVersionUID = 1L;

    public ZestClientElementSendKeysDialog(ExtensionZest ext, Frame owner, Dimension dim) {
        super(ext, owner, "zest.dialog.clientElementSendKeys.add.title", dim);
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

        this.addTextField(FIELD_VALUE, ((ZestClientElementSendKeys) client).getValue());

        if (add) {
            this.setTitle(
                    Constant.messages.getString("zest.dialog.clientElementSendKeys.add.title"));
        } else {
            this.setTitle(
                    Constant.messages.getString("zest.dialog.clientElementSendKeys.edit.title"));
        }

        setFieldMainPopupMenu(FIELD_VALUE);
    }

    @Override
    public void saveFields() {
        ((ZestClientElementSendKeys) this.getClient()).setValue(this.getStringValue(FIELD_VALUE));
    }

    @Override
    public String validateFields() {
        return super.validateFields();
    }
}
