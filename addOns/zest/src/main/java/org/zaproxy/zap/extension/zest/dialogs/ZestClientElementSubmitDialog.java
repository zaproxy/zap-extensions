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
import org.mozilla.zest.core.v1.ZestStatement;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestScriptWrapper;

public class ZestClientElementSubmitDialog extends ZestClientElementDialog {

    private static final long serialVersionUID = 1L;

    public ZestClientElementSubmitDialog(ExtensionZest ext, Frame owner, Dimension dim) {
        super(ext, owner, "zest.dialog.clientElementSubmit.add.title", dim);
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

        if (add) {
            this.setTitle(Constant.messages.getString("zest.dialog.clientElementSubmit.add.title"));
        } else {
            this.setTitle(
                    Constant.messages.getString("zest.dialog.clientElementSubmit.edit.title"));
        }
    }

    @Override
    public void saveFields() {
        // Nothing extra to do
    }

    @Override
    public String validateFields() {
        // Nothing extra to do
        return super.validateFields();
    }
}
