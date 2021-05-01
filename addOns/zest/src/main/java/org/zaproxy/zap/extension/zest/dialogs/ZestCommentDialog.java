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
import org.zaproxy.zest.core.v1.ZestComment;
import org.zaproxy.zest.core.v1.ZestStatement;

public class ZestCommentDialog extends StandardFieldsDialog implements ZestDialog {

    private static final String FIELD_COMMENT = "zest.dialog.comment.label.comment";

    private static final long serialVersionUID = 1L;

    private ExtensionZest extension = null;
    private ScriptNode parent = null;
    private ScriptNode child = null;
    private ZestScriptWrapper script = null;
    private ZestStatement stmt = null;
    private ZestComment comment = null;
    private boolean add = false;

    public ZestCommentDialog(ExtensionZest ext, Frame owner, Dimension dim) {
        super(owner, "zest.dialog.action.add.title", dim);
        this.extension = ext;
    }

    public void init(
            ZestScriptWrapper script,
            ScriptNode parent,
            ScriptNode child,
            ZestStatement stmt,
            ZestComment comment,
            boolean add) {
        this.script = script;
        this.add = add;
        this.parent = parent;
        this.child = child;
        this.stmt = stmt;
        this.comment = comment;

        this.removeAllFields();

        if (add) {
            this.setTitle(Constant.messages.getString("zest.dialog.comment.add.title"));
        } else {
            this.setTitle(Constant.messages.getString("zest.dialog.comment.edit.title"));
        }

        this.addMultilineField(FIELD_COMMENT, comment.getComment());
    }

    @Override
    public void save() {
        comment.setComment(this.getStringValue(FIELD_COMMENT));

        if (add) {
            if (stmt == null) {
                extension.addToParent(parent, comment);
            } else {
                extension.addAfterRequest(parent, child, stmt, comment);
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
