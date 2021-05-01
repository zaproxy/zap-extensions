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
package org.zaproxy.zap.extension.zest.menu;

import java.awt.Component;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zest.core.v1.ZestComment;
import org.zaproxy.zest.core.v1.ZestContainer;
import org.zaproxy.zest.core.v1.ZestElement;
import org.zaproxy.zest.core.v1.ZestStatement;

/** ZAP: New Popup Menu Alert Delete */
public class ZestAddCommentPopupMenu extends ExtensionPopupMenuItem {

    private static final long serialVersionUID = 1L;

    private ExtensionZest extension = null;
    private ScriptNode parent = null;
    private ScriptNode child = null;
    private ZestStatement stmt = null;

    /** */
    public ZestAddCommentPopupMenu(ExtensionZest extension) {
        super();
        this.extension = extension;
        initialize();
    }

    /** @param label */
    public ZestAddCommentPopupMenu(String label) {
        super(label);
    }

    /** This method initializes this */
    private void initialize() {
        this.setText(Constant.messages.getString("zest.comment.popup"));

        this.addActionListener(
                new java.awt.event.ActionListener() {

                    @Override
                    public void actionPerformed(java.awt.event.ActionEvent e) {
                        extension
                                .getDialogManager()
                                .showZestCommentDialog(
                                        parent, child, stmt, new ZestComment(), true);
                    }
                });
    }

    @Override
    public boolean isEnableForComponent(Component invoker) {
        if (extension.isScriptTree(invoker)) {
            ScriptNode node = extension.getSelectedZestNode();
            ZestElement ze = extension.getSelectedZestElement();
            if (node == null || node.isTemplate()) {
                return false;
            } else if (ze != null) {
                if (ze instanceof ZestContainer) {
                    parent = node;
                    child = null;
                    stmt = null;
                    return true;
                } else if (ze instanceof ZestStatement) {
                    parent = node.getParent();
                    child = node;
                    stmt = (ZestStatement) ze;
                    return true;
                }
            }
        }
        return false;
    }

    @Override
    public boolean isSafe() {
        return true;
    }
}
