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
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestZapUtils;
import org.zaproxy.zest.core.v1.ZestContainer;
import org.zaproxy.zest.core.v1.ZestControl;
import org.zaproxy.zest.core.v1.ZestControlLoopBreak;
import org.zaproxy.zest.core.v1.ZestControlLoopNext;
import org.zaproxy.zest.core.v1.ZestControlReturn;
import org.zaproxy.zest.core.v1.ZestElement;
import org.zaproxy.zest.core.v1.ZestLoop;
import org.zaproxy.zest.core.v1.ZestRequest;
import org.zaproxy.zest.core.v1.ZestScript;

public class ZestAddControlPopupMenu extends ExtensionPopupMenuItem {

    private static final long serialVersionUID = 2282358266003940700L;

    private ExtensionZest extension;

    /** This method initializes */
    public ZestAddControlPopupMenu(ExtensionZest extension) {
        super("AddControlX");
        this.extension = extension;
    }

    /**/
    @Override
    public String getParentMenuName() {
        return Constant.messages.getString("zest.control.add.popup");
    }

    @Override
    public boolean isSubMenu() {
        return true;
    }

    @Override
    public boolean isDummyItem() {
        return true;
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
                    reCreateSubMenu(node, null, null, null);
                    return true;
                }
            }
        }

        return false;
    }

    private boolean isInLoop(ScriptNode node) {
        if (ZestZapUtils.getElement(node) instanceof ZestLoop) {
            return true;
        }
        if (ZestZapUtils.getElement(node) instanceof ZestScript) {
            // Got to the top level
            return false;
        }
        if (node.getParent() != null) {
            return this.isInLoop(node.getParent());
        }
        return false;
    }

    private boolean hasControl(ScriptNode node) {
        for (int i = 0; i < node.getChildCount(); i++) {
            if (ZestZapUtils.getElement((ScriptNode) node.getChildAt(i)) instanceof ZestControl) {
                return true;
            }
        }
        return false;
    }

    private void reCreateSubMenu(
            ScriptNode parent, ScriptNode child, ZestRequest req, String text) {

        if (hasControl(parent)) {
            // Only makes sense to have one control element per container
            return;
        }

        createPopupAddControlMenu(parent, child, req, new ZestControlReturn(text));
        if (this.isInLoop(parent)) {
            createPopupAddControlMenu(parent, child, req, new ZestControlLoopBreak());
            createPopupAddControlMenu(parent, child, req, new ZestControlLoopNext());
        }
    }

    private void createPopupAddControlMenu(
            final ScriptNode parent,
            final ScriptNode child,
            final ZestRequest req,
            final ZestControl za) {
        ZestPopupMenu menu =
                new ZestPopupMenu(
                        Constant.messages.getString("zest.control.add.popup"),
                        ZestZapUtils.toUiString(za, false));
        menu.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        if (za instanceof ZestControlReturn) {
                            extension
                                    .getDialogManager()
                                    .showZestControlDialog(parent, child, req, za, true);
                        } else {
                            // The other controls dont have anything to edit, so just add them
                            // straight in.
                            extension.addToParent(parent, za);
                        }
                    }
                });
        menu.setMenuIndex(this.getMenuIndex());
        View.getSingleton().getPopupList().add(menu);
    }

    @Override
    public boolean isSafe() {
        return true;
    }
}
