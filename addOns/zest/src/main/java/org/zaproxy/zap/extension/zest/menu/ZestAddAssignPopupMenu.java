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
import org.zaproxy.zap.extension.httppanel.view.syntaxhighlight.HttpPanelSyntaxHighlightTextArea;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestZapUtils;
import org.zaproxy.zest.core.v1.ZestAssignCalc;
import org.zaproxy.zest.core.v1.ZestAssignFieldValue;
import org.zaproxy.zest.core.v1.ZestAssignFromElement;
import org.zaproxy.zest.core.v1.ZestAssignGlobalVariable;
import org.zaproxy.zest.core.v1.ZestAssignRandomInteger;
import org.zaproxy.zest.core.v1.ZestAssignRegexDelimiters;
import org.zaproxy.zest.core.v1.ZestAssignReplace;
import org.zaproxy.zest.core.v1.ZestAssignString;
import org.zaproxy.zest.core.v1.ZestAssignStringDelimiters;
import org.zaproxy.zest.core.v1.ZestAssignment;
import org.zaproxy.zest.core.v1.ZestConditional;
import org.zaproxy.zest.core.v1.ZestContainer;
import org.zaproxy.zest.core.v1.ZestElement;
import org.zaproxy.zest.core.v1.ZestRequest;
import org.zaproxy.zest.core.v1.ZestStatement;

public class ZestAddAssignPopupMenu extends ExtensionPopupMenuItem {

    private static final long serialVersionUID = 2282358266003940700L;

    private ExtensionZest extension;

    /** This method initializes */
    public ZestAddAssignPopupMenu(ExtensionZest extension) {
        super("AddAssignX");
        this.extension = extension;
    }

    /**/
    @Override
    public String getParentMenuName() {
        return Constant.messages.getString("zest.assign.add.popup");
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
                    if (ze instanceof ZestConditional && ZestZapUtils.getShadowLevel(node) == 0) {
                        return false;
                    }
                    reCreateSubMenu(node, null, null, null);
                } else if (ze instanceof ZestStatement) {
                    reCreateSubMenu(
                            node.getParent(),
                            node,
                            (ZestStatement) ZestZapUtils.getElement(node),
                            null);
                    return true;
                }
            }

        } else if (invoker instanceof HttpPanelSyntaxHighlightTextArea
                && extension.getExtScript().getScriptUI() != null) {
            HttpPanelSyntaxHighlightTextArea panel = (HttpPanelSyntaxHighlightTextArea) invoker;
            ScriptNode node = extension.getExtScript().getScriptUI().getSelectedNode();

            if (node == null || node.isTemplate()) {
                return false;
            } else if (extension.isSelectedMessage(panel.getMessage())
                    && panel.getSelectedText() != null
                    && panel.getSelectedText().length() > 0) {

                if (ZestZapUtils.getElement(node) instanceof ZestRequest) {
                    reCreateSubMenu(
                            node.getParent(),
                            node,
                            (ZestRequest) ZestZapUtils.getElement(node),
                            panel.getSelectedText());
                    return true;
                }
            }
        }

        return false;
    }

    private void reCreateSubMenu(
            ScriptNode parent, ScriptNode child, ZestStatement req, String text) {
        createPopupAddActionMenu(parent, child, req, new ZestAssignString(null, text));
        createPopupAddActionMenu(parent, child, req, new ZestAssignFieldValue());
        createPopupAddActionMenu(parent, child, req, new ZestAssignRegexDelimiters());
        createPopupAddActionMenu(parent, child, req, new ZestAssignStringDelimiters());
        createPopupAddActionMenu(parent, child, req, new ZestAssignRandomInteger());
        createPopupAddActionMenu(
                parent, child, req, new ZestAssignReplace(null, text, null, false, false));
        createPopupAddActionMenu(parent, child, req, new ZestAssignCalc());
        createPopupAddActionMenu(parent, child, req, new ZestAssignFromElement());
        createPopupAddActionMenu(parent, child, req, new ZestAssignGlobalVariable());
    }

    private void createPopupAddActionMenu(
            final ScriptNode parent,
            final ScriptNode child,
            final ZestStatement stmt,
            final ZestAssignment za) {
        ZestPopupMenu menu =
                new ZestPopupMenu(
                        Constant.messages.getString("zest.assign.add.popup"),
                        ZestZapUtils.toUiString(za, false));
        menu.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        extension
                                .getDialogManager()
                                .showZestAssignDialog(parent, child, stmt, za, true);
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
