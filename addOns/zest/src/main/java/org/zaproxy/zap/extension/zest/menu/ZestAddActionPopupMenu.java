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
import java.util.regex.Pattern;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.httppanel.view.syntaxhighlight.HttpPanelSyntaxHighlightTextArea;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestScriptWrapper;
import org.zaproxy.zap.extension.zest.ZestZapUtils;
import org.zaproxy.zest.core.v1.ZestAction;
import org.zaproxy.zest.core.v1.ZestActionFail;
import org.zaproxy.zest.core.v1.ZestActionGlobalVariableRemove;
import org.zaproxy.zest.core.v1.ZestActionGlobalVariableSet;
import org.zaproxy.zest.core.v1.ZestActionIntercept;
import org.zaproxy.zest.core.v1.ZestActionInvoke;
import org.zaproxy.zest.core.v1.ZestActionPrint;
import org.zaproxy.zest.core.v1.ZestActionScan;
import org.zaproxy.zest.core.v1.ZestActionSleep;
import org.zaproxy.zest.core.v1.ZestConditional;
import org.zaproxy.zest.core.v1.ZestContainer;
import org.zaproxy.zest.core.v1.ZestElement;
import org.zaproxy.zest.core.v1.ZestExpression;
import org.zaproxy.zest.core.v1.ZestRequest;
import org.zaproxy.zest.core.v1.ZestScript;
import org.zaproxy.zest.core.v1.ZestStatement;

public class ZestAddActionPopupMenu extends ExtensionPopupMenuItem {

    private static final long serialVersionUID = 2282358266003940700L;

    private ExtensionZest extension;

    /** This method initializes */
    public ZestAddActionPopupMenu(ExtensionZest extension) {
        super("AddActionX");
        this.extension = extension;
    }

    /**/
    @Override
    public String getParentMenuName() {
        return Constant.messages.getString("zest.action.add.popup");
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
                    if (ze instanceof ZestConditional) {
                        if (ZestZapUtils.getShadowLevel(node) == 0) {
                            return false;
                        }
                    }
                    reCreateSubMenu(node, null, null, null);
                    return true;
                } else if (ze instanceof ZestStatement) {
                    reCreateSubMenu(
                            node.getParent(),
                            node,
                            (ZestStatement) ZestZapUtils.getElement(node),
                            null);
                    return true;
                } else if (ze instanceof ZestExpression) {
                    return false;
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
                            Pattern.quote(panel.getSelectedText()));
                    return true;
                }
            }
        }

        return false;
    }

    private void reCreateSubMenu(
            ScriptNode parent, ScriptNode child, ZestStatement stmt, String text) {
        ZestScriptWrapper wrapper = extension.getZestTreeModel().getScriptWrapper(parent);
        ZestScript script = wrapper.getZestScript();
        String type = script.getType();
        if (ZestScript.Type.StandAlone.name().equals(type)
                || ZestScript.Type.Targeted.name().equals(type)) {
            // Doesnt really make sense for passive or active scripts
            createPopupAddActionMenu(parent, child, stmt, new ZestActionScan(text));
        }
        if (!script.isPassive()) {
            createPopupAddActionMenu(parent, child, stmt, new ZestActionInvoke());
        }
        if (ExtensionScript.TYPE_PROXY.equals(wrapper.getType().getName())) {
            createPopupAddActionMenu(parent, child, stmt, new ZestActionIntercept());
        }

        createPopupAddActionMenu(parent, child, stmt, new ZestActionPrint(text));
        createPopupAddActionMenu(parent, child, stmt, new ZestActionFail(text));
        createPopupAddActionMenu(parent, child, stmt, new ZestActionSleep());
        createPopupAddActionMenu(parent, child, stmt, new ZestActionGlobalVariableSet());
        createPopupAddActionMenu(parent, child, stmt, new ZestActionGlobalVariableRemove());
    }

    private void createPopupAddActionMenu(
            final ScriptNode parent,
            final ScriptNode child,
            final ZestStatement stmt,
            final ZestAction za) {
        ZestPopupMenu menu =
                new ZestPopupMenu(
                        Constant.messages.getString("zest.action.add.popup"),
                        ZestZapUtils.toUiString(za, false));
        menu.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        if (za instanceof ZestActionIntercept) {
                            // No params so can just add straight away
                            if (stmt == null) {
                                extension.addToParent(parent, za);
                            } else {
                                extension.addAfterRequest(parent, child, stmt, za);
                            }
                        } else {
                            extension
                                    .getDialogManager()
                                    .showZestActionDialog(parent, child, stmt, za, true);
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
