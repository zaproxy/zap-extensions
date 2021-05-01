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
import java.util.LinkedList;
import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestZapUtils;
import org.zaproxy.zest.core.v1.ZestConditional;
import org.zaproxy.zest.core.v1.ZestElement;
import org.zaproxy.zest.core.v1.ZestExpression;
import org.zaproxy.zest.core.v1.ZestExpressionAnd;
import org.zaproxy.zest.core.v1.ZestExpressionClientElementExists;
import org.zaproxy.zest.core.v1.ZestExpressionEquals;
import org.zaproxy.zest.core.v1.ZestExpressionIsInteger;
import org.zaproxy.zest.core.v1.ZestExpressionLength;
import org.zaproxy.zest.core.v1.ZestExpressionOr;
import org.zaproxy.zest.core.v1.ZestExpressionRegex;
import org.zaproxy.zest.core.v1.ZestExpressionResponseTime;
import org.zaproxy.zest.core.v1.ZestExpressionStatusCode;
import org.zaproxy.zest.core.v1.ZestExpressionURL;
import org.zaproxy.zest.core.v1.ZestRequest;
import org.zaproxy.zest.core.v1.ZestStatement;
import org.zaproxy.zest.core.v1.ZestStructuredExpression;
import org.zaproxy.zest.core.v1.ZestVariables;

public class ZestAddExpressionPopupMenu extends ExtensionPopupMenuItem {

    private static final long serialVersionUID = -2858088231126854392L;

    private ExtensionZest extension;

    public ZestAddExpressionPopupMenu(ExtensionZest extension) {
        super("AddExpressionX");
        this.extension = extension;
    }

    /**/
    @Override
    public String getParentMenuName() {
        return Constant.messages.getString("zest.condition.add.popup");
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

            if (node != null) {
                if (ze instanceof ZestRequest) {
                    return false;
                }
                if (ze instanceof ZestConditional && ZestZapUtils.getShadowLevel(node) == 0) {
                    ZestExpression expr =
                            (ZestExpression) ((ZestConditional) ze).getRootExpression();
                    if (expr == null) {
                        reCreateSubMenu(node, null, null, ZestVariables.RESPONSE_BODY, "");
                    } else {
                        return false;
                    }
                }
                if (ze instanceof ZestStructuredExpression) {
                    reCreateSubMenu(node, null, null, ZestVariables.RESPONSE_BODY, "");
                    return true;
                }
            }
        }
        return false;
    }

    protected void reCreateSubMenu(
            ScriptNode parent, ScriptNode child, ZestStatement stmt, String loc, String text) {
        createPopupAddExprMenu(parent, child, stmt, new ZestExpressionRegex(loc, text));
        createPopupAddExprMenu(parent, child, stmt, new ZestExpressionEquals(loc, text));
        createPopupAddExprMenu(parent, child, stmt, new ZestExpressionLength());
        createPopupAddExprMenu(parent, child, stmt, new ZestExpressionIsInteger());
        createPopupAddExprMenu(parent, child, stmt, new ZestExpressionStatusCode());
        createPopupAddExprMenu(parent, child, stmt, new ZestExpressionResponseTime());
        createPopupAddExprMenu(parent, child, stmt, new ZestExpressionURL());
        createPopupAddExprMenu(parent, child, stmt, new ZestExpressionClientElementExists());
        createPopupAddExprMenu(parent, child, stmt, new ZestExpressionOr(), true);
        createPopupAddExprMenu(parent, child, stmt, new ZestExpressionAnd(), true);
    }

    private void createPopupAddExprMenu(
            final ScriptNode parent,
            ScriptNode child,
            final ZestStatement stmt,
            final ZestStructuredExpression exp,
            boolean empty) {
        if (!empty) {
            createPopupAddExprMenu(parent, child, stmt, exp);
        } else {
            final List<ScriptNode> nodes = new LinkedList<>();
            nodes.add(child);
            ZestPopupMenu menu;
            menu =
                    new ZestPopupMenu(
                            Constant.messages.getString("zest.expression.add.popup"),
                            ZestZapUtils.toUiString(exp, false));
            menu.addActionListener(
                    new ActionListener() {

                        @Override
                        public void actionPerformed(ActionEvent arg0) {
                            // add a new empty structures expression node (no dialog needed)
                            extension.addToParent(extension.getSelectedZestNode(), exp);
                        }
                    });
            menu.setMenuIndex(this.getMenuIndex());
            View.getSingleton().getPopupList().add(menu);
        }
    }

    private void createPopupAddExprMenu(
            final ScriptNode parent,
            ScriptNode child,
            final ZestStatement stmt,
            final ZestExpression ze) {
        final List<ScriptNode> nodes = new LinkedList<>();
        nodes.add(child);
        ZestPopupMenu menu;
        /*if (ze instanceof ZestStructuredExpression) {
        	menu = new ZestPopupMenu(
        			Constant.messages.getString("zest.expression.add.popup"),
        			Constant.messages
        					.getString("zest.element.expression.structured"));
        } else {TODO line 162*/
        menu =
                new ZestPopupMenu(
                        Constant.messages.getString("zest.expression.add.popup"),
                        ZestZapUtils.toUiString(ze, false));
        //		}
        menu.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        extension
                                .getDialogManager()
                                .showZestExpressionDialog(
                                        parent, nodes, stmt, ze, true, false, false);
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
