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
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestZapUtils;
import org.zaproxy.zest.core.v1.ZestAssertion;
import org.zaproxy.zest.core.v1.ZestElement;
import org.zaproxy.zest.core.v1.ZestExpressionLength;
import org.zaproxy.zest.core.v1.ZestExpressionRegex;
import org.zaproxy.zest.core.v1.ZestExpressionStatusCode;
import org.zaproxy.zest.core.v1.ZestRequest;
import org.zaproxy.zest.core.v1.ZestVariables;

public class ZestAddAssertionPopupMenu extends ExtensionPopupMenuItem {

    private static final long serialVersionUID = 2282358266003940700L;

    private ExtensionZest extension;

    /** This method initializes */
    public ZestAddAssertionPopupMenu(ExtensionZest extension) {
        super("AddAssertX");
        this.extension = extension;
    }

    /**/
    @Override
    public String getParentMenuName() {
        return Constant.messages.getString("zest.assert.add.popup");
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
        String var = ZestVariables.RESPONSE_BODY;
        if (extension.isScriptTree(invoker)) {
            ScriptNode node = extension.getSelectedZestNode();
            ZestElement ze = extension.getSelectedZestElement();
            if (node == null || node.isTemplate()) {
                return false;
            } else if (ze != null && ze instanceof ZestRequest) {
                reCreateSubMenu(node, (ZestRequest) ZestZapUtils.getElement(node), var, null);
                return true;
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
                    ZestRequest req = (ZestRequest) ZestZapUtils.getElement(node);
                    if (req.getResponse() != null
                            && req.getResponse().getHeaders() != null
                            && req.getResponse().getHeaders().indexOf(panel.getSelectedText())
                                    >= 0) {
                        var = ZestVariables.RESPONSE_HEADER;
                    }

                    reCreateSubMenu(node, req, var, Pattern.quote(panel.getSelectedText()));
                    return true;
                }
            }
        }
        return false;
    }

    private void reCreateSubMenu(ScriptNode parent, ZestRequest req, String variable, String text) {
        boolean incStatusCode = true;
        for (ZestAssertion za : req.getAssertions()) {
            if (za.getRootExpression() instanceof ZestExpressionStatusCode) {
                incStatusCode = false;
            }
        }
        // Only makes sence to have one of each of these
        if (incStatusCode) {
            createPopupAddAssertionMenu(parent, new ZestAssertion(new ZestExpressionStatusCode()));
        }
        // Can be any number of these
        createPopupAddAssertionMenu(parent, new ZestAssertion(new ZestExpressionLength()));
        createPopupAddAssertionMenu(
                parent, new ZestAssertion(new ZestExpressionRegex(variable, text)));
    }

    private void createPopupAddAssertionMenu(final ScriptNode req, final ZestAssertion za2) {
        ZestPopupMenu menu =
                new ZestPopupMenu(
                        Constant.messages.getString("zest.assert.add.popup"),
                        ZestZapUtils.toUiString(za2, false));
        menu.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        extension.getDialogManager().showZestAssertionDialog(req, null, za2, true);
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
