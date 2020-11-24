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
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestZapUtils;
import org.zaproxy.zest.core.v1.ZestConditional;
import org.zaproxy.zest.core.v1.ZestContainer;
import org.zaproxy.zest.core.v1.ZestElement;
import org.zaproxy.zest.core.v1.ZestLoop;
import org.zaproxy.zest.core.v1.ZestLoopClientElements;
import org.zaproxy.zest.core.v1.ZestLoopFile;
import org.zaproxy.zest.core.v1.ZestLoopInteger;
import org.zaproxy.zest.core.v1.ZestLoopRegex;
import org.zaproxy.zest.core.v1.ZestLoopString;
import org.zaproxy.zest.core.v1.ZestStatement;

public class ZestAddLoopPopupMenu extends ExtensionPopupMenuItem {

    private static final long serialVersionUID = -8433923894855139684L;

    private ExtensionZest extension;

    private static final Logger logger = Logger.getLogger(ZestAddConditionPopupMenu.class);

    /** This method initializes */
    public ZestAddLoopPopupMenu(ExtensionZest extension) {
        super("AddLoopX");
        this.extension = extension;
    }

    /**/
    @Override
    public String getParentMenuName() {
        return Constant.messages.getString("zest.loop.add.popup");
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

            if (node != null && !node.isTemplate()) {
                if (ze instanceof ZestContainer) {
                    if (ze instanceof ZestConditional && ZestZapUtils.getShadowLevel(node) == 0) {
                        return false;
                    }
                    reCreateSubMenu(node, null, null);
                    return true;
                } else if (ze instanceof ZestStatement) {
                    reCreateSubMenu(node.getParent(), node, (ZestStatement) ze);
                    return true;
                }
            }
        }
        return false;
    }

    private void reCreateSubMenu(ScriptNode parent, ScriptNode child, ZestStatement stmt) {
        List<ScriptNode> children = new LinkedList<>();
        children.add(child);
        createPopupAddActionMenu(parent, children, stmt, new ZestLoopString());
        try {
            createPopupAddActionMenu(parent, children, stmt, new ZestLoopFile());
        } catch (IOException e) {
            logger.debug(e.getMessage(), e);
        }
        createPopupAddActionMenu(parent, children, stmt, new ZestLoopInteger());
        createPopupAddActionMenu(parent, children, stmt, new ZestLoopClientElements());
        createPopupAddActionMenu(parent, children, stmt, new ZestLoopRegex());
    }

    private void createPopupAddActionMenu(
            final ScriptNode parent,
            final List<ScriptNode> children,
            final ZestStatement stmt,
            final ZestLoop<?> za) {
        ZestPopupMenu menu =
                new ZestPopupMenu(
                        Constant.messages.getString("zest.loop.add.popup"),
                        ZestZapUtils.toUiString(za, false));
        menu.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        extension
                                .getDialogManager()
                                .showZestLoopDialog(parent, children, stmt, za, true, false);
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
