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
import javax.swing.JTree;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestZapUtils;
import org.zaproxy.zest.core.v1.ZestControl;
import org.zaproxy.zest.core.v1.ZestScript;
import org.zaproxy.zest.core.v1.ZestStatement;

/** ZAP: New Popup Menu Alert Delete */
public class ZestPopupZestMove extends ExtensionPopupMenuItem {

    private static final long serialVersionUID = 1L;

    private static final Logger logger = Logger.getLogger(ZestPopupZestMove.class);

    private ExtensionZest extension = null;
    private boolean up;

    /** */
    public ZestPopupZestMove(ExtensionZest extension, boolean up) {
        super();
        this.extension = extension;
        this.up = up;
        initialize();
    }

    /** @param label */
    public ZestPopupZestMove(String label) {
        super(label);
    }

    /** This method initializes this */
    private void initialize() {
        if (up) {
            this.setText(Constant.messages.getString("zest.move.up.popup"));
        } else {
            this.setText(Constant.messages.getString("zest.move.down.popup"));
        }

        this.addActionListener(
                new java.awt.event.ActionListener() {
                    @Override
                    public void actionPerformed(java.awt.event.ActionEvent e) {
                        for (ScriptNode node : extension.getSelectedZestNodes()) {
                            if (up) {
                                extension.moveNodeUp(node);
                            } else {
                                extension.moveNodeDown(node);
                            }
                        }
                    }
                });
    }

    @Override
    public boolean isEnableForComponent(Component invoker) {
        if (extension.isScriptTree(invoker)) {
            try {
                JTree tree = (JTree) invoker;
                if (tree.getLastSelectedPathComponent() != null) {
                    if (tree.getSelectionPaths().length != 1) {
                        // Start by just supporting one at a time..
                        return false;
                    }
                    ScriptNode node = extension.getExtScript().getScriptUI().getSelectedNode();
                    this.setEnabled(false);

                    if (node == null || node.isRoot() || ZestZapUtils.getElement(node) == null) {
                        return false;
                    } else if ((ZestZapUtils.getElement(node) instanceof ZestScript)) {
                        return false;
                    } else if (ZestZapUtils.getShadowLevel(node) > 0) {
                        // Cant move these
                        /* TODO
                        } else if ((ZestZapUtils.getElement(node) instanceof ZestControl)) {
                        	return false;
                        } else if (ZestTreeElement.isSubclass(node.getZestElement(), ZestTreeElement.Type.COMMON_TESTS)) {
                        	// Cantmove these either
                        	 */
                    } else if (up) {
                        ScriptNode prev = (ScriptNode) node.getPreviousSibling();
                        while (prev != null && ZestZapUtils.getShadowLevel(prev) > 0) {
                            prev = (ScriptNode) prev.getPreviousSibling();
                        }
                        if (prev != null) {
                            if (ZestZapUtils.getElement(node)
                                            .isSameSubclass(ZestZapUtils.getElement(prev))
                                    || (ZestZapUtils.getElement(node) instanceof ZestStatement
                                            && ZestZapUtils.getElement(prev)
                                                    instanceof ZestStatement)) {
                                this.setEnabled(true);
                            }
                        }
                    } else {
                        // Down
                        ScriptNode next = (ScriptNode) node.getNextSibling();
                        while (next != null && ZestZapUtils.getShadowLevel(next) > 0) {
                            next = (ScriptNode) next.getNextSibling();
                        }
                        if (next != null) {
                            if (!(ZestZapUtils.getElement(next) instanceof ZestControl)
                                    && (ZestZapUtils.getElement(node)
                                                    .isSameSubclass(ZestZapUtils.getElement(next))
                                            || (ZestZapUtils.getElement(node)
                                                            instanceof ZestStatement
                                                    && ZestZapUtils.getElement(next)
                                                            instanceof ZestStatement))) {
                                this.setEnabled(true);
                            }
                        }
                    }

                    return true;
                }
            } catch (Exception e) {
                logger.error(e.getMessage(), e);
            }
        }
        return false;
    }

    @Override
    public boolean isSafe() {
        return true;
    }
}
