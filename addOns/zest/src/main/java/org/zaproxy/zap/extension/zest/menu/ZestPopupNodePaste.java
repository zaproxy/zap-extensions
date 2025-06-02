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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestZapUtils;
import org.zaproxy.zest.core.v1.ZestContainer;
import org.zaproxy.zest.core.v1.ZestElement;
import org.zaproxy.zest.core.v1.ZestStatement;

@SuppressWarnings("serial")
public class ZestPopupNodePaste extends ExtensionPopupMenuItem {

    private static final long serialVersionUID = 1L;

    private static final Logger LOGGER = LogManager.getLogger(ZestPopupNodePaste.class);

    private ExtensionZest extension = null;

    /** */
    public ZestPopupNodePaste(ExtensionZest extension) {
        super();
        this.extension = extension;
        initialize();
    }

    /**
     * @param label
     */
    public ZestPopupNodePaste(String label) {
        super(label);
    }

    /** This method initializes this */
    private void initialize() {
        this.setText(Constant.messages.getString("zest.cnp.paste.popup"));

        this.addActionListener(
                e -> {
                    ScriptNode node = extension.getSelectedZestNode();
                    ZestElement element = ZestZapUtils.getElement(node);
                    if (node != null) {
                        if (element instanceof ZestContainer) {
                            extension.pasteToNode(node);
                        } else {
                            extension.pasteToNode(node.getParent(), node);
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
                    ScriptNode node = extension.getSelectedZestNode();
                    ZestElement element = ZestZapUtils.getElement(node);
                    this.setEnabled(false);

                    if (node == null || node.isRoot() || element == null) {
                        return false;

                    } else if (element instanceof ZestContainer
                            && extension.canPasteNodesTo(node)) {
                        this.setEnabled(true);

                    } else if (element instanceof ZestStatement
                            && extension.canPasteNodesTo(node.getParent())) {
                        this.setEnabled(true);
                    }

                    return true;
                }
            } catch (Exception e) {
                LOGGER.error(e.getMessage(), e);
            }
        }
        return false;
    }

    @Override
    public boolean isSafe() {
        return true;
    }
}
