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
import java.util.ArrayList;
import java.util.List;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestZapUtils;
import org.zaproxy.zest.core.v1.ZestScript;
import org.zaproxy.zest.core.v1.ZestStatement;

/** ZAP: New Popup Menu Alert Delete */
public class ZestPopupNodeCopyOrCut extends ExtensionPopupMenuItem {

    private static final long serialVersionUID = 1L;

    private static final Logger logger = Logger.getLogger(ZestPopupNodeCopyOrCut.class);

    private ExtensionZest extension = null;
    private boolean cut;

    /** */
    public ZestPopupNodeCopyOrCut(ExtensionZest extension, boolean cut) {
        super();
        this.extension = extension;
        this.cut = cut;
        initialize();
    }

    /** @param label */
    public ZestPopupNodeCopyOrCut(String label) {
        super(label);
    }

    /** This method initializes this */
    private void initialize() {
        if (cut) {
            this.setText(Constant.messages.getString("zest.cnp.cut.popup"));
        } else {
            this.setText(Constant.messages.getString("zest.cnp.copy.popup"));
        }

        this.addActionListener(
                new java.awt.event.ActionListener() {
                    @Override
                    public void actionPerformed(java.awt.event.ActionEvent e) {
                        List<ScriptNode> nodes = new ArrayList<ScriptNode>();
                        for (ScriptNode node : extension.getSelectedZestNodes()) {
                            if (ZestZapUtils.getElement(node) instanceof ZestStatement) {
                                nodes.add(node);
                            }
                        }
                        extension.setCnpNodes(nodes);
                        extension.setCut(cut);
                    }
                });
    }

    @Override
    public boolean isEnableForComponent(Component invoker) {
        if (extension.isScriptTree(invoker)) {
            try {
                List<ScriptNode> selectedNodes = extension.getSelectedZestNodes();
                if (selectedNodes.isEmpty()) {
                    return false;
                }

                this.setEnabled(false);
                for (ScriptNode node : selectedNodes) {
                    if (node == null || node.isRoot() || node.isTemplate()) {
                        this.setEnabled(false);
                        return false;
                    } else if ((ZestZapUtils.getElement(node) instanceof ZestScript)) {
                        // Cant copy the whole script
                        this.setEnabled(false);
                        return false;
                    } else if (ZestZapUtils.getShadowLevel(node) > 0) {
                        // Ignore these
                    } else if (!(ZestZapUtils.getElement(node) instanceof ZestStatement)) {
                        // Cant copy these
                        this.setEnabled(false);
                        break;
                    } else {
                        this.setEnabled(true);
                    }
                }

                return true;
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
