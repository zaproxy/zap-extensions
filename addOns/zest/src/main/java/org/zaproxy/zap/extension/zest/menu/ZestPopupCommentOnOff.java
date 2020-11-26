/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
public class ZestPopupCommentOnOff extends ExtensionPopupMenuItem {

    private static final long serialVersionUID = 1L;

    private static final Logger logger = Logger.getLogger(ZestPopupCommentOnOff.class);

    private ExtensionZest extension = null;
    private boolean comment = false;

    /** */
    public ZestPopupCommentOnOff(ExtensionZest extension) {
        super();
        this.extension = extension;
        initialize();
    }

    /** @param label */
    public ZestPopupCommentOnOff(String label) {
        super(label);
    }

    /** This method initializes this */
    private void initialize() {
        /*
        if (cut) {
        	this.setText(Constant.messages.getString("zest.cnp.cut.popup"));
        } else {
        	this.setText(Constant.messages.getString("zest.cnp.copy.popup"));
        }
        */

        this.addActionListener(
                new java.awt.event.ActionListener() {
                    @Override
                    public void actionPerformed(java.awt.event.ActionEvent e) {
                        for (ScriptNode node : extension.getSelectedZestNodes()) {
                            if (ZestZapUtils.getElement(node) instanceof ZestStatement) {
                                extension.setEnabled(node, comment);
                            }
                        }
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
                // If we have a mix of commented and uncommented statements then default to
                // commenting
                this.comment = true;
                for (ScriptNode node : selectedNodes) {
                    if (node == null || node.isRoot() || node.isTemplate()) {
                        this.setEnabled(false);
                        return false;
                    } else if ((ZestZapUtils.getElement(node) instanceof ZestScript)) {
                        // Cant comment the whole script
                        this.setEnabled(false);
                        return false;
                    } else if (ZestZapUtils.getShadowLevel(node) > 0) {
                        // Ignore these
                    } else if (!(ZestZapUtils.getElement(node) instanceof ZestStatement)) {
                        // Cant comment these
                        this.setEnabled(false);
                        break;
                    } else {
                        if (((ZestStatement) ZestZapUtils.getElement(node)).isEnabled()) {
                            this.comment = false;
                        }
                        this.setEnabled(true);
                    }
                }
                if (comment) {
                    this.setText(Constant.messages.getString("zest.comment.off.popup"));
                } else {
                    this.setText(Constant.messages.getString("zest.comment.on.popup"));
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
