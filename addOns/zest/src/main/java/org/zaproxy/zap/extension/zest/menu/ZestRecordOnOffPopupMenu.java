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
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestScriptWrapper;

/** Popup for turning on and off recording for Zest standalone scripts */
@SuppressWarnings("serial")
public class ZestRecordOnOffPopupMenu extends ExtensionPopupMenuItem {

    private static final long serialVersionUID = 1L;

    private static final Logger logger = LogManager.getLogger(ZestRecordOnOffPopupMenu.class);

    private ExtensionZest extension = null;
    private boolean record;

    /** */
    public ZestRecordOnOffPopupMenu(ExtensionZest extension, boolean record) {
        super();
        this.extension = extension;
        this.record = record;
        if (record) {
            this.setText(Constant.messages.getString("zest.record.on.popup"));
        } else {
            this.setText(Constant.messages.getString("zest.record.off.popup"));
        }
        initialize();
    }

    /** This method initializes this */
    private void initialize() {

        this.addActionListener(
                e -> extension.setRecording(extension.getSelectedZestNode(), record));
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
                    if (node != null && node.getUserObject() instanceof ZestScriptWrapper) {
                        ZestScriptWrapper script = (ZestScriptWrapper) node.getUserObject();
                        if (script.getType().hasCapability(ScriptType.CAPABILITY_APPEND)
                                && record != script.isRecording()) {
                            this.setEnabled(true);
                            return true;
                        } else {
                            return false;
                        }
                    }
                }
            } catch (Exception e) {
                logger.error(e.getMessage(), e);
            }
        }
        return false;
    }
}
