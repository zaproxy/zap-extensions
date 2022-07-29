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
package org.zaproxy.zap.extension.scripts;

import java.awt.Component;
import javax.swing.JOptionPane;
import javax.swing.JTree;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.script.ScriptWrapper;

@SuppressWarnings("serial")
public class PopupRemoveScript extends ExtensionPopupMenuItem {

    private static final long serialVersionUID = 1L;

    private ExtensionScriptsUI extension = null;

    /** */
    public PopupRemoveScript(ExtensionScriptsUI extension) {
        super();
        this.extension = extension;
        initialize();
    }

    /** @param label */
    public PopupRemoveScript(String label) {
        super(label);
    }

    /** This method initializes this */
    private void initialize() {
        this.setText(Constant.messages.getString("scripts.close.popup"));

        this.addActionListener(
                e -> {
                    ScriptWrapper script = extension.getScriptsPanel().getSelectedScript();
                    if (script != null) {
                        removeScript(script);
                    }
                });
    }

    private void removeScript(ScriptWrapper script) {
        if (script.isChanged()) {
            if (View.getSingleton()
                            .showConfirmDialog(Constant.messages.getString("scripts.close.confirm"))
                    != JOptionPane.OK_OPTION) {
                return;
            }
        }
        extension.getExtScript().removeScript(script);
    }

    @Override
    public boolean isEnableForComponent(Component invoker) {
        if (invoker.getName() != null && invoker.getName().equals(ScriptsListPanel.TREE)) {
            try {
                JTree tree = (JTree) invoker;
                ScriptNode node = (ScriptNode) tree.getLastSelectedPathComponent();

                if (node == null
                        || node.isTemplate()
                        || node.getUserObject() == null
                        || !(node.getUserObject() instanceof ScriptWrapper)) {
                    return false;
                }

                return extension.getScriptsPanel().getSelectedScript() != null;
            } catch (Exception e) {
            }
        }
        return false;
    }

    @Override
    public boolean isSafe() {
        return true;
    }
}
