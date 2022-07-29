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
package org.zaproxy.zap.extension.scripts;

import java.awt.Component;
import javax.swing.JTree;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.script.ScriptType;

@SuppressWarnings("serial")
public class PopupNewScriptFromType extends ExtensionPopupMenuItem {

    private static final long serialVersionUID = 1L;

    private ExtensionScriptsUI extension = null;

    private ScriptType type = null;

    /** */
    public PopupNewScriptFromType(ExtensionScriptsUI extension) {
        super();
        this.extension = extension;
        initialize();
    }

    /** @param label */
    public PopupNewScriptFromType(String label) {
        super(label);
    }

    /** This method initializes this */
    private void initialize() {
        this.setText(Constant.messages.getString("scripts.instantiate.popup"));

        this.addActionListener(
                e -> {
                    if (type != null) {
                        instantiateType(type);
                    }
                });
    }

    private void instantiateType(ScriptType type) {
        extension.getScriptsPanel().showNewScriptDialog(type);
    }

    @Override
    public boolean isEnableForComponent(Component invoker) {
        if (invoker.getName() != null && invoker.getName().equals(ScriptsListPanel.TREE)) {
            try {
                JTree tree = (JTree) invoker;
                ScriptNode node = (ScriptNode) tree.getLastSelectedPathComponent();

                // Enable if this is a type node - doesnt matter if its a template or not..
                if (node == null || node.getUserObject() != null || node.getType() == null) {
                    return false;
                }
                this.type = node.getType();

                return true;
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
