/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
import javax.swing.ImageIcon;
import javax.swing.JTree;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.popup.ExtensionPopupMenuComponent;

/**
 * An {@link ExtensionPopupMenuItem} that allows to save the script selected in the Scripts tree.
 */
@SuppressWarnings("serial")
public class PopupMenuItemSaveScript extends ExtensionPopupMenuItem {

    private static final long serialVersionUID = 1L;

    private ScriptsListPanel scriptsPanel;
    private ScriptWrapper selectedScript;

    /**
     * Constructs a {@code PopupMenuItemSaveScript} with the given scripts panel.
     *
     * @param scriptsPanel the scripts panel.
     * @throws IllegalArgumentException if scripts panel is {@code null}.
     */
    public PopupMenuItemSaveScript(ScriptsListPanel scriptsPanel) {
        super(Constant.messages.getString("scripts.list.toolbar.button.save"));

        if (scriptsPanel == null) {
            throw new IllegalArgumentException("The parameter scriptsPanel must not be null.");
        }

        setIcon(
                DisplayUtils.getScaledIcon(
                        new ImageIcon(
                                PopupMenuItemSaveScript.class.getResource(
                                        "/resource/icon/16/096.png"))));

        this.scriptsPanel = scriptsPanel;

        this.addActionListener(
                e -> {
                    PopupMenuItemSaveScript.this.scriptsPanel.saveScript(selectedScript);
                    selectedScript = null;
                });
    }

    @Override
    public boolean isEnableForComponent(Component invoker) {
        if (!ScriptsListPanel.TREE.equals(invoker.getName())) {
            return false;
        }

        JTree scriptsTree = (JTree) invoker;
        ScriptNode node = (ScriptNode) scriptsTree.getLastSelectedPathComponent();
        if (node == null || node.isTemplate() || !(node.getUserObject() instanceof ScriptWrapper)) {
            return false;
        }

        if (scriptsTree.getSelectionCount() != 1) {
            setEnabled(false);
            return true;
        }

        ScriptWrapper selectedScript = (ScriptWrapper) node.getUserObject();
        if (selectedScript.isChanged()) {
            setEnabled(true);
            this.selectedScript = selectedScript;
        } else {
            setEnabled(false);
        }

        return true;
    }

    @Override
    public boolean isSafe() {
        return true;
    }

    @Override
    public void dismissed(ExtensionPopupMenuComponent selectedMenuComponent) {
        super.dismissed(selectedMenuComponent);

        if (selectedMenuComponent != this) {
            selectedScript = null;
        }
    }
}
