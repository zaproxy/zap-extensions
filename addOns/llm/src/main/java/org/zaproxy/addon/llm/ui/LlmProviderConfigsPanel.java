/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.llm.ui;

import java.awt.Dialog;
import javax.swing.JOptionPane;
import javax.swing.SortOrder;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.llm.LlmProviderConfig;
import org.zaproxy.zap.view.AbstractMultipleOptionsBaseTablePanel;

@SuppressWarnings("serial")
public class LlmProviderConfigsPanel
        extends AbstractMultipleOptionsBaseTablePanel<LlmProviderConfig> {

    private static final long serialVersionUID = 1L;

    private static final String REMOVE_DIALOG_TITLE =
            Constant.messages.getString("llm.options.providers.remove.title");
    private static final String REMOVE_DIALOG_TEXT =
            Constant.messages.getString("llm.options.providers.remove.text");
    private static final String REMOVE_DIALOG_CONFIRM_BUTTON_LABEL =
            Constant.messages.getString("llm.options.providers.remove.button.confirm");
    private static final String REMOVE_DIALOG_CANCEL_BUTTON_LABEL =
            Constant.messages.getString("llm.options.providers.remove.button.cancel");

    private AddLlmProviderDialog addDialog;
    private ModifyLlmProviderDialog modifyDialog;

    public LlmProviderConfigsPanel(LlmProviderConfigsTableModel model) {
        super(model);
        this.model = model;
        getTable().setSortOrder(0, SortOrder.ASCENDING);
    }

    @Override
    public LlmProviderConfig showAddDialogue() {
        if (addDialog == null) {
            addDialog =
                    new AddLlmProviderDialog(
                            (Dialog) View.getSingleton().getOptionsDialog(null),
                            (LlmProviderConfigsTableModel) model);
            addDialog.pack();
        }
        addDialog.setVisible(true);
        return addDialog.getProviderConfig();
    }

    @Override
    public LlmProviderConfig showModifyDialogue(LlmProviderConfig e) {
        if (modifyDialog == null) {
            modifyDialog =
                    new ModifyLlmProviderDialog(
                            (Dialog) View.getSingleton().getOptionsDialog(null),
                            (LlmProviderConfigsTableModel) model);
            modifyDialog.pack();
        }
        modifyDialog.setProviderConfig(e);
        modifyDialog.setVisible(true);
        LlmProviderConfig updated = modifyDialog.getProviderConfig();
        if (updated != null && !updated.equals(e)) {
            return updated;
        }
        return null;
    }

    @Override
    public boolean showRemoveDialogue(LlmProviderConfig e) {
        int option =
                JOptionPane.showOptionDialog(
                        View.getSingleton().getMainFrame(),
                        REMOVE_DIALOG_TEXT,
                        REMOVE_DIALOG_TITLE,
                        JOptionPane.OK_CANCEL_OPTION,
                        JOptionPane.QUESTION_MESSAGE,
                        null,
                        new String[] {
                            REMOVE_DIALOG_CONFIRM_BUTTON_LABEL, REMOVE_DIALOG_CANCEL_BUTTON_LABEL
                        },
                        null);

        return option == JOptionPane.OK_OPTION;
    }
}
