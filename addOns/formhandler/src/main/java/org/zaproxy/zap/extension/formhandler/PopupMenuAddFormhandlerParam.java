/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.formhandler;

import java.awt.Component;
import javax.swing.JTable;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.params.HtmlParameterStats;
import org.zaproxy.zap.extension.params.ParamsPanel;
import org.zaproxy.zap.extension.params.ParamsTableModel;

public class PopupMenuAddFormhandlerParam extends ExtensionPopupMenuItem {

    private static final long serialVersionUID = 1L;

    private JTable paramTable = null;

    public PopupMenuAddFormhandlerParam() {
        super(Constant.messages.getString("formhandler.popup.menu.params.add.label"));
        this.addActionListener(
                e -> {
                    PopupDialogAddField popupDialogAddField = null;
                    HtmlParameterStats hps =
                            ((ParamsTableModel) paramTable.getModel())
                                    .getHtmlParameterStatsAtRow(paramTable.getSelectedRow());
                    popupDialogAddField =
                            new PopupDialogAddField(
                                    View.getSingleton().getOptionsDialog(null),
                                    hps.getName(),
                                    hps.getValues());
                    popupDialogAddField.setVisible(true);
                });
    }

    @Override
    public boolean isEnableForComponent(Component invoker) {
        if (invoker.getName() != null && invoker.getName().equals(ParamsPanel.PANEL_NAME)) {
            this.paramTable = (JTable) invoker;
            this.setEnabled(paramTable.getSelectedRowCount() == 1);
            return true;
        }
        return false;
    }

    @Override
    public boolean isSafe() {
        return true;
    }
}
