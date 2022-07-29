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
package org.zaproxy.zap.extension.plugnhack.brk;

import java.awt.Component;
import javax.swing.JTable;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.zaproxy.zap.extension.brk.ExtensionBreak;
import org.zaproxy.zap.extension.plugnhack.ClientsPanel;
import org.zaproxy.zap.extension.plugnhack.MessageListTableModel;

@SuppressWarnings("serial")
public class PopupMenuAddBreakClient extends ExtensionPopupMenuItem {

    private static final long serialVersionUID = 1L;
    private ExtensionBreak extension = null;
    private JTable messageTable = null;
    private static Logger log = LogManager.getLogger(PopupMenuAddBreakClient.class);

    public PopupMenuAddBreakClient(ExtensionBreak extension) {
        super(Constant.messages.getString("brk.add.popup"));

        this.extension = extension;

        initialize();
    }

    private void initialize() {

        this.addActionListener(
                evt -> {
                    int[] rows = messageTable.getSelectedRows();
                    if (rows.length != 1) {
                        return;
                    }

                    try {
                        MessageListTableModel model =
                                (MessageListTableModel) messageTable.getModel();
                        extension.addUiBreakpoint(model.getClientMessageAtRow(rows[0]));

                    } catch (Exception e) {
                        extension
                                .getView()
                                .showWarningDialog(
                                        Constant.messages.getString("brk.add.error.history"));
                    }
                });
    }

    @Override
    public boolean isEnableForComponent(Component invoker) {

        if (ClientsPanel.CLIENTS_MESSAGE_TABLE_NAME.equals(invoker.getName())) {
            try {
                messageTable = (JTable) invoker;
                int[] rows = messageTable.getSelectedRows();
                if (rows.length == 1) {
                    this.setEnabled(true);
                } else {
                    this.setEnabled(false);
                }

            } catch (Exception e) {
                log.warn(e.getMessage(), e);
            }
            return true;
        }
        return false;
    }
}
