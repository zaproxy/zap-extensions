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
package org.zaproxy.zap.extension.plugnhack;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Vector;
import javax.swing.ImageIcon;
import javax.swing.table.AbstractTableModel;
import org.parosproxy.paros.Constant;

@SuppressWarnings("serial")
public class MessageListTableModel extends AbstractTableModel {

    private static final SimpleDateFormat SDF = new SimpleDateFormat("HH:mm:ss.SSS");
    private static final long serialVersionUID = 1L;

    private final Vector<String> columnNames;
    private List<ClientMessage> messages;

    public MessageListTableModel() {
        super();
        columnNames = new Vector<>();
        columnNames.add(Constant.messages.getString("plugnhack.msg.table.header.date"));
        columnNames.add(""); // Changed icon
        columnNames.add(Constant.messages.getString("plugnhack.msg.table.header.client"));
        columnNames.add(Constant.messages.getString("plugnhack.msg.table.header.type"));
        columnNames.add(Constant.messages.getString("plugnhack.msg.table.header.data"));

        messages = Collections.synchronizedList(new ArrayList<>());
    }

    @Override
    public int getColumnCount() {
        return columnNames.size();
    }

    @Override
    public int getRowCount() {
        return messages.size();
    }

    @Override
    public String getColumnName(int col) {
        return columnNames.get(col);
    }

    @Override
    public Object getValueAt(int row, int col) {
        Object obj = null;
        if (row >= messages.size()) {
            return null;
        }
        ClientMessage msg = messages.get(row);
        switch (col) {
            case 0:
                obj = SDF.format(msg.getReceived());
                break;
            case 1:
                switch (msg.getState()) {
                    case received:
                        if (msg.isChanged()) {
                            obj = ExtensionPlugNHack.CHANGED_ICON;
                        }
                        break;
                    case pending:
                        obj = ExtensionPlugNHack.PENDING_ICON;
                        break;
                    case resent:
                        obj = ExtensionPlugNHack.CHANGED_ICON;
                        break;
                    case dropped:
                        obj = ExtensionPlugNHack.DROPPED_ICON;
                        break;
                    case oraclehit:
                        obj = ExtensionPlugNHack.ORACLE_ICON;
                        break;
                }
                break;
            case 2:
                obj = msg.getClientId();
                break;
            case 3:
                obj = msg.getType();
                break;
            case 4:
                obj = msg.getData();
                break;
        }
        return obj;
    }

    public ClientMessage getClientMessageAtRow(int row) {
        return messages.get(row);
    }

    public void addClientMessage(ClientMessage msg) {
        messages.add(msg);
        this.fireTableRowsInserted(messages.size() - 1, messages.size() - 1);
    }

    public void clientMessageChanged(ClientMessage msg) {
        int index = messages.indexOf(msg);
        if (index >= 0) {
            this.fireTableRowsUpdated(index, index);
        }
    }

    @Override
    public boolean isCellEditable(int row, int col) {
        return false;
    }

    @Override
    public Class<? extends Object> getColumnClass(int c) {
        if (c == 1) {
            return ImageIcon.class;
        }
        return String.class;
    }

    public void removeAllElements() {
        messages.clear();
        this.fireTableDataChanged();
    }
}
