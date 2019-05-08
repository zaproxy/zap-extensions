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
package org.zaproxy.zap.extension.tokengen;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import javax.swing.table.AbstractTableModel;
import org.parosproxy.paros.Constant;

public class TokenGenMessagesTableModel extends AbstractTableModel {

    private static final long serialVersionUID = -6455260082620124655L;

    public static final int RTT_COLUMN_INDEX = 5;
    public static final int RESPONSE_BODY_SIZE_COLUMN_INDEX = 6;

    private static final String[] COLUMN_NAMES = {
        Constant.messages.getString("tokengen.results.table.header.timestamp.request"),
        Constant.messages.getString("tokengen.results.table.header.method"),
        Constant.messages.getString("tokengen.results.table.header.url"),
        Constant.messages.getString("tokengen.results.table.header.code"),
        Constant.messages.getString("tokengen.results.table.header.reason"),
        Constant.messages.getString("tokengen.results.table.header.rtt"),
        Constant.messages.getString("tokengen.results.table.header.size.responsebody"),
        Constant.messages.getString("tokengen.results.table.header.token")
    };

    private static final int COLUMN_COUNT = COLUMN_NAMES.length;

    private List<MessageSummary> messages = new ArrayList<>();

    public TokenGenMessagesTableModel() {
        messages = new ArrayList<>();
    }

    @Override
    public int getColumnCount() {
        return COLUMN_COUNT;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMN_NAMES[column];
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        switch (columnIndex) {
            case 0:
                return Date.class;
            case 1:
                return String.class;
            case 2:
                return String.class;
            case 3:
                return Integer.class;
            case 4:
                return String.class;
            case RTT_COLUMN_INDEX:
                return Long.class;
            case RESPONSE_BODY_SIZE_COLUMN_INDEX:
                return Long.class;
            case 7:
                return String.class;
            default:
                return String.class;
        }
    }

    @Override
    public int getRowCount() {
        return messages.size();
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        MessageSummary message = messages.get(rowIndex);

        switch (columnIndex) {
            case 0:
                return message.getRequestTimestamp();
            case 1:
                return message.getMethod();
            case 2:
                return message.getUri();
            case 3:
                return message.getStatusCode();
            case 4:
                return message.getReasonPhrase();
            case RTT_COLUMN_INDEX:
                return message.getTimeElapsedMillis();
            case RESPONSE_BODY_SIZE_COLUMN_INDEX:
                return message.getResponseBodyLength();
            case 7:
                return message.getToken();
            default:
                return "";
        }
    }

    public void addMessage(MessageSummary message) {
        int index = messages.size();
        messages.add(message);

        fireTableRowsInserted(index, index);
    }

    public void clear() {
        messages = new ArrayList<>();
        fireTableDataChanged();
    }

    public MessageSummary getMessage(int rowIndex) {
        return messages.get(rowIndex);
    }
}
