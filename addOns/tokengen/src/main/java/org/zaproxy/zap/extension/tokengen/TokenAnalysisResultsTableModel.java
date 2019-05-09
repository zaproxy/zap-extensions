/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP Development Team
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
import java.util.List;
import javax.swing.ImageIcon;
import javax.swing.table.DefaultTableModel;
import org.parosproxy.paros.Constant;

public class TokenAnalysisResultsTableModel extends DefaultTableModel {

    private static final long serialVersionUID = 1L;
    private static final String[] columnNames = {
        Constant.messages.getString("tokengen.analyse.table.test"),
        Constant.messages.getString("tokengen.analyse.table.result"),
        Constant.messages.getString("tokengen.analyse.table.desc")
    };

    private List<TokenAnalysisTestResult> results = new ArrayList<>();

    public TokenAnalysisResultsTableModel() {}

    public void addResult(TokenAnalysisTestResult result) {
        this.results.add(result);
        this.fireTableRowsInserted(results.size() - 1, results.size() - 1);
    }

    @Override
    public Class<?> getColumnClass(int c) {
        if (c == 1) {
            return ImageIcon.class;
        }
        return String.class;
    }

    @Override
    public String getColumnName(int col) {
        return columnNames[col];
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        if (columnIndex == 1) {
            return true;
        }
        return false;
    }

    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    @Override
    public int getRowCount() {
        if (results == null) {
            return 0;
        }
        return results.size();
    }

    @Override
    public Object getValueAt(int row, int col) {
        TokenAnalysisTestResult result = results.get(row);
        Object value = null;
        switch (col) {
            case 0:
                value =
                        Constant.messages.getString(
                                "tokengen.analyse.test." + result.getType().name().toLowerCase());
                break;
            case 1:
                switch (result.getResult()) {
                    case PASS:
                        value =
                                new ImageIcon(
                                        getClass()
                                                .getResource(
                                                        "/resource/icon/16/072.png")); // Green flag
                        break;
                    case HIGH:
                        value =
                                new ImageIcon(
                                        getClass()
                                                .getResource(
                                                        "/resource/icon/16/074.png")); // Yellow
                        // flag
                        break;
                    case MEDIUM:
                        value =
                                new ImageIcon(
                                        getClass()
                                                .getResource(
                                                        "/resource/icon/16/076.png")); // Orange
                        // flag
                        break;
                    case LOW:
                        value =
                                new ImageIcon(
                                        getClass()
                                                .getResource(
                                                        "/resource/icon/16/075.png")); // Pink flag
                        break;
                    case FAIL:
                        value =
                                new ImageIcon(
                                        getClass()
                                                .getResource(
                                                        "/resource/icon/16/071.png")); // Red flag
                        break;
                }
                break;
            case 2:
                value = result.getSummary();
                if (result.getSummary() == null || result.getSummary().length() == 0) {
                    value =
                            Constant.messages.getString(
                                    "tokengen.analyse.summary."
                                            + result.getResult().name().toLowerCase());
                }
                break;
            default:
                value = "";
        }
        return value;
    }

    public void clear() {
        this.results.clear();
        this.fireTableDataChanged();
    }
}
