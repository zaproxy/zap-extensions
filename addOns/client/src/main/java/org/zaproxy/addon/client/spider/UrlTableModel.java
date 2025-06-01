/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.client.spider;

import java.util.ArrayList;
import java.util.List;
import javax.swing.table.AbstractTableModel;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import org.parosproxy.paros.Constant;

@SuppressWarnings("serial")
public class UrlTableModel extends AbstractTableModel {

    private static final long serialVersionUID = -6380136823410869457L;

    private static final String[] COLUMN_NAMES = {
        Constant.messages.getString("client.spider.panel.table.header.uri"),
    };

    private static final int COLUMN_COUNT = COLUMN_NAMES.length;

    private List<UrlScanResult> scanResults;

    public UrlTableModel() {
        super();

        scanResults = new ArrayList<>();
    }

    @Override
    public String getColumnName(int column) {
        return COLUMN_NAMES[column];
    }

    @Override
    public int getColumnCount() {
        return COLUMN_COUNT;
    }

    @Override
    public int getRowCount() {
        return scanResults.size();
    }

    @Override
    public Object getValueAt(int row, int col) {
        UrlScanResult result = scanResults.get(row);
        switch (col) {
            case 0:
                return result.getUri();
            default:
                return null;
        }
    }

    public void removeAllElements() {
        scanResults.clear();
        fireTableDataChanged();
    }

    public void addScanResult(String uri) {
        UrlScanResult result = new UrlScanResult(uri);
        if (!scanResults.contains(result)) {
            scanResults.add(result);
            fireTableRowsInserted(scanResults.size() - 1, scanResults.size() - 1);
        }
    }

    public void removesScanResult(String uri) {
        UrlScanResult toRemove = new UrlScanResult(uri);
        int index = scanResults.indexOf(toRemove);
        if (index >= 0) {
            scanResults.remove(index);
            fireTableRowsDeleted(index, index);
        }
    }

    /**
     * Returns the type of column for given column index.
     *
     * @param columnIndex the column index
     * @return the column class
     */
    @Override
    public Class<?> getColumnClass(int columnIndex) {
        switch (columnIndex) {
            case 0:
                return String.class;
        }
        return null;
    }

    /**
     * The Class UrlScanResult that stores an entry in the table (a result for the spidering
     * process).
     */
    @EqualsAndHashCode
    @Getter
    private static class UrlScanResult {
        private String uri;

        protected UrlScanResult(String uri) {
            this.uri = uri;
        }
    }

    public List<String> getAddedNodes() {
        List<String> list = new ArrayList<>(this.scanResults.size());
        for (UrlScanResult res : this.scanResults) {
            list.add(res.uri);
        }
        return list;
    }
}
