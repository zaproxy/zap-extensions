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
package org.zaproxy.zap.extension.zest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.swing.table.AbstractTableModel;
import org.parosproxy.paros.Constant;

@SuppressWarnings("serial")
public class OptionsZestIgnoreHeadersTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 1L;

    private static final String[] columnNames = {
        Constant.messages.getString("zest.options.label.ignore"),
        Constant.messages.getString("zest.options.label.header")
    };

    private List<String> allHeaders = Collections.emptyList();
    private List<String> ignoredHeaders = Collections.emptyList();

    /** */
    public OptionsZestIgnoreHeadersTableModel() {
        super();
    }

    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    @Override
    public int getRowCount() {
        return allHeaders.size();
    }

    @Override
    public Object getValueAt(int row, int col) {
        switch (col) {
            case 0:
                return this.isIgnored(row);
            case 1:
                return this.getHeader(row);
        }
        return null;
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        if (columnIndex == 0) {
            return true;
        }
        return false;
    }

    @Override
    public void setValueAt(Object value, int row, int col) {
        if (col == 0) {
            if ((boolean) value) {
                this.ignoredHeaders.add(this.getHeader(row));
            } else {
                this.ignoredHeaders.remove(this.getHeader(row));
            }
        }
    }

    @Override
    public String getColumnName(int col) {
        return columnNames[col];
    }

    @Override
    public Class<?> getColumnClass(int c) {
        if (c == 0) {
            return Boolean.class;
        }
        return String.class;
    }

    protected String getHeader(int row) {
        return this.allHeaders.get(row);
    }

    protected boolean isIgnored(int row) {
        String header = this.getHeader(row);
        if (header != null) {
            return this.ignoredHeaders.contains(header);
        }
        return false;
    }

    public void setAllHeaders(List<String> allHeaders) {
        this.allHeaders = allHeaders;
    }

    public void setIgnoredHeaders(List<String> ignoredHeaders) {
        this.ignoredHeaders = new ArrayList<>(ignoredHeaders);
    }

    public List<String> getIgnoredHeaders() {
        return Collections.unmodifiableList(this.ignoredHeaders);
    }
}
