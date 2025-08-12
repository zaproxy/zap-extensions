/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.addon.authhelper.internal.ui.diags;

import java.util.List;
import javax.swing.table.AbstractTableModel;
import org.parosproxy.paros.Constant;

@SuppressWarnings("serial")
public class StepsTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 1L;

    private static final String[] COLUMNS = {
        Constant.messages.getString("authhelper.authdiags.panel.table.header.timestamp"),
        Constant.messages.getString("authhelper.authdiags.panel.table.steps.header.number"),
        Constant.messages.getString("authhelper.authdiags.panel.table.steps.header.description"),
        Constant.messages.getString("authhelper.authdiags.panel.table.steps.header.url"),
        Constant.messages.getString("authhelper.authdiags.panel.table.steps.header.webelement"),
        Constant.messages.getString("authhelper.authdiags.panel.table.steps.header.screenshot"),
        Constant.messages.getString("authhelper.authdiags.panel.table.steps.header.messages"),
        Constant.messages.getString("authhelper.authdiags.panel.table.steps.header.webelements"),
        Constant.messages.getString("authhelper.authdiags.panel.table.steps.header.localstorage"),
    };

    private List<StepUi> entries;

    public StepsTableModel(List<StepUi> entries) {
        this.entries = entries;
    }

    public StepUi getStep(int row) {
        return entries.get(row);
    }

    @Override
    public String getColumnName(int column) {
        return COLUMNS[column];
    }

    @Override
    public int getColumnCount() {
        return COLUMNS.length;
    }

    @Override
    public int getRowCount() {
        return entries.size();
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        switch (columnIndex) {
            case 4, 5:
                return Boolean.class;
            case 1, 6, 7, 8:
                return Integer.class;
            default:
                return String.class;
        }
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        StepUi step = entries.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return step.getCreateTimestamp();
            case 1:
                return step.getNumber();
            case 2:
                return step.getDescription();
            case 3:
                return step.getUrl();
            case 4:
                return step.hasWebElement();
            case 5:
                return step.hasScreenshot();
            case 6:
                return step.getMessagesIds().size();
            case 7:
                return step.getWebElements().size();
            case 8:
                return step.getBrowserStorageItems().size();
            default:
                return "";
        }
    }
}
