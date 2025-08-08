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
public class WebElementsTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 1L;

    private static final String[] COLUMNS = {
        Constant.messages.getString(
                "authhelper.authdiags.panel.table.steps.webelements.header.formIndex"),
        Constant.messages.getString(
                "authhelper.authdiags.panel.table.steps.webelements.header.tagName"),
        Constant.messages.getString(
                "authhelper.authdiags.panel.table.steps.webelements.header.attributeType"),
        Constant.messages.getString(
                "authhelper.authdiags.panel.table.steps.webelements.header.attributeId"),
        Constant.messages.getString(
                "authhelper.authdiags.panel.table.steps.webelements.header.attributeName"),
        Constant.messages.getString(
                "authhelper.authdiags.panel.table.steps.webelements.header.attributeValue"),
        Constant.messages.getString(
                "authhelper.authdiags.panel.table.steps.webelements.header.text"),
        Constant.messages.getString(
                "authhelper.authdiags.panel.table.steps.webelements.header.displayed"),
        Constant.messages.getString(
                "authhelper.authdiags.panel.table.steps.webelements.header.enabled"),
        Constant.messages.getString(
                "authhelper.authdiags.panel.table.steps.webelements.header.selector"),
    };

    private List<WebElementUi> entries;

    public WebElementsTableModel(List<WebElementUi> entries) {
        this.entries = entries;
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
            case 0:
                return Integer.class;
            case 7, 8:
                return Boolean.class;
            default:
                return String.class;
        }
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        WebElementUi step = entries.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return step.getFormIndex();
            case 1:
                return step.getTagName();
            case 2:
                return step.getAttributeType();
            case 3:
                return step.getAttributeId();
            case 4:
                return step.getAttributeName();
            case 5:
                return step.getAttributeValue();
            case 6:
                return step.getText();
            case 7:
                return step.isDisplayed();
            case 8:
                return step.isEnabled();
            case 9:
                return step.getSelector();
            default:
                return "";
        }
    }
}
