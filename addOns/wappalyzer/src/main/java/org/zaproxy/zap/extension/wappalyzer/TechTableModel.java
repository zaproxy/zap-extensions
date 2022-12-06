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
package org.zaproxy.zap.extension.wappalyzer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Vector;
import javax.swing.table.AbstractTableModel;
import org.parosproxy.paros.Constant;

@SuppressWarnings("serial")
public class TechTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 1L;

    private final Vector<String> columnNames;
    private List<ApplicationMatch> apps;

    private int lastAddedRow;
    private int lastEditedRow;

    public TechTableModel() {
        super();
        columnNames = new Vector<>();
        columnNames.add(Constant.messages.getString("wappalyzer.table.header.name"));
        columnNames.add(Constant.messages.getString("wappalyzer.table.header.version"));
        columnNames.add(Constant.messages.getString("wappalyzer.table.header.category"));
        columnNames.add(Constant.messages.getString("wappalyzer.table.header.website"));
        columnNames.add(Constant.messages.getString("wappalyzer.table.header.implies"));
        columnNames.add(Constant.messages.getString("wappalyzer.table.header.cpe"));
        // Dont currently support confidence
        // columnNames.add(Constant.messages.getString("wappalyzer.table.header.confidence"));

        apps = Collections.synchronizedList(new ArrayList<>());

        lastAddedRow = -1;
        lastEditedRow = -1;
    }

    @Override
    public int getColumnCount() {
        return columnNames.size();
    }

    @Override
    public int getRowCount() {
        return apps.size();
    }

    @Override
    public String getColumnName(int col) {
        return columnNames.get(col);
    }

    @Override
    public Object getValueAt(int row, int col) {
        Object obj = null;
        if (row >= apps.size()) {
            return null;
        }
        ApplicationMatch app = apps.get(row);
        switch (col) {
            case 0:
                obj = app.getApplication();
                break;
            case 1:
                obj = app.getVersion();
                break;
            case 2:
                obj = getCategoriesString(app.getApplication());
                break;
            case 3:
                obj = app.getApplication().getWebsite();
                break;
            case 4:
                obj = getImpliesString(app.getApplication());
                break;
            case 5:
                obj = app.getApplication().getCpe();
                // case 5: obj = app.getConfidence(); break;
        }
        return obj;
    }

    public String getCategoriesString(Application app) {
        return categoriesToString(app.getCategories());
    }

    public String getImpliesString(Application app) {
        return listToString(app.getImplies());
    }

    private String categoriesToString(List<String> list) {
        if (list == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        for (String str : list) {
            // See if we can i18n them
            if (Constant.messages.containsKey("wappalyzer.category." + str)) {
                sb.append(Constant.messages.getString("wappalyzer.category." + str));
            } else {
                sb.append(str);
            }
            sb.append(" ");
        }
        return sb.toString();
    }

    private String listToString(List<String> list) {
        if (list == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        for (String str : list) {
            sb.append(str);
            sb.append(" ");
        }
        return sb.toString();
    }

    public ApplicationMatch getApplicationAtRow(int row) {
        return apps.get(row);
    }

    public void addApplication(ApplicationMatch app) {
        lastAddedRow = -1;

        for (int i = 0; i < apps.size(); i++) {
            int cmp =
                    app.getApplication()
                            .getName()
                            .toLowerCase()
                            .compareTo(apps.get(i).getApplication().getName().toLowerCase());
            if (cmp < 0) {
                apps.add(i, app);
                this.fireTableRowsInserted(i, i);

                lastAddedRow = i;
                return;

            } else if (cmp == 0) {
                // Already matches, so ignore
                ApplicationMatch existing = apps.get(i);
                existing.getVersions().addAll(app.getVersions());
                lastAddedRow = i;
                return;
            }
        }

        if (!apps.contains(app)) {
            apps.add(app);
            this.fireTableRowsInserted(apps.size() - 1, apps.size() - 1);

            lastAddedRow = apps.size() - 1;
        }
    }

    public int getLastAddedRow() {
        return lastAddedRow;
    }

    public int getLastEditedRow() {
        return lastEditedRow;
    }

    @Override
    public boolean isCellEditable(int row, int col) {
        return false;
    }

    @Override
    public Class<? extends Object> getColumnClass(int c) {
        switch (c) {
            case 0:
                return Application.class;
            case 1:
                return String.class;
            case 2:
                return String.class;
            case 3:
                return String.class;
            case 4:
                return String.class;
            case 5:
                return String.class;
        }
        return null;
    }

    public void removeAllElements() {
        apps.clear();
    }

    public List<ApplicationMatch> getApps() {
        return apps;
    }

    public Application getApp(int row) {
        return apps.get(row).getApplication();
    }
}
