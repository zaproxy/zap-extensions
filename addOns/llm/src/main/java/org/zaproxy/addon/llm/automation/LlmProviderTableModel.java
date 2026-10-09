/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.llm.automation;

import java.util.ArrayList;
import java.util.List;
import javax.swing.table.AbstractTableModel;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.llm.automation.LlmConfigJob.Provider;

/** The table model of the providers of an {@link LlmConfigJob}. */
@SuppressWarnings("serial")
class LlmProviderTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 1L;

    private static final String[] COLUMN_NAMES = {
        Constant.messages.getString("llm.configjob.dialog.table.header.name"),
        Constant.messages.getString("llm.configjob.dialog.table.header.type"),
        Constant.messages.getString("llm.configjob.dialog.table.header.endpoint"),
        Constant.messages.getString("llm.configjob.dialog.table.header.models")
    };

    private List<Provider> providers = new ArrayList<>();

    @Override
    public int getColumnCount() {
        return COLUMN_NAMES.length;
    }

    @Override
    public int getRowCount() {
        return providers.size();
    }

    @Override
    public String getColumnName(int col) {
        return COLUMN_NAMES[col];
    }

    @Override
    public Class<?> getColumnClass(int col) {
        return String.class;
    }

    @Override
    public boolean isCellEditable(int row, int col) {
        return false;
    }

    @Override
    public Object getValueAt(int row, int col) {
        Provider provider = providers.get(row);
        return switch (col) {
            case 0 -> provider.getName();
            case 1 -> provider.getType() != null ? provider.getType().toString() : "";
            case 2 -> provider.getEndpoint();
            case 3 -> provider.getModels() != null ? String.join(", ", provider.getModels()) : "";
            default -> null;
        };
    }

    List<Provider> getProviders() {
        return providers;
    }

    void setProviders(List<Provider> providers) {
        this.providers = providers != null ? new ArrayList<>(providers) : new ArrayList<>();
        fireTableDataChanged();
    }

    void add(Provider provider) {
        providers.add(provider);
        fireTableRowsInserted(providers.size() - 1, providers.size() - 1);
    }

    void update(int index, Provider provider) {
        providers.set(index, provider);
        fireTableRowsUpdated(index, index);
    }

    void remove(int index) {
        if (index >= 0 && index < providers.size()) {
            providers.remove(index);
            fireTableRowsDeleted(index, index);
        }
    }

    /**
     * Tells whether the name is used by a provider other than the one at the given index.
     *
     * @param index the index of the provider being edited, or {@code -1} if it's a new one
     */
    boolean isNameUsed(String name, int index) {
        String trimmed = StringUtils.trimToEmpty(name);
        for (int i = 0; i < providers.size(); i++) {
            if (i != index && trimmed.equals(StringUtils.trimToEmpty(providers.get(i).getName()))) {
                return true;
            }
        }
        return false;
    }
}
