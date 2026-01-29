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
package org.zaproxy.addon.llm.ui;

import java.util.Collections;
import java.util.List;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.llm.LlmProviderConfig;
import org.zaproxy.zap.view.AbstractMultipleOptionsBaseTableModel;

@SuppressWarnings("serial")
public class LlmProviderConfigsTableModel
        extends AbstractMultipleOptionsBaseTableModel<LlmProviderConfig> {

    private static final long serialVersionUID = 1L;

    private static final String[] COLUMN_NAMES = {
        Constant.messages.getString("llm.options.providers.table.header.name"),
        Constant.messages.getString("llm.options.providers.table.header.provider"),
        Constant.messages.getString("llm.options.providers.table.header.models"),
        Constant.messages.getString("llm.options.providers.table.header.endpoint")
    };

    private static final int COLUMN_COUNT = COLUMN_NAMES.length;

    private List<LlmProviderConfig> providerConfigs;

    public LlmProviderConfigsTableModel() {
        super();
        providerConfigs = Collections.emptyList();
    }

    @Override
    public String getColumnName(int col) {
        return COLUMN_NAMES[col];
    }

    @Override
    public int getColumnCount() {
        return COLUMN_COUNT;
    }

    @Override
    public int getRowCount() {
        return providerConfigs.size();
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        LlmProviderConfig config = getElement(rowIndex);
        switch (columnIndex) {
            case 0:
                return config.getName();
            case 1:
                return config.getProvider().toString();
            case 2:
                return String.join(", ", config.getModels());
            case 3:
                return config.getEndpoint();
            default:
                return null;
        }
    }

    public void setProviderConfigs(List<LlmProviderConfig> providerConfigs) {
        this.providerConfigs = providerConfigs;
        fireTableDataChanged();
    }

    @Override
    public List<LlmProviderConfig> getElements() {
        return providerConfigs;
    }
}
