/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.paramdigger.gui;

import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.zaproxy.zap.view.table.HistoryReferencesTable;

@SuppressWarnings("serial")
public class ParamDiggerResultsTable extends HistoryReferencesTable {

    private static final long serialVersionUID = 1L;
    private static final String RESULTS_TABLE_NAME = "ParamDiggerResultsTable";

    private final ExtensionHistory extensionHistory;

    public ParamDiggerResultsTable(ParamDiggerHistoryTableModel model) {
        super(model);
        setName(RESULTS_TABLE_NAME);
        extensionHistory =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionHistory.class);
    }

    @Override
    protected HistoryReference getHistoryReferenceAtViewRow(int row) {
        HistoryReference historyReference = super.getHistoryReferenceAtViewRow(row);
        if (historyReference == null) {
            return null;
        }

        if (extensionHistory == null
                || extensionHistory.getHistoryReference(historyReference.getHistoryId()) == null) {
            // Associated message was deleted in the meantime.
            return null;
        }

        return historyReference;
    }
}
