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
package org.zaproxy.zap.extension.spiderAjax;

import java.awt.EventQueue;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.swing.event.TableModelEvent;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.eventBus.EventConsumer;
import org.zaproxy.zap.extension.alert.AlertEventPublisher;
import org.zaproxy.zap.extension.spiderAjax.SpiderListener.ResourceState;
import org.zaproxy.zap.view.table.AbstractCustomColumnHistoryReferencesTableModel;
import org.zaproxy.zap.view.table.AbstractHistoryReferencesTableEntry;
import org.zaproxy.zap.view.table.DefaultHistoryReferencesTableEntry;

public class AjaxSpiderResultsTableModel
        extends AbstractCustomColumnHistoryReferencesTableModel<
                AjaxSpiderResultsTableModel.AjaxSpiderTableEntry> {

    private static final long serialVersionUID = 4949104995571034494L;

    private static final Column[] COLUMNS =
            new Column[] {
                Column.CUSTOM,
                Column.HREF_ID,
                Column.REQUEST_TIMESTAMP,
                Column.RESPONSE_TIMESTAMP,
                Column.METHOD,
                Column.URL,
                Column.STATUS_CODE,
                Column.STATUS_REASON,
                Column.RTT,
                Column.SIZE_REQUEST_HEADER,
                Column.SIZE_REQUEST_BODY,
                Column.SIZE_RESPONSE_HEADER,
                Column.SIZE_RESPONSE_BODY,
                Column.HIGHEST_ALERT,
                Column.NOTE,
                Column.TAGS
            };

    private static final String[] CUSTOM_COLUMN_NAMES = {
        Constant.messages.getString("spiderajax.panel.table.header.processed")
    };

    private static final EnumMap<ResourceState, ProcessedCellItem> statesMap;

    private final ExtensionHistory extensionHistory;
    private AlertEventConsumer alertEventConsumer;

    private List<AjaxSpiderTableEntry> resources;
    private Map<Integer, Integer> idsToRows;

    static {
        statesMap = new EnumMap<>(ResourceState.class);
        addState(statesMap, ResourceState.PROCESSED, "processed");
        addState(statesMap, ResourceState.OUT_OF_CONTEXT, "outofcontext");
        addState(statesMap, ResourceState.OUT_OF_SCOPE, "outofscope");
        addState(statesMap, ResourceState.EXCLUDED, "excluded");
        addState(statesMap, ResourceState.IO_ERROR, "ioerror");
    }

    public AjaxSpiderResultsTableModel() {
        super(COLUMNS);

        resources = new ArrayList<>();
        idsToRows = new HashMap<>();

        alertEventConsumer = new AlertEventConsumer();
        extensionHistory =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionHistory.class);
        ZAP.getEventBus()
                .registerConsumer(
                        alertEventConsumer, AlertEventPublisher.getPublisher().getPublisherName());
    }

    private static void addState(
            Map<ResourceState, ProcessedCellItem> map, ResourceState state, String i18nName) {
        map.put(
                state,
                new ProcessedCellItem(
                        state,
                        Constant.messages.getString("spiderajax.panel.table.cell." + i18nName)));
    }

    public void addHistoryReference(HistoryReference historyReference, ResourceState state) {
        HistoryReference latestHistoryReference = historyReference;
        if (extensionHistory != null) {
            latestHistoryReference =
                    extensionHistory.getHistoryReference(historyReference.getHistoryId());
        }
        final AjaxSpiderTableEntry entry = new AjaxSpiderTableEntry(latestHistoryReference, state);
        EventQueue.invokeLater(
                new Runnable() {

                    @Override
                    public void run() {
                        final int row = resources.size();
                        idsToRows.put(entry.getHistoryId(), Integer.valueOf(row));
                        resources.add(entry);
                        fireTableRowsInserted(row, row);
                    }
                });
    }

    void unload() {
        if (alertEventConsumer != null) {
            ZAP.getEventBus()
                    .unregisterConsumer(
                            alertEventConsumer,
                            AlertEventPublisher.getPublisher().getPublisherName());
            alertEventConsumer = null;
        }
    }

    @Override
    public void addEntry(AjaxSpiderTableEntry entry) {}

    @Override
    public void refreshEntryRow(int historyReferenceId) {
        final DefaultHistoryReferencesTableEntry entry = getEntryWithHistoryId(historyReferenceId);

        if (entry != null) {
            int rowIndex = getEntryRowIndex(historyReferenceId);
            getEntryWithHistoryId(historyReferenceId).refreshCachedValues();

            fireTableRowsUpdated(rowIndex, rowIndex);
        }
    }

    @Override
    public void removeEntry(int historyReferenceId) {}

    @Override
    public AjaxSpiderTableEntry getEntry(int rowIndex) {
        return resources.get(rowIndex);
    }

    @Override
    public AjaxSpiderTableEntry getEntryWithHistoryId(int historyReferenceId) {
        final int row = getEntryRowIndex(historyReferenceId);
        if (row != -1) {
            return resources.get(row);
        }
        return null;
    }

    @Override
    public int getEntryRowIndex(int historyReferenceId) {
        final Integer row = idsToRows.get(Integer.valueOf(historyReferenceId));
        if (row != null) {
            return row.intValue();
        }
        return -1;
    }

    @Override
    public void clear() {
        resources = new ArrayList<>();
        idsToRows = new HashMap<>();
        fireTableDataChanged();
    }

    @Override
    public int getRowCount() {
        return resources.size();
    }

    @Override
    protected Class<?> getColumnClass(Column column) {
        return AbstractHistoryReferencesTableEntry.getColumnClass(column);
    }

    @Override
    protected Object getPrototypeValue(Column column) {
        return AbstractHistoryReferencesTableEntry.getPrototypeValue(column);
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        if (columnIndex == -1) {
            return getEntry(rowIndex);
        }
        return super.getValueAt(rowIndex, columnIndex);
    }

    @Override
    protected Object getCustomValueAt(AjaxSpiderTableEntry entry, int columnIndex) {
        if (getCustomColumnIndex(columnIndex) == 0) {
            return statesMap.get(entry.getResourceState());
        }
        return null;
    }

    @Override
    protected String getCustomColumnName(int columnIndex) {
        return CUSTOM_COLUMN_NAMES[getCustomColumnIndex(columnIndex)];
    }

    @Override
    protected Class<?> getCustomColumnClass(int columnIndex) {
        if (getCustomColumnIndex(columnIndex) == 0) {
            return ProcessedCellItem.class;
        }
        return null;
    }

    @Override
    protected Object getCustomPrototypeValue(int columnIndex) {
        if (getCustomColumnIndex(columnIndex) == 0) {
            return "Out Of Context";
        }
        return null;
    }

    static class AjaxSpiderTableEntry extends DefaultHistoryReferencesTableEntry {

        private final ResourceState state;

        public AjaxSpiderTableEntry(HistoryReference historyReference, ResourceState state) {
            super(historyReference, COLUMNS);
            this.state = state;
        }

        public ResourceState getResourceState() {
            return state;
        }
    }

    private class AlertEventConsumer implements EventConsumer {

        @Override
        public void eventReceived(Event event) {
            switch (event.getEventType()) {
                case AlertEventPublisher.ALERT_ADDED_EVENT:
                case AlertEventPublisher.ALERT_CHANGED_EVENT:
                case AlertEventPublisher.ALERT_REMOVED_EVENT:
                    refreshEntry(
                            Integer.valueOf(
                                    event.getParameters()
                                            .get(AlertEventPublisher.HISTORY_REFERENCE_ID)));
                    break;
                case AlertEventPublisher.ALL_ALERTS_REMOVED_EVENT:
                    refreshEntries();
                    break;
                default:
            }
        }

        private void refreshEntry(final int id) {
            if (EventQueue.isDispatchThread()) {
                refreshEntryRow(id);
                return;
            }

            EventQueue.invokeLater(
                    new Runnable() {

                        @Override
                        public void run() {
                            refreshEntry(id);
                        }
                    });
        }

        private void refreshEntries() {
            if (EventQueue.isDispatchThread()) {
                refreshEntryRows();
                return;
            }

            EventQueue.invokeLater(
                    new Runnable() {

                        @Override
                        public void run() {
                            refreshEntries();
                        }
                    });
        }

        public void refreshEntryRows() {
            if (getRowCount() == 0) {
                return;
            }

            for (int i = 0; i < getRowCount(); i++) {
                getEntry(i).refreshCachedValues();
            }

            fireTableChanged(
                    new TableModelEvent(
                            AjaxSpiderResultsTableModel.this,
                            0,
                            getRowCount() - 1,
                            getColumnIndex(Column.HIGHEST_ALERT),
                            TableModelEvent.UPDATE));
        }
    }

    static class ProcessedCellItem implements Comparable<ProcessedCellItem> {

        private final ResourceState state;
        private final String label;

        public ProcessedCellItem(ResourceState state, String label) {
            this.state = state;
            this.label = label;
        }

        public ResourceState getState() {
            return state;
        }

        public String getLabel() {
            return label;
        }

        @Override
        public String toString() {
            return label;
        }

        @Override
        public int hashCode() {
            return 31 + state.hashCode();
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null) {
                return false;
            }
            if (getClass() != obj.getClass()) {
                return false;
            }
            ProcessedCellItem other = (ProcessedCellItem) obj;
            if (state != other.state) {
                return false;
            }
            return true;
        }

        @Override
        public int compareTo(ProcessedCellItem other) {
            if (other == null) {
                return 1;
            }
            return state.compareTo(other.state);
        }
    }
}
