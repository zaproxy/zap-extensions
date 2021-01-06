/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.allinonenotes;

import java.util.HashMap;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.HistoryReferenceEventPublisher;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.eventBus.EventConsumer;

public class EventConsumerImpl implements EventConsumer {

    private static final Logger LOGGER = LogManager.getLogger(EventConsumerImpl.class);
    private static Map<Integer, Integer> rowMapper = new HashMap<>();
    private NotesTableModel notesTableModel;

    public EventConsumerImpl(NotesTableModel ntm) {
        this.notesTableModel = ntm;
    }

    private NotesTableModel getNotesTableModel() {
        return notesTableModel;
    }

    protected void deleteRowFromNotes(int requestID) {
        LOGGER.debug("NOTE deleted...");
        if (rowMapper.get(requestID) != null) {
            int rowToDelete = rowMapper.get(requestID);
            getNotesTableModel().removeRow(rowToDelete);
            rowMapper.remove(requestID);
        }
    }

    protected void addRowToNotesTable(int requestID) {
        ExtensionHistory extHist =
                org.parosproxy.paros.control.Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionHistory.class);
        HistoryReference hr = extHist.getHistoryReference(requestID);

        if (hr != null) {
            if (hr.hasNote()) {

                try {

                    String note = hr.getHttpMessage().getNote();
                    if (rowMapper.containsKey(requestID)) {
                        // note updated
                        LOGGER.debug("NOTE updated...");
                        int rowToUpdate = rowMapper.get(requestID);
                        getNotesTableModel().setValueAt(note, rowToUpdate, 1);
                    } else {
                        // note created
                        LOGGER.debug("NOTE created...");
                        rowMapper.put(requestID, getNotesTableModel().getRowCount());
                        getNotesTableModel().addRow(new NoteRecord(requestID, note));
                    }

                } catch (HttpMalformedHeaderException | DatabaseException e) {
                    LOGGER.error(e.getMessage());
                }

            } else {
                // note must have been deleted
                deleteRowFromNotes(requestID);
            }
        }
    }

    @Override
    public void eventReceived(Event event) {

        switch (event.getEventType()) {
            case HistoryReferenceEventPublisher.EVENT_NOTE_SET:
                LOGGER.debug("NOTE SET EVENT received...");
                int refIdAdd =
                        Integer.valueOf(
                                event.getParameters()
                                        .get(
                                                HistoryReferenceEventPublisher
                                                        .FIELD_HISTORY_REFERENCE_ID));
                addRowToNotesTable(refIdAdd);
                break;
            case HistoryReferenceEventPublisher.EVENT_REMOVED:
                // This only gets fired if request is removed
                LOGGER.debug("NOTE REMOVE EVENT received... {}", event.getParameters().toString());
                int refIdDelete =
                        Integer.valueOf(
                                event.getParameters()
                                        .get(
                                                HistoryReferenceEventPublisher
                                                        .FIELD_HISTORY_REFERENCE_ID));
                deleteRowFromNotes(refIdDelete);
                break;
            default:
        }
    }

    public void resetRowMapper() {
        rowMapper.clear();
    }
}
