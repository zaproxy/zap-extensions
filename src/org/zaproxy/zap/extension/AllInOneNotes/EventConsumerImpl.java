package org.zaproxy.zap.extension.AllInOneNotes;

import org.apache.log4j.Logger;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.HistoryReferenceEventPublisher;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.eventBus.EventConsumer;

import java.util.HashMap;
import java.util.Map;

public class EventConsumerImpl implements EventConsumer {

    private static final Logger LOGGER = Logger.getLogger(EventConsumerImpl.class);
    private static Map<Integer, Integer> rowMapper = new HashMap<>();

    protected void deleteRowFromNotes(int requestID){
        LOGGER.debug("NOTE deleted...");
        NotesTableModel model = (NotesTableModel) ExtensionAllInOneNotes.notesTable.getModel();
        int rowToDelete = rowMapper.get(requestID);

        model.removeRow(rowToDelete);
        rowMapper.remove(requestID);
    }

    protected void addRowToNotesTable(int requestID){
        ExtensionHistory extHist = (ExtensionHistory) org.parosproxy.paros.control.Control.getSingleton().
                getExtensionLoader().getExtension(ExtensionHistory.NAME);
        HistoryReference hr = extHist.getHistoryReference(requestID);
        NotesTableModel model = (NotesTableModel) ExtensionAllInOneNotes.notesTable.getModel();

        if (hr != null) {
            if (hr.hasNote()) {

                    try {

                        String note = hr.getHttpMessage().getNote();
                        if (rowMapper.containsKey(requestID)){
                            //note updated
                            LOGGER.debug("NOTE updated...");
                            int rowToUpdate = rowMapper.get(requestID);
                            model.setValueAt(note, rowToUpdate, 1);
                        }
                        else {
                            //note created
                            LOGGER.debug("NOTE created...");
                            rowMapper.put(requestID, model.getRowCount());
                            model.addRow(new String[]{String.valueOf(requestID), note});
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
                LOGGER.debug("NOTE SET EVENT recieved...");
                int refIdAdd = Integer.valueOf(event.getParameters().get(HistoryReferenceEventPublisher.FIELD_HISTORY_REFERENCE_ID));
                addRowToNotesTable(refIdAdd);
                break;
            case HistoryReferenceEventPublisher.EVENT_REMOVED:
                // This only gets fired if request is removed
                LOGGER.debug("NOTE REMOVE EVENT recieved...");
                LOGGER.debug(event.getParameters().toString());
                int refIdDelete = Integer.valueOf(event.getParameters().get(HistoryReferenceEventPublisher.FIELD_HISTORY_REFERENCE_ID));
                deleteRowFromNotes(refIdDelete);
                break;
            default:
        }

    }

}
