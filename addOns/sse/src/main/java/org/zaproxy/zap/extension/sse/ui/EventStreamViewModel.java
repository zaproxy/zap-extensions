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
package org.zaproxy.zap.extension.sse.ui;

import java.util.ArrayList;
import java.util.List;
import org.apache.commons.collections.map.LRUMap;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.db.DatabaseException;
import org.zaproxy.zap.extension.sse.ServerSentEvent;
import org.zaproxy.zap.extension.sse.db.EventStreamPrimaryKey;
import org.zaproxy.zap.extension.sse.db.ServerSentEventStream;
import org.zaproxy.zap.extension.sse.db.TableEventStream;
import org.zaproxy.zap.extension.sse.ui.filter.EventStreamViewFilter;
import org.zaproxy.zap.utils.PagingTableModel;

/**
 * This model uses a database table to load only needed entries from database. Moreover it shows
 * only those entries that are not deny listed by the given filter.
 */
public class EventStreamViewModel extends PagingTableModel<ServerSentEvent> {

    private static final long serialVersionUID = -5047686640383236512L;

    private static final Logger logger = Logger.getLogger(EventStreamViewModel.class);

    private static final int PAYLOAD_PREVIEW_LENGTH = 150;

    /** Names of all columns. */
    private static final String[] COLUMN_NAMES = {
        Constant.messages.getString("sse.table.header.id"),
        Constant.messages.getString("sse.table.header.timestamp"),
        Constant.messages.getString("sse.table.header.last_event_id"),
        Constant.messages.getString("sse.table.header.event_type"),
        Constant.messages.getString("sse.table.header.data")
    };

    /** Number of columns in this table model */
    protected static final int COLUMN_COUNT = COLUMN_NAMES.length;

    /** Used to show only specific events. */
    private EventStreamViewFilter filter;

    /** Interface to database. */
    private TableEventStream table;

    /** If null, all messages are shown. */
    private Integer activeStreamId;

    /**
     * Avoid having two much SQL queries by caching result and allow next query after new message
     * has arrived.
     */
    private Integer cachedRowCount;

    private Object cachedRowCountSemaphore = new Object();

    private LRUMap fullMessagesCache;

    /**
     * Ctor.
     *
     * @param databaseTable
     * @param filter
     */
    public EventStreamViewModel(TableEventStream databaseTable, EventStreamViewFilter filter) {
        this(databaseTable);

        this.filter = filter;
    }

    /**
     * Useful Ctor for subclasses.
     *
     * @param databaseTable
     */
    protected EventStreamViewModel(TableEventStream databaseTable) {
        super();

        table = databaseTable;
        fullMessagesCache = new LRUMap(10);
    }

    public void setActiveStream(Integer streamId) {
        activeStreamId = streamId;
        clear();
        fireTableDataChanged();
    }

    public Integer getActiveStreamId() {
        return activeStreamId;
    }

    /** @return size of currently visible messages */
    @Override
    public int getRowCount() {
        if (table == null) {
            return 0;
        }
        try {
            synchronized (cachedRowCountSemaphore) {
                if (cachedRowCount == null) {
                    cachedRowCount =
                            table.getEventCount(getCriterionMessage(), getCriterianInScope());
                }
                return cachedRowCount;
            }
        } catch (DatabaseException e) {
            logger.error(e.getMessage(), e);
            return 0;
        }
    }

    protected List<Integer> getCriterianInScope() {
        if (filter.getShowJustInScope()) {
            List<Integer> inScopeStreamIds = new ArrayList<>();

            // iterate through channels, and derive channel-ids in scope
            try {
                for (ServerSentEventStream stream : table.getStreamItems()) {
                    if (stream.isInScope()) {
                        inScopeStreamIds.add(stream.getId());
                    }
                }
                return inScopeStreamIds;
            } catch (DatabaseException e) {
                logger.warn(e.getMessage(), e);
            }
        }

        return null;
    }

    protected ServerSentEvent getCriterionMessage() {
        ServerSentEvent event = new ServerSentEvent();

        if (activeStreamId != null) {
            event.setStreamId(activeStreamId);
        }

        return event;
    }

    @Override
    public Object getRealValueAt(ServerSentEvent event, int columnIndex) {
        Object value = null;
        switch (columnIndex) {
            case 0:
                value = new EventStreamPrimaryKey(event.getStreamId(), event.getId());
                break;
            case 1:
                value = event.getDateTime();
                break;
            case 2:
                value = event.getLastEventId();
                break;
            case 3:
                value = event.getEventType();
                break;
            case 4:
                String preview = event.getData();
                if (preview.length() > PAYLOAD_PREVIEW_LENGTH) {
                    value = preview.substring(0, PAYLOAD_PREVIEW_LENGTH - 1) + "...";
                } else {
                    value = preview;
                }
                break;
        }
        return value;
    }

    //	private String emphasize(String message) {
    //		return "<html><i>" + StringEscapeUtils.escapeXml(message) + "</i></html>";
    //	}

    @Override
    protected Object getPlaceholderValueAt(int columnIndex) {
        if (getColumnClass(columnIndex).equals(String.class)) {
            return "..";
        }
        return null;
    }

    @Override
    protected List<ServerSentEvent> loadPage(int offset, int length) {
        try {
            return table.getEvents(
                    getCriterionMessage(),
                    getCriterianInScope(),
                    offset,
                    length,
                    PAYLOAD_PREVIEW_LENGTH);
        } catch (DatabaseException e) {
            logger.error(e.getMessage(), e);
            return new ArrayList<>(0);
        }
    }

    /** @return number of columns */
    @Override
    public int getColumnCount() {
        return COLUMN_COUNT;
    }

    /** @return name of the given column index */
    @Override
    public String getColumnName(int columnIndex) {
        return COLUMN_NAMES[columnIndex];
    }

    /** @return type of column for given column index */
    @Override
    public Class<?> getColumnClass(int columnIndex) {
        switch (columnIndex) {
            case 0:
                return EventStreamPrimaryKey.class;
            case 1:
                return String.class;
            case 2:
                return String.class;
            case 3:
                return String.class;
            case 4:
                return String.class;
        }
        return null;
    }

    /**
     * Might return null. Always check!
     *
     * <p>Retrieves Server-Sent Events from database with full payload.
     *
     * @param rowIndex
     * @return data transfer object
     */
    public ServerSentEvent getServerSentEvent(int rowIndex) {
        ServerSentEvent event = getRowObject(rowIndex);

        if (event == null) {
            return null;
        }

        String pk = event.toString();
        if (fullMessagesCache.containsKey(pk)) {
            return (ServerSentEvent) fullMessagesCache.get(pk);
        } else if (event.getId() == null) {
            return event;
        } else {
            try {
                ServerSentEvent fullEvent = table.getEvent(event.getId(), event.getStreamId());
                fullMessagesCache.put(pk, fullEvent);

                return fullEvent;
            } catch (DatabaseException e) {
                logger.error("Error retrieving full event!", e);
                return event;
            }
        }
    }

    /** Call this method when a new filter is applied on the messages list. */
    public void fireFilterChanged() {
        clear();
        fireTableDataChanged();
    }

    @Override
    public void fireTableDataChanged() {
        synchronized (cachedRowCountSemaphore) {
            cachedRowCount = null;
        }
        super.fireTableDataChanged();
    }

    @Override
    protected void clear() {
        super.clear();

        synchronized (cachedRowCountSemaphore) {
            cachedRowCount = null;
        }

        fullMessagesCache.clear();
    }

    /**
     * A new message has arrived.
     *
     * @param event
     */
    public void fireMessageArrived(ServerSentEvent event) {
        boolean isAllowlistedChannel =
                (activeStreamId == null) || event.getStreamId().equals(activeStreamId);
        if ((filter != null && filter.isDenylisted(event)) || !isAllowlistedChannel) {
            // no need to fire update, as it isn't active now
        } else {
            // find out where it is inserted and update precisely

            // if new row is inserted at the end
            // it suffices to fire inserted row at the end of list

            // with enabled row sorter, you'll have to take care about this
            int rowCount = getRowCount();

            synchronized (cachedRowCountSemaphore) {
                cachedRowCount = null;
            }

            fireTableRowsInserted(rowCount, rowCount);
        }
    }

    public Integer getModelRowIndexOf(ServerSentEvent event) {
        if (event.getId() == null) {
            return null;
        }

        ServerSentEvent criteria = getCriterionMessage();
        criteria.setStreamId(event.getStreamId());
        criteria.setId(event.getId());

        try {
            return table.getIndexOf(criteria, null);
        } catch (DatabaseException e) {
            logger.error(e.getMessage(), e);
            // maybe I'm right with this guess - try
            return event.getId() - 1;
        }
    }

    public void setTable(TableEventStream table) {
        this.table = table;
    }
}
