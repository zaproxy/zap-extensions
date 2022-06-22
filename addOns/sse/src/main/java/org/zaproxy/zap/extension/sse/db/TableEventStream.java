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
package org.zaproxy.zap.extension.sse.db;

import java.sql.Clob;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Time;
import java.sql.Timestamp;
import java.sql.Types;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;
import java.util.Set;
import org.apache.commons.collections.map.LRUMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.hsqldb.jdbc.JDBCClob;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.db.DbUtils;
import org.parosproxy.paros.db.paros.ParosAbstractTable;
import org.zaproxy.zap.extension.sse.ServerSentEvent;

/** Manages writing and reading Server-Sent Event streams and events to the database. */
public class TableEventStream extends ParosAbstractTable {
    private static final Logger logger = LogManager.getLogger(TableEventStream.class);

    private Set<Integer> streamIds;
    private LRUMap streamCache;

    private PreparedStatement psInsertEvent;

    private PreparedStatement psSelectStreams;

    private PreparedStatement psInsertStream;
    private PreparedStatement psUpdateStream;

    private PreparedStatement psUpdateHistoryFk;

    private PreparedStatement psDeleteStream;
    private PreparedStatement psDeleteEventsByStreamId;

    private PreparedStatement psSelectEvent;

    private PreparedStatement psSelectMaxStreamId;

    private Queue<ServerSentEvent> eventBuffer = new LinkedList<>();
    private Queue<ServerSentEventStream> streamBuffer = new LinkedList<>();

    /** Create tables if not already available */
    @Override
    protected void reconnect(Connection conn) throws DatabaseException {
        try {
            if (!DbUtils.hasTable(conn, "EVENT_STREAM")) {
                // need to create the tables
                DbUtils.execute(
                        conn,
                        "CREATE CACHED TABLE event_stream ("
                                + "stream_id BIGINT PRIMARY KEY,"
                                + "host VARCHAR(255) NOT NULL,"
                                + "port INTEGER NOT NULL,"
                                + "url VARCHAR(1024) NOT NULL,"
                                + "start_timestamp TIMESTAMP NOT NULL,"
                                + "end_timestamp TIMESTAMP NULL,"
                                + "history_id INTEGER NULL,"
                                + "FOREIGN KEY (history_id) REFERENCES HISTORY(HISTORYID) ON DELETE SET NULL ON UPDATE SET NULL"
                                + ")");

                DbUtils.execute(
                        conn,
                        "CREATE CACHED TABLE event_stream_event ("
                                + "event_id BIGINT NOT NULL,"
                                + "stream_id BIGINT NOT NULL,"
                                + "timestamp TIMESTAMP NOT NULL,"
                                + "last_event_id VARCHAR(255) NOT NULL,"
                                + "data CLOB(16M) NOT NULL,"
                                + "event_type VARCHAR(255) NOT NULL,"
                                + "reconnection_time BIGINT NULL,"
                                + "raw_event CLOB(16M) NOT NULL,"
                                + "PRIMARY KEY (event_id, stream_id),"
                                + "FOREIGN KEY (stream_id) REFERENCES event_stream(stream_id)"
                                + ")");

                streamIds = new HashSet<>();
            } else {
                streamIds = null;
            }

            streamCache = new LRUMap(20);

            // STREAMS
            psSelectMaxStreamId =
                    conn.prepareStatement(
                            "SELECT MAX(s.stream_id) as stream_id " + "FROM event_stream AS s");

            psSelectStreams =
                    conn.prepareStatement(
                            "SELECT s.* " + "FROM event_stream AS s " + "ORDER BY s.stream_id");

            // id goes last to be consistent with update query
            psInsertStream =
                    conn.prepareStatement(
                            "INSERT INTO "
                                    + "event_stream (host, port, url, start_timestamp, end_timestamp, history_id, stream_id) "
                                    + "VALUES (?,?,?,?,?,?,?)");

            psUpdateStream =
                    conn.prepareStatement(
                            "UPDATE event_stream SET "
                                    + "host = ?, port = ?, url = ?, start_timestamp = ?, end_timestamp = ?, history_id = ? "
                                    + "WHERE stream_id = ?");

            psUpdateHistoryFk =
                    conn.prepareStatement(
                            "UPDATE event_stream SET " + "history_id = ? " + "WHERE stream_id = ?");

            psDeleteStream =
                    conn.prepareStatement("DELETE FROM event_stream " + "WHERE stream_id = ?");

            // EVENTS
            psSelectEvent =
                    conn.prepareStatement(
                            "SELECT e.* "
                                    + "FROM event_stream_event AS e "
                                    + "WHERE e.event_id = ? AND e.stream_id = ?");

            psInsertEvent =
                    conn.prepareStatement(
                            "INSERT INTO "
                                    + "event_stream_event (event_id, stream_id, timestamp, last_event_id, data, event_type, reconnection_time, raw_event) "
                                    + "VALUES (?,?,?,?,?,?,?,?)");

            psDeleteEventsByStreamId =
                    conn.prepareStatement(
                            "DELETE FROM event_stream_event " + "WHERE stream_id = ?");

            if (streamIds == null) {
                streamIds = new HashSet<>();
                PreparedStatement psSelectStreamIds =
                        conn.prepareStatement(
                                "SELECT s.stream_id "
                                        + "FROM event_stream AS s "
                                        + "ORDER BY s.stream_id");
                try {
                    psSelectStreamIds.execute();

                    ResultSet rs = psSelectStreamIds.getResultSet();
                    while (rs.next()) {
                        streamIds.add(rs.getInt(1));
                    }
                } finally {
                    try {
                        psSelectStreamIds.close();
                    } catch (SQLException e) {
                        logger.debug(e.getMessage(), e);
                    }
                }
            }
        } catch (SQLException e) {
            throw new DatabaseException(e);
        }
    }

    /**
     * Prepares a {@link PreparedStatement} instance on the fly.
     *
     * @param criteria
     * @return number of events that fulfill given template
     * @throws DatabaseException
     */
    public synchronized int getEventCount(ServerSentEvent criteria) throws DatabaseException {
        return getEventCount(criteria, null);
    }

    /**
     * Prepares a {@link PreparedStatement} instance on the fly.
     *
     * @param criteria
     * @param inScopeStreamIds
     * @return number of events that fulfill given template
     * @throws DatabaseException
     */
    public synchronized int getEventCount(ServerSentEvent criteria, List<Integer> inScopeStreamIds)
            throws DatabaseException {
        try {
            String query = "SELECT COUNT(e.stream_id) FROM event_stream_event AS e " + "<where> ";

            PreparedStatement stmt = buildEventCriteriaStatement(query, criteria, inScopeStreamIds);
            try {
                return executeAndGetSingleIntValue(stmt);
            } finally {
                stmt.close();
            }
        } catch (SQLException e) {
            throw new DatabaseException(e);
        }
    }

    private int executeAndGetSingleIntValue(PreparedStatement stmt) throws SQLException {
        stmt.execute();
        ResultSet rs = stmt.getResultSet();
        try {
            if (rs.next()) {
                return rs.getInt(1);
            }
            return 0;
        } finally {
            rs.close();
        }
    }

    public synchronized int getIndexOf(ServerSentEvent criteria, List<Integer> inScopeStreamIds)
            throws DatabaseException {
        try {
            String query =
                    "SELECT COUNT(e.event_id) "
                            + "FROM event_stream_event AS e "
                            + "<where> AND e.event_id < ?";
            PreparedStatement stmt = buildEventCriteriaStatement(query, criteria, inScopeStreamIds);

            int paramsCount = stmt.getParameterMetaData().getParameterCount();
            stmt.setInt(paramsCount, criteria.getId());

            try {
                return executeAndGetSingleIntValue(stmt);
            } finally {
                stmt.close();
            }
        } catch (SQLException e) {
            throw new DatabaseException(e);
        }
    }

    public synchronized ServerSentEvent getEvent(int eventId, int streamId)
            throws DatabaseException {
        try {
            psSelectEvent.setInt(1, eventId);
            psSelectEvent.setInt(2, streamId);
            psSelectEvent.execute();

            List<ServerSentEvent> events = buildEvents(psSelectEvent.getResultSet(), false);
            if (events.size() != 1) {
                throw new DatabaseException("Event not found!");
            }
            return events.get(0);
        } catch (SQLException e) {
            throw new DatabaseException(e);
        }
    }

    /**
     * Retrieves list of {@link ServerSentEvent}, but loads only parts of the payload.
     *
     * @param criteria
     * @param inScopeStreamIds
     * @param offset
     * @param limit
     * @param payloadPreviewLength
     * @return Events that fulfill given template.
     * @throws DatabaseException
     */
    public synchronized List<ServerSentEvent> getEvents(
            ServerSentEvent criteria,
            List<Integer> inScopeStreamIds,
            int offset,
            int limit,
            int payloadPreviewLength)
            throws DatabaseException {
        try {
            String query =
                    "SELECT e.event_id, e.stream_id, e.timestamp, e.last_event_id, e.event_type, e.data, e.reconnection_time, e.raw_event "
                            + "FROM event_stream_event AS e "
                            + "<where> "
                            + "ORDER BY e.timestamp, e.stream_id, e.event_id "
                            + "LIMIT ? "
                            + "OFFSET ?";

            PreparedStatement stmt;
            try {
                stmt = buildEventCriteriaStatement(query, criteria, inScopeStreamIds);
            } catch (DatabaseException e) {
                if (getConnection().isClosed()) {
                    return new ArrayList<>(0);
                }

                throw e;
            }

            try {
                int paramsCount = stmt.getParameterMetaData().getParameterCount();
                stmt.setInt(paramsCount - 1, limit);
                stmt.setInt(paramsCount, offset);

                stmt.execute();

                return buildEvents(stmt.getResultSet(), true, payloadPreviewLength);
            } finally {
                stmt.close();
            }
        } catch (SQLException e) {
            throw new DatabaseException(e);
        }
    }

    private List<ServerSentEvent> buildEvents(ResultSet rs, boolean interpretLiteralBytes)
            throws SQLException {
        return buildEvents(rs, interpretLiteralBytes, -1);
    }
    /**
     * @param rs
     * @param interpretLiteralBytes
     * @param previewLength
     * @return
     * @throws DatabaseException
     */
    private List<ServerSentEvent> buildEvents(
            ResultSet rs, boolean interpretLiteralBytes, int previewLength) throws SQLException {
        List<ServerSentEvent> events = new ArrayList<>();
        try {
            while (rs.next()) {
                ServerSentEvent event;

                int streamId = rs.getInt("stream_id");
                //				ServerSentEventStream stream = getStream(streamId);
                event = new ServerSentEvent();
                // TODO should I set stream?
                event.setId(rs.getInt("event_id"));
                event.setEventType(rs.getString("event_type"));
                event.setLastEventId(rs.getString("last_event_id"));
                event.setStreamId(streamId);
                event.setTime(rs.getTimestamp("timestamp"));

                if (previewLength == -1) {
                    // load all characters
                    event.setData(rs.getString("data"));
                } else {
                    Clob clob = rs.getClob("data");
                    int length = Math.min(previewLength, (int) clob.length());
                    event.setData(clob.getSubString(1, length));
                    clob.free();
                }

                Clob clob = rs.getClob("raw_event");
                event.setRawEventLength(clob.length());
                if (previewLength == -1) {
                    // load all characters
                    event.setRawEvent(rs.getString("raw_event"));
                } else {
                    int length = Math.min(previewLength, (int) clob.length());
                    event.setRawEvent(clob.getSubString(1, length));
                }
                clob.free();

                events.add(event);
            }
        } finally {
            rs.close();
        }

        return events;
    }

    public ServerSentEventStream getStream(int streamId) throws DatabaseException {
        if (!streamCache.containsKey(streamId)) {
            ServerSentEventStream criteria = new ServerSentEventStream();
            criteria.setId(streamId);
            List<ServerSentEventStream> streams = getStreams(criteria);
            if (streams.size() == 1) {
                streamCache.put(streamId, streams.get(0));
            } else {
                throw new DatabaseException("Stream '" + streamId + "' not found!");
            }
        }
        return (ServerSentEventStream) streamCache.get(streamId);
    }

    private PreparedStatement buildEventCriteriaStatement(
            String query, ServerSentEvent criteria, List<Integer> inScopeStreamIds)
            throws DatabaseException, SQLException {
        List<String> where = new ArrayList<>();
        List<Object> params = new ArrayList<>();

        Integer streamId = criteria.getStreamId();
        if (streamId != null) {
            where.add("s.stream_id = ?");
            params.add(streamId);
        }

        if (inScopeStreamIds != null) {
            StringBuilder whereExpr = new StringBuilder("s.stream_id IN (");
            int inScopeStreamCount = inScopeStreamIds.size();

            if (inScopeStreamCount > 0) {
                for (int i = 0; i < inScopeStreamCount; i++) {
                    params.add(inScopeStreamIds.get(i));

                    whereExpr.append("?");
                    if ((i + 1) < inScopeStreamCount) {
                        whereExpr.append(",");
                    }
                }
            } else {
                whereExpr.append("null");
            }

            whereExpr.append(")");
            where.add(whereExpr.toString());
        }

        return buildCriteriaStatementHelper(query, where, params);
    }

    public EventStreamPrimaryKey getEventPrimaryKey(ServerSentEvent event) {
        return new EventStreamPrimaryKey(event.getStreamId(), event.getId());
    }

    public List<ServerSentEventStream> getStreamItems() throws DatabaseException {
        try {
            psSelectStreams.execute();
            ResultSet rs = psSelectStreams.getResultSet();

            return buildStreams(rs);
        } catch (SQLException e) {
            throw new DatabaseException(e);
        }
    }

    private List<ServerSentEventStream> buildStreams(ResultSet rs) throws SQLException {
        List<ServerSentEventStream> streams = new ArrayList<>();
        try {
            while (rs.next()) {
                ServerSentEventStream stream = new ServerSentEventStream();
                stream.setId(rs.getInt("stream_id"));
                stream.setHost(rs.getString("host"));
                stream.setPort(rs.getInt("port"));
                stream.setUrl(rs.getString("url"));
                stream.setStartTimestamp(rs.getTimestamp("start_timestamp").getTime());

                Time endTs = rs.getTime("end_timestamp");
                stream.setEndTimestamp((endTs != null) ? endTs.getTime() : null);

                stream.setHistoryId(rs.getInt("history_id"));

                streams.add(stream);
            }
        } finally {
            rs.close();
        }

        return streams;
    }

    public void insertOrUpdateStream(ServerSentEventStream stream) throws DatabaseException {
        synchronized (this) {
            try {
                if (getConnection().isClosed()) {
                    // temporarily buffer streams and insert/update later
                    streamBuffer.offer(stream);
                    return;
                }

                do {
                    PreparedStatement stmt;
                    boolean addIdOnSuccess = false;

                    // first, find out if already inserted
                    if (streamIds.contains(stream.getId())) {
                        // proceed with update
                        stmt = psUpdateStream;
                    } else {
                        // proceed with insert
                        stmt = psInsertStream;
                        addIdOnSuccess = true;
                        logger.debug("insert stream: {}", stream);
                    }

                    Long startTs = stream.getStartTimestamp();
                    Long endTs = stream.getEndTimestamp();

                    stmt.setString(1, stream.getHost());
                    stmt.setInt(2, stream.getPort());
                    stmt.setString(3, stream.getUrl());
                    stmt.setTimestamp(4, (startTs != null) ? new Timestamp(startTs) : null);
                    stmt.setTimestamp(5, (endTs != null) ? new Timestamp(endTs) : null);
                    stmt.setNull(6, Types.INTEGER);
                    stmt.setInt(7, stream.getId());

                    stmt.execute();
                    if (addIdOnSuccess) {
                        streamIds.add(stream.getId());
                    }

                    if (stream.getHistoryId() != null) {
                        psUpdateHistoryFk.setInt(1, stream.getHistoryId());
                        psUpdateHistoryFk.setInt(2, stream.getId());
                        try {
                            psUpdateHistoryFk.execute();
                        } catch (SQLException e) {
                            // safely ignore this exception
                            // on shutdown, the history table is cleaned before
                            // event streams are closed and updated
                            logger.debug(e.getMessage(), e);
                        }
                    }

                    stream = streamBuffer.poll();
                } while (stream != null);
            } catch (SQLException e) {
                throw new DatabaseException(e);
            }
        }
    }

    public void insertEvent(ServerSentEvent event) throws DatabaseException {
        // synchronize on whole object to avoid race conditions with insertOrUpdateStreams()
        synchronized (this) {
            try {
                if (getConnection().isClosed()) {
                    // temporarily buffer events and write them the next time
                    eventBuffer.offer(event);
                    return;
                }

                do {
                    while (!streamIds.contains(event.getStreamId())) {
                        // maybe stream is buffered
                        if (streamBuffer.size() > 0) {
                            insertOrUpdateStream(streamBuffer.poll());
                            continue;
                        }
                        throw new DatabaseException("stream not inserted: " + event.getStreamId());
                    }

                    logger.debug("insert event: {}", event);

                    psInsertEvent.setInt(1, event.getId());
                    psInsertEvent.setInt(2, event.getStreamId());
                    psInsertEvent.setTimestamp(3, new Timestamp(event.getTimestamp()));
                    psInsertEvent.setString(4, event.getLastEventId());
                    psInsertEvent.setClob(5, new JDBCClob(event.getData()));
                    psInsertEvent.setString(6, event.getEventType());

                    Integer time;
                    if ((time = event.getReconnectionTime()) == null) {
                        psInsertEvent.setNull(7, java.sql.Types.INTEGER);
                    } else {
                        psInsertEvent.setInt(7, time);
                    }
                    psInsertEvent.setClob(8, new JDBCClob(event.getRawEvent()));
                    psInsertEvent.execute();

                    event = eventBuffer.poll();
                } while (event != null);
            } catch (SQLException e) {
                throw new DatabaseException(e);
            }
        }
    }

    public List<ServerSentEventStream> getStreams(ServerSentEventStream criteria)
            throws DatabaseException {
        try {
            String query =
                    "SELECT s.* "
                            + "FROM event_stream AS s "
                            + "<where> "
                            + "ORDER BY s.start_timestamp, s.stream_id";

            PreparedStatement stmt;
            try {
                stmt = buildEventCriteriaStatement(query, criteria);
            } catch (DatabaseException e) {
                if (getConnection().isClosed()) {
                    return new ArrayList<>(0);
                }

                throw e;
            }

            stmt.execute();

            return buildStreams(stmt.getResultSet());
        } catch (SQLException e) {
            throw new DatabaseException(e);
        }
    }

    private PreparedStatement buildEventCriteriaStatement(
            String query, ServerSentEventStream criteria) throws SQLException, DatabaseException {
        List<String> where = new ArrayList<>();
        List<Object> params = new ArrayList<>();

        Integer id = criteria.getId();
        if (id != null) {
            where.add("s.stream_id = ?");
            params.add(id);
        }

        return buildCriteriaStatementHelper(query, where, params);
    }

    private PreparedStatement buildCriteriaStatementHelper(
            String query, List<String> where, List<Object> params)
            throws SQLException, DatabaseException {
        int conditionsCount = where.size();
        if (conditionsCount > 0) {
            StringBuilder whereExpr = new StringBuilder();
            int i = 0;
            for (String condition : where) {
                whereExpr.append(condition);

                i++;
                if (i < conditionsCount) {
                    // one more will be appended
                    whereExpr.append(" AND ");
                }
            }
            query = query.replace("<where>", "WHERE " + whereExpr.toString());
        } else {
            query = query.replace("<where> AND", "WHERE ");
            query = query.replace("<where> ", "");
        }

        PreparedStatement stmt = getConnection().prepareStatement(query);
        try {
            int i = 1;
            for (Object param : params) {
                stmt.setObject(i++, param);
            }
        } catch (SQLException e) {
            stmt.close();
            throw e;
        }

        return stmt;
    }

    /**
     * Deletes all entries from given streamId from database.
     *
     * @param streamId
     * @throws DatabaseException
     */
    public void purgeStream(Integer streamId) throws DatabaseException {
        synchronized (this) {
            try {
                if (streamIds.contains(streamId)) {
                    psDeleteEventsByStreamId.setInt(1, streamId);
                    psDeleteEventsByStreamId.execute();

                    psDeleteStream.setInt(1, streamId);
                    psDeleteStream.execute();

                    streamIds.remove(streamId);
                }
            } catch (SQLException e) {
                throw new DatabaseException(e);
            }
        }
    }

    /**
     * @return current maximum value of the stream_id column
     * @throws DatabaseException
     */
    public int getMaxStreamId() throws DatabaseException {
        synchronized (this) {
            try {
                return executeAndGetSingleIntValue(psSelectMaxStreamId);
            } catch (SQLException e) {
                throw new DatabaseException(e);
            }
        }
    }
}
