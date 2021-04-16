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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.db.DatabaseException;
import org.zaproxy.zap.extension.sse.EventStreamObserver;
import org.zaproxy.zap.extension.sse.EventStreamProxy.State;
import org.zaproxy.zap.extension.sse.ServerSentEvent;

/**
 * Listens to all Server-Sent Events and utilizes {@link TableEventStream} to store events in
 * database.
 */
public class EventStreamStorage implements EventStreamObserver {

    private static final Logger logger = LogManager.getLogger(EventStreamStorage.class);

    /** Determines when events are stored in database. */
    public static final int EVENT_STREAM_OBSERVING_ORDER = 100;

    private TableEventStream table;

    public EventStreamStorage(TableEventStream table) {
        this.table = table;
    }

    @Override
    public int getServerSentEventObservingOrder() {
        return EVENT_STREAM_OBSERVING_ORDER;
    }

    @Override
    public boolean onServerSentEvent(ServerSentEvent event) {
        boolean continueForwarding = true;
        try {
            table.insertEvent(event);
        } catch (DatabaseException e) {
            logger.error(e.getMessage(), e);
        }
        return continueForwarding;
    }

    @Override
    public void onServerSentEventStateChange(State state, ServerSentEventStream stream) {
        if (state.equals(State.OPEN)
                || state.equals(State.CLOSED)
                || state.equals(State.INCLUDED)) {
            try {
                if (table != null) {
                    table.insertOrUpdateStream(stream);
                } else if (!state.equals(State.CLOSED)) {
                    logger.warn(
                            "Could not update state of Server-Sent Event stream to '{}'!", state);
                }
            } catch (DatabaseException e) {
                logger.error(e.getMessage(), e);
            }
        } else if (state.equals(State.EXCLUDED)) {
            // when proxy is excluded from ZAP, then messages are forwarded
            // but not stored - all existing communication is deleted
            try {
                table.purgeStream(stream.getId());
            } catch (DatabaseException e) {
                logger.error(e.getMessage(), e);
            }
        }
    }

    public TableEventStream getTable() {
        return table;
    }

    public void setTable(TableEventStream table) {
        this.table = table;
    }
}
