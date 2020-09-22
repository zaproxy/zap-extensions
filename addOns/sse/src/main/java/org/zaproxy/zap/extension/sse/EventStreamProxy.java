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
package org.zaproxy.zap.extension.sse;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.log4j.Logger;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.extension.sse.db.ServerSentEventStream;

public class EventStreamProxy {

    private static final Logger logger = Logger.getLogger(EventStreamProxy.class);

    private static Comparator<EventStreamObserver> observersComparator;

    /** WebSocket communication state. */
    public enum State {
        CONNECTING,
        OPEN,
        CLOSED, // ready state
        EXCLUDED,
        INCLUDED; // no Server-Sent Events state, used for new allow/deny listed streams
    }

    //	private final HttpMessage message;
    private final BufferedWriter writer;

    private EventStreamListener listener;

    private static AtomicInteger streamIdGenerator = new AtomicInteger(0);

    private AtomicInteger eventIdGenerator = new AtomicInteger(0);

    /**
     * Keep track of the last event ID as it is used by subsequent events as long as a new one is
     * retrieved.
     */
    private String lastEventId = "";

    /** List of observers, that are informed in case of a new event. */
    private List<EventStreamObserver> observers = new ArrayList<>();

    private ServerSentEventStream dataStreamObject;

    public EventStreamProxy(HttpMessage message, BufferedReader reader, BufferedWriter writer) {
        //		this.message = message;
        this.writer = writer;

        listener = new EventStreamListener(this, reader);

        HttpRequestHeader reqHeader = message.getRequestHeader();

        dataStreamObject = new ServerSentEventStream();
        dataStreamObject.setId(streamIdGenerator.incrementAndGet());
        dataStreamObject.setUrl(reqHeader.getURI().toString());
        dataStreamObject.setStartTimestamp(Calendar.getInstance().getTimeInMillis());
        dataStreamObject.setHost(reqHeader.getHostName());
        dataStreamObject.setPort(reqHeader.getHostPort());

        // wait until HistoryReference is saved to database
        while (message.getHistoryRef() == null) {
            try {
                Thread.sleep(5);
            } catch (InterruptedException e) {
                logger.warn(e.getMessage(), e);
            }
        }
        dataStreamObject.setHistoryId(message.getHistoryRef().getHistoryId());
    }

    public void start() {
        // TODO use thread pool
        (new Thread(listener)).start();
        notifyStateObservers(State.OPEN);
    }

    public void stop() {
        try {
            if (logger.isDebugEnabled()) {
                logger.debug("Close Server-Sent Events stream #" + dataStreamObject.getId());
            }

            listener.close(); // closes reader
            writer.close();

            notifyStateObservers(State.CLOSED);
            dataStreamObject.setEndTimestamp(Calendar.getInstance().getTimeInMillis());
        } catch (IOException e) {
            if (logger.isDebugEnabled()) {
                logger.debug("An exception occurred while stopping the proxy:", e);
            }
        }
        // TODO close thread also?
    }

    /**
     * Interprets the event according to {@link
     * http://www.w3.org/TR/eventsource/#event-stream-interpretation}. Call this method if newline
     * occurred. Do not call for incomplete events. Discard pending data once the end of file is
     * reached.
     *
     * @param event
     */
    public ServerSentEvent processEvent(final String event) {
        ServerSentEvent sse = new ServerSentEvent();
        sse.setTime(Calendar.getInstance().getTimeInMillis());
        sse.setStreamId(dataStreamObject.getId());
        sse.setRawEvent(event);

        int colonIndex;
        String field;
        String value;

        for (String line : event.split("\n")) {
            colonIndex = line.indexOf(":");
            field = null;
            value = null;

            if (colonIndex == 0) {
                // line starts with a colon
                // according to specification line should be ignored,
                // but we want to keep track of this column
                // => comment can be viewed in raw data
                continue;
            } else if (colonIndex > -1) {
                field = line.substring(0, colonIndex);

                int dataIndex = colonIndex + 1;
                if (line.charAt(dataIndex) == ' ') {
                    // do not include first whitespace
                    dataIndex++;
                }

                value = line.substring(dataIndex);
            } else {
                // whole line is used as field name
                field = line;

                // the empty string is used as value
                value = "";
            }

            switch (field) {
                case ServerSentEvent.FIELD_NAME_EVENT:
                    sse.setEventType(value);
                    break;
                case ServerSentEvent.FIELD_NAME_DATA:
                    sse.appendData(value);
                    break;
                case ServerSentEvent.FIELD_NAME_ID:
                    lastEventId = value;
                    break;
                case ServerSentEvent.FIELD_NAME_RETRY:
                    if (value.matches("^[0-9]+")) {
                        sse.setReconnectionTime(Integer.valueOf(value));
                    }
                    break;
                default:
                    // ignore the field
                    break;
            }
        }

        // dispatch the event
        sse.setLastEventId(lastEventId);

        if (sse.isDataEmpty()) {
            sse.setEventType("");
        }

        sse.setId(eventIdGenerator.incrementAndGet());
        sse.setStreamId(dataStreamObject.getId());
        sse.finishData();

        if (logger.isDebugEnabled()) {
            logger.debug("Processed Server-Sent Event" + sse.toString());
        }

        boolean doForward = notifyObservers(sse);
        if (doForward) {
            forward(sse);
        }

        return sse;
    }

    private void forward(ServerSentEvent sse) {
        try {
            // forward event and trigger processing in client via an empty line
            writer.write(sse.getRawEvent() + "\n\n");
            writer.flush();
        } catch (IOException e) {
            logger.warn(
                    "Forwarding event "
                            + sse.toString()
                            + " was not possible due to: "
                            + e.getMessage(),
                    e);
            stop();
        }
    }

    private boolean notifyObservers(ServerSentEvent sse) {
        boolean doForward = true;
        synchronized (observers) {
            for (EventStreamObserver observer : observers) {
                if (!observer.onServerSentEvent(sse)) {
                    doForward = false;
                    break;
                }
            }
        }
        return doForward;
    }

    /**
     * Helper to inform about new {@link WebSocketProxy#state}. Also called when a former {@link
     * WebSocketProxy#isForwardOnly} channel is no longer deny listed {@link State#INCLUDED} or
     * vice-versa {@link State#EXCLUDED}.
     */
    protected void notifyStateObservers(State state) {
        synchronized (observers) {
            for (EventStreamObserver observer : observers) {
                observer.onServerSentEventStateChange(state, getStreamValues());
            }
        }
    }

    private ServerSentEventStream getStreamValues() {
        return dataStreamObject;
    }

    public void addObserver(EventStreamObserver observer) {
        synchronized (observers) {
            observers.add(observer);
            Collections.sort(observers, getObserversComparator());
        }
    }

    /**
     * Returns the comparator used for determining order of notification.
     *
     * @return
     */
    private static Comparator<EventStreamObserver> getObserversComparator() {
        if (observersComparator == null) {
            observersComparator =
                    new Comparator<EventStreamObserver>() {

                        @Override
                        public int compare(EventStreamObserver o1, EventStreamObserver o2) {
                            int order1 = o1.getServerSentEventObservingOrder();
                            int order2 = o2.getServerSentEventObservingOrder();

                            if (order1 < order2) {
                                return -1;
                            } else if (order1 > order2) {
                                return 1;
                            }

                            return 0;
                        }
                    };
        }
        return observersComparator;
    }
}
