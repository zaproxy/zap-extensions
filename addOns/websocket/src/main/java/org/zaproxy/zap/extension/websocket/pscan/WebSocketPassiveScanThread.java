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
package org.zaproxy.zap.extension.websocket.pscan;

import java.util.Iterator;
import java.util.concurrent.LinkedBlockingQueue;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.db.DatabaseException;
import org.zaproxy.zap.extension.websocket.WebSocketMessage;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.WebSocketObserver;
import org.zaproxy.zap.extension.websocket.WebSocketProxy;
import org.zaproxy.zap.extension.websocket.alerts.WebSocketAlertThread;
import org.zaproxy.zap.extension.websocket.alerts.WebSocketAlertWrapper;
import org.zaproxy.zap.extension.websocket.db.TableWebSocket;
import org.zaproxy.zap.extension.websocket.db.WebSocketStorage;
import org.zaproxy.zap.utils.Stats;

/** Implements a background thread for passive scanning */
public class WebSocketPassiveScanThread extends Thread
        implements WebSocketObserver, WebSocketAlertThread {

    public static final String WEBSOCKET_PSCAN_STATS_PREFIX = "stats.websockets.pscan.";

    private static final Logger LOGGER = LogManager.getLogger(WebSocketPassiveScanThread.class);

    private static final int WEBSOCKET_OBSERVING_ORDER =
            WebSocketStorage.WEBSOCKET_OBSERVING_ORDER + 10;

    /** Interval for message reading */
    public static final int SLEEP_TIME = 5000;

    /** Thread safe Linked Queue */
    private LinkedBlockingQueue<MessageWrapper> messagesBuffer;

    /** {@code True} to enable the passive scan Thread */
    private volatile boolean isActive;

    /** Reference to Database. Used in order to pick messages for scanning */
    private TableWebSocket tableWebSocket;

    /**
     * Manager used to updating the messages table. In addition, used by passive scan thread so as
     * to get access at plugins
     */
    private WebSocketPassiveScannerManager passiveScannerManager;

    /**
     * Initialize the passive scan in background thread. By default thread is inactive and not
     * alive. In order to activate thread use {@link WebSocketPassiveScanThread#start()}
     *
     * @param passiveScannerManager the manager
     */
    public WebSocketPassiveScanThread(WebSocketPassiveScannerManager passiveScannerManager) {
        super("ZAP-WS-PassiveScanner");
        super.setDaemon(true);

        this.passiveScannerManager = passiveScannerManager;
        this.isActive = false;
        messagesBuffer = new LinkedBlockingQueue<>();
    }

    /** @return true if the table was initialized */
    public boolean hasTable() {
        return tableWebSocket != null;
    }

    public void setTable(TableWebSocket tableWebSocket) {
        this.tableWebSocket = tableWebSocket;
    }

    public boolean isActive() {
        return isActive;
    }

    @Override
    public int getObservingOrder() {
        return WEBSOCKET_OBSERVING_ORDER;
    }

    @Override
    public boolean onMessageFrame(int channelId, WebSocketMessage message) {
        if (message.isFinished() && !shouldIgnoreServerModeMessages(message)) {
            messagesBuffer.add(new MessageWrapper(message.getMessageId(), channelId));
        }
        return true;
    }

    @Override
    public void onStateChange(WebSocketProxy.State state, WebSocketProxy proxy) {
        // Ignore
    }

    @Override
    public void run() {
        MessageWrapper messageWrap;
        WebSocketPassiveScannerDecorator currentPassiveScanner;
        WebSocketMessageDTO currentMessage;
        Iterator<WebSocketPassiveScannerDecorator> iterator;
        WebSocketScanHelperImpl helper = new WebSocketScanHelperImpl(this);
        while (isActive) {
            if (messagesBuffer.isEmpty() || tableWebSocket == null) {
                try {
                    Thread.sleep(SLEEP_TIME);
                } catch (InterruptedException e) {
                    LOGGER.info("Sleeping was interrupted", e);
                }
                if (!isActive) {
                    break;
                }
            } else {
                messageWrap = messagesBuffer.poll();
                try {
                    currentMessage =
                            tableWebSocket.getMessage(messageWrap.messageId, messageWrap.channelId);
                    iterator = passiveScannerManager.getIterator();
                    while (iterator.hasNext()) {
                        if ((currentPassiveScanner = iterator.next()).isEnabled()) {
                            long startTime = System.currentTimeMillis();
                            currentPassiveScanner.scanMessage(
                                    helper.getWebSocketScanHelper(
                                            currentPassiveScanner.getId(), currentMessage),
                                    currentMessage);
                            Stats.incCounter(
                                    WEBSOCKET_PSCAN_STATS_PREFIX + currentPassiveScanner.getName(),
                                    System.currentTimeMillis() - startTime);
                        }
                    }
                } catch (DatabaseException e) {
                    LOGGER.warn("Could not get messages from database", e);
                }
            }
        }
    }

    @Override
    public Alert.Source getAlertSource() {
        return Alert.Source.PASSIVE;
    }

    @Override
    public void raiseAlert(WebSocketAlertWrapper websocketAlert) {
        if (!isActive) {
            return;
        }
        passiveScannerManager.getAlertManager().alertFound(websocketAlert);
    }

    private boolean shouldIgnoreServerModeMessages(WebSocketMessage message) {
        return message.getProxyMode().equals(WebSocketProxy.Mode.SERVER)
                && passiveScannerManager.isServerModeIgnored();
    }

    /** Shutdown the passive scan thread */
    public void shutdown() {
        isActive = false;
    }

    @Override
    public synchronized void start() {
        isActive = true;
        super.start();
    }

    private class MessageWrapper {
        public int messageId;
        public int channelId;

        MessageWrapper(int messageId, int channelId) {
            this.messageId = messageId;
            this.channelId = channelId;
        }
    }
}
