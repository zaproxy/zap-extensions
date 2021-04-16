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
import java.util.concurrent.CopyOnWriteArraySet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.zap.extension.websocket.WebSocketObserver;
import org.zaproxy.zap.extension.websocket.WebSocketSenderListener;
import org.zaproxy.zap.extension.websocket.alerts.AlertManager;
import org.zaproxy.zap.extension.websocket.db.TableWebSocket;

/**
 * Manages all stuff related with the WebSocket Passive Scanning. Manager is able to open a
 * background thread {@link WebSocketPassiveScanThread} so as to run passive scans. In addition, all
 * {@link WebSocketPassiveScanner} implementations should be registered and enabled/disabled by this
 * class. Manager keeps the WebSocket Scanners into thread safe list. Finally, informs every Passive
 * Scanners (should implement {@link WebSocketSenderListener}) about messages with method{@link
 * WebSocketPassiveScannerManager#getWebSocketScannerObserver()}
 */
public class WebSocketPassiveScannerManager {

    private static final Logger LOGGER = LogManager.getLogger(WebSocketPassiveScannerManager.class);

    /** The background thread where the passive scans are running */
    private WebSocketPassiveScanThread passiveScanThread;

    /** Used to raise Alert Messages */
    private AlertManager alertManager;

    /** List stores passive scanners */
    private CopyOnWriteArraySet<WebSocketPassiveScannerDecorator> passiveScannersSet;

    /** True if server proxies should be ignored */
    private boolean isServerModeIgnored = true;

    /**
     * Initiate a Passive Scanner Manager. By default passive scans are disabled. In order to enable
     * all passive scanners {@see WebSocketPassiveScannerManager#setAllEnable}. In addition, if
     * WebSocket Proxy Mode equals to {@link
     * org.zaproxy.zap.extension.websocket.WebSocketProxy.Mode#SERVER} , proxy's messages, by
     * default, are ignored to passive scan .
     */
    public WebSocketPassiveScannerManager(AlertManager alertManager) {
        this.alertManager = alertManager;
    }

    /** Listening WebSocketMessages */
    public WebSocketObserver getWebSocketScannerObserver() {
        if (passiveScanThread == null) {
            passiveScanThread = new WebSocketPassiveScanThread(this);
        }
        return passiveScanThread;
    }

    /**
     * Initialize background thread {@link WebSocketPassiveScanThread}. In addition, used as {@link
     * org.zaproxy.zap.extension.websocket.WebSocketSenderListener}
     *
     * @return the background thread
     */
    public WebSocketPassiveScanThread getWebSocketPassiveScanThread() {
        if (passiveScanThread == null) {
            passiveScanThread = new WebSocketPassiveScanThread(this);
        }
        return passiveScanThread;
    }

    /**
     * Initiate or returns the list of WebSocket Passive Scanners
     *
     * @return list of the passive scanners
     */
    private CopyOnWriteArraySet<WebSocketPassiveScannerDecorator> getPassiveScannersSet() {
        if (passiveScannersSet == null) {
            passiveScannersSet = new CopyOnWriteArraySet<>();
        }
        return passiveScannersSet;
    }

    /**
     * Sets/Updates the {@link TableWebSocket} for passive scanner.
     *
     * @param tableWebSocket the table is going to be set
     */
    public void setTable(TableWebSocket tableWebSocket) {
        passiveScanThread.setTable(tableWebSocket);
    }

    public boolean hasTable() {
        return passiveScanThread.hasTable();
    }
    /**
     * Adds the WebSocketPassive Scanner if not null
     *
     * @return {@code true} is passiveScanner was added properly.
     */
    public synchronized boolean add(WebSocketPassiveScanner passiveScanner) {

        if (passiveScanner == null) {
            throw new IllegalArgumentException("Parameter passiveScanner must not be null.");
        }
        WebSocketPassiveScannerDecorator wsPlugin =
                new WebSocketPassiveScannerDecorator(passiveScanner);
        return addPlugin(wsPlugin);
    }

    /**
     * Add a passive scanner to thread safe list
     *
     * @return {@code true} if passive scanner is added to list successfully.
     * @param passiveScanner the WebSocket Passive scan Plugin
     */
    private boolean addPlugin(WebSocketPassiveScannerDecorator passiveScanner) {
        if (getPassiveScannersSet().contains(passiveScanner)) {
            LOGGER.warn(
                    "Insertion of {} is prevent in order to avoid the duplication",
                    passiveScanner.getName());
            return false;
        }
        return getPassiveScannersSet().add(passiveScanner);
    }

    /**
     * Enables or disables all WebSocket Passive Scanners
     *
     * @param enabled {@code true} if the scanners should be enabled, {@code false} otherwise
     */
    public void setAllEnable(boolean enabled) {
        Iterator<WebSocketPassiveScannerDecorator> iterator = this.getIterator();
        while (iterator.hasNext()) {
            iterator.next().setEnabled(enabled);
        }
    }

    /**
     * Enables or disables a WebSocket Passive Scanners
     *
     * @param enabled {@code true} if the scanner should be enabled, {@code false} otherwise
     */
    public void setEnable(WebSocketPassiveScanner scanner, boolean enabled) {

        Iterator<WebSocketPassiveScannerDecorator> iterator = this.getIterator();
        WebSocketPassiveScannerDecorator itScanner;
        while (iterator.hasNext()) {
            itScanner = iterator.next();
            if (itScanner.equals(scanner)) {
                itScanner.setEnabled(enabled);
                return;
            }
        }
    }

    /**
     * Start the background thread where passive scans are running. Do nothing if the background
     * thread have already been running
     */
    public void startThread() {
        if (passiveScanThread != null && !passiveScanThread.isAlive()) {
            passiveScanThread.start();
        } else {
            LOGGER.info("Passive scan thread have already been running");
        }
    }

    /** Shut down the background thread if it have been activated. */
    public void shutdownThread() {
        if (this.passiveScanThread != null && passiveScanThread.isActive()) {
            passiveScanThread.shutdown();
        } else {
            LOGGER.info("Passive scan thread had already been closed");
        }
    }

    public AlertManager getAlertManager() {
        return alertManager;
    }

    /**
     * Drop the passive scanner from the list
     *
     * @return {@code true} if passive scanner is dropped from list successfully.
     */
    public synchronized boolean removeScanner(WebSocketPassiveScanner passiveScanner) {
        return getPassiveScannersSet().remove(new WebSocketPassiveScannerDecorator(passiveScanner));
    }

    /** @return an iterator for all WebSocket Passive Scanners */
    protected Iterator<WebSocketPassiveScannerDecorator> getIterator() {
        return getPassiveScannersSet().iterator();
    }

    public boolean isContained(WebSocketPassiveScanner webSocketPassiveScanner) {
        return getPassiveScannersSet()
                .contains(new WebSocketPassiveScannerDecorator(webSocketPassiveScanner));
    }

    public boolean isServerModeIgnored() {
        return isServerModeIgnored;
    }

    public void setServerModeIgnored(boolean serverModeIgnored) {
        isServerModeIgnored = serverModeIgnored;
    }
}
