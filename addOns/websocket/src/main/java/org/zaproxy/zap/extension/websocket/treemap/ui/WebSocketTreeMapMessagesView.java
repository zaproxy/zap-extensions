/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.zap.extension.websocket.treemap.ui;

import java.awt.EventQueue;
import java.util.concurrent.LinkedBlockingQueue;
import javax.swing.event.TreeSelectionListener;
import org.apache.log4j.Logger;
import org.zaproxy.zap.extension.httppanel.HttpPanel;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.treemap.nodes.structural.WebSocketNodeInterface;

public class WebSocketTreeMapMessagesView implements Runnable {

    private static final Logger logger = Logger.getLogger(WebSocketTreeMapMessagesView.class);

    private HttpPanel requestPanel;
    private HttpPanel responsePanel;

    private WebSocketTreeMapModel model;

    LinkedBlockingQueue<WebSocketMessageDTO> displayQueue;

    private Thread thread = null;

    WebSocketTreeMapMessagesView(WebSocketTreeMapModel model) {
        this.model = model;

        displayQueue = new LinkedBlockingQueue<>();
    }

    protected TreeSelectionListener getWebSocketTreeMapListener() {

        return treeSelectionEvent -> {
            if (treeSelectionEvent.getNewLeadSelectionPath() == null) return;

            WebSocketNodeInterface node =
                    (WebSocketNodeInterface) treeSelectionEvent.getPath().getLastPathComponent();
            if (node.isLeaf()) {
                readAndDisplay(node.getMessage());
            }
        };
    }

    @Override
    public void run() {

        WebSocketMessageDTO message;
        int count = 0;

        do {
            synchronized (displayQueue) {
                count = displayQueue.size();
                if (count == 0) {
                    break;
                }

                message = displayQueue.poll();
            }

            try {
                final WebSocketMessageDTO msg = message;

                EventQueue.invokeAndWait(
                        () -> {
                            if (msg.isOutgoing.booleanValue()) {
                                requestPanel.setMessage(msg);
                                responsePanel.clearView(false);
                                requestPanel.setTabFocus();
                            } else {
                                requestPanel.clearView(true);
                                responsePanel.setMessage(msg, true);
                                responsePanel.setTabFocus();
                            }
                        });
            } catch (Exception e) {
                logger.error(e.getMessage(), e);
            }

            try {
                Thread.sleep(200);
            } catch (Exception e) {
            }

        } while (true);
    }

    private void readAndDisplay(final WebSocketMessageDTO message) {
        if (message == null) {
            return;
        }

        synchronized (displayQueue) {
            if (displayQueue.size() > 0) {
                displayQueue.clear();
            }
            displayQueue.add(message);
        }

        if (thread != null && thread.isAlive()) {
            return;
        }

        thread = new Thread(this);
        thread.setPriority(Thread.NORM_PRIORITY);
        thread.start();
    }

    public void setDisplayPanel(HttpPanel requestPanel, HttpPanel responsePanel) {
        this.requestPanel = requestPanel;
        this.responsePanel = responsePanel;
    }
}
