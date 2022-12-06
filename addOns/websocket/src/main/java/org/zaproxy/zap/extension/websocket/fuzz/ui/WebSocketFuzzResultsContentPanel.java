/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.websocket.fuzz.ui;

import java.awt.BorderLayout;
import java.awt.EventQueue;
import javax.swing.Box;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JToolBar;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.fuzz.FuzzResultsContentPanel;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.fuzz.WebSocketFuzzer;
import org.zaproxy.zap.extension.websocket.fuzz.WebSocketFuzzerListener;
import org.zaproxy.zap.utils.StickyScrollbarAdjustmentListener;

@SuppressWarnings("serial")
public class WebSocketFuzzResultsContentPanel extends JPanel
        implements FuzzResultsContentPanel<WebSocketMessageDTO, WebSocketFuzzer> {

    private static final long serialVersionUID = -2258680877665356649L;

    public static final String RESULTS_PANEL_NAME = "websocketFuzzerResultsContentPanel";

    private static final Logger logger =
            LogManager.getLogger(WebSocketFuzzResultsContentPanel.class);

    private static final WebSocketFuzzMessagesViewModel EMPTY_RESULTS_MODEL =
            new WebSocketFuzzMessagesViewModel(-1, null);

    private JToolBar toolbar;
    private JLabel messageCountLabel;
    private JLabel messageCountValueLabel;
    private JLabel errorCountLabel;
    private JLabel errorCountValueLabel;

    private JPanel mainPanel;

    private JScrollPane fuzzResultTableScrollPane;
    private WebSocketFuzzMessagesView fuzzResultTable;

    private WebSocketFuzzer currentFuzzer;
    private WebSocketFuzzerListener websocketFuzzerListener;

    public WebSocketFuzzResultsContentPanel() {
        super(new BorderLayout());

        toolbar = new JToolBar();
        toolbar.setFloatable(false);
        toolbar.setRollover(true);

        messageCountLabel =
                new JLabel(
                        Constant.messages.getString(
                                "websocket.fuzzer.results.toolbar.messagesSent"));
        messageCountValueLabel = new JLabel("0");

        errorCountLabel =
                new JLabel(Constant.messages.getString("websocket.fuzzer.results.toolbar.errors"));
        errorCountValueLabel = new JLabel("0");

        toolbar.add(Box.createHorizontalStrut(4));
        toolbar.add(messageCountLabel);
        toolbar.add(Box.createHorizontalStrut(4));
        toolbar.add(messageCountValueLabel);
        toolbar.add(Box.createHorizontalStrut(32));

        toolbar.add(errorCountLabel);
        toolbar.add(Box.createHorizontalStrut(4));
        toolbar.add(errorCountValueLabel);

        mainPanel = new JPanel(new BorderLayout());

        fuzzResultTable = new WebSocketFuzzMessagesView(EMPTY_RESULTS_MODEL);
        fuzzResultTable.setDisplayPanel(
                View.getSingleton().getRequestPanel(), View.getSingleton().getResponsePanel());

        fuzzResultTableScrollPane = new JScrollPane();
        fuzzResultTableScrollPane.setViewportView(fuzzResultTable.getViewComponent());
        fuzzResultTableScrollPane
                .getVerticalScrollBar()
                .addAdjustmentListener(new StickyScrollbarAdjustmentListener());

        mainPanel.add(fuzzResultTableScrollPane);

        add(toolbar, BorderLayout.PAGE_START);
        add(mainPanel, BorderLayout.CENTER);
    }

    @Override
    public JPanel getPanel() {
        return this;
    }

    @Override
    public void clear() {
        if (!EventQueue.isDispatchThread()) {
            try {
                EventQueue.invokeAndWait(this::clear);
            } catch (Exception e) {
                logger.error(e.getMessage(), e);
            }
            return;
        }

        currentFuzzer = null;
        fuzzResultTable.clear();
    }

    public void clear(WebSocketFuzzer fuzzer) {
        if (currentFuzzer == fuzzer) {
            clear();
        }
    }

    @Override
    public void showFuzzerResults(WebSocketFuzzer fuzzer) {
        if (currentFuzzer != null) {
            currentFuzzer.removeWebSocketFuzzerListener(getWebSocketFuzzerListener());
        }
        currentFuzzer = fuzzer;

        messageCountValueLabel.setText(Integer.toString(currentFuzzer.getMessagesSentCount()));
        int errorCount = currentFuzzer.getErrorCount();
        errorCountValueLabel.setText(Integer.toString(errorCount));

        currentFuzzer.addWebSocketFuzzerListener(getWebSocketFuzzerListener());

        fuzzResultTable.setModel(currentFuzzer.getMessagesModel());
    }

    private WebSocketFuzzerListener getWebSocketFuzzerListener() {
        if (websocketFuzzerListener == null) {
            websocketFuzzerListener = new WebSocketFuzzerListenerImpl();
        }
        return websocketFuzzerListener;
    }

    private class WebSocketFuzzerListenerImpl implements WebSocketFuzzerListener {

        @Override
        public void messageSent(int total) {
            messageCountValueLabel.setText(Integer.toString(total));
        }

        @Override
        public void errorFound(int total) {
            errorCountValueLabel.setText(Integer.toString(total));
        }
    }
}
