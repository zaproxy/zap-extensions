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

import java.awt.EventQueue;
import java.util.ArrayList;
import java.util.List;
import javax.swing.table.TableModel;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.db.DatabaseException;
import org.zaproxy.zap.extension.websocket.WebSocketFuzzMessageDTO;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.db.TableWebSocket;
import org.zaproxy.zap.extension.websocket.fuzz.WebSocketFuzzResult;
import org.zaproxy.zap.extension.websocket.ui.WebSocketMessagesViewModel;

/**
 * This {@link TableModel} is also backed by the database, but has got some additional columns.
 * Moreover, erroneous entries are stored into an extra {@link List}.
 */
@SuppressWarnings("serial")
public class WebSocketFuzzMessagesViewModel extends WebSocketMessagesViewModel {
    private static final long serialVersionUID = 5435325545219552543L;

    private static final Logger logger = LogManager.getLogger(WebSocketFuzzMessagesViewModel.class);

    /** Names of new columns. */
    private static final String[] COLUMN_NAMES = {
        Constant.messages.getString("websocket.table.header.state"),
        Constant.messages.getString("websocket.table.header.fuzz")
    };

    /** Number of columns in this table model increased. */
    private static final int COLUMN_COUNT =
            WebSocketMessagesViewModel.COLUMN_COUNT + COLUMN_NAMES.length;

    /** This list holds all erroneous messages for this view model. */
    private List<WebSocketMessageDTO> erroneousMessages = new ArrayList<>();

    private final int currentFuzzId;

    private static final String msgSuccess;
    private static final String msgFail;

    static {
        msgSuccess = Constant.messages.getString("websocket.fuzz.success");
        msgFail = Constant.messages.getString("websocket.fuzz.fail");
    }

    public WebSocketFuzzMessagesViewModel(int currentFuzzId, TableWebSocket table) {
        super(table);

        this.currentFuzzId = currentFuzzId;
    }

    /** @return number of columns */
    @Override
    public int getColumnCount() {
        return COLUMN_COUNT;
    }

    /** @return name of the given column index */
    @Override
    public String getColumnName(int columnIndex) {
        final int totalParent = WebSocketMessagesViewModel.COLUMN_COUNT;
        if (columnIndex < totalParent) {
            return super.getColumnName(columnIndex);
        }
        return COLUMN_NAMES[columnIndex - totalParent];
    }

    /** Return values of new columns. */
    @Override
    public Object getRealValueAt(WebSocketMessageDTO message, int columnIndex) {
        if (message instanceof WebSocketFuzzMessageDTO) {
            WebSocketFuzzMessageDTO fuzzMessage = (WebSocketFuzzMessageDTO) message;
            switch (columnIndex) {
                case 6:
                    String state = "";
                    switch (fuzzMessage.state) {
                        case SUCCESSFUL:
                            state = msgSuccess;
                            break;
                        case ERROR:
                            state = msgFail;
                            break;
                        default:
                    }
                    return state;

                case 7:
                    return fuzzMessage.fuzz;
            }
        }
        return super.getRealValueAt(message, columnIndex);
    }

    /** @return type of column for given column index */
    @Override
    public Class<?> getColumnClass(int columnIndex) {
        switch (columnIndex) {
            case 6:
            case 7:
                return String.class;
            default:
                return super.getColumnClass(columnIndex);
        }
    }

    /** Row count is determined by size of messages list. */
    @Override
    protected WebSocketMessageDTO getCriterionMessage() {
        WebSocketFuzzMessageDTO fuzzMessage = new WebSocketFuzzMessageDTO();
        fuzzMessage.fuzzId = currentFuzzId;
        return fuzzMessage;
    }

    /**
     * Adds new message, that failed to be sent over channel.
     *
     * @param message
     */
    private void addErroneousWebSocketMessage(WebSocketFuzzMessageDTO message) {
        erroneousMessages.add(message);

        int rowCount = getRowCount();
        fireTableRowsInserted(rowCount, rowCount);
    }

    @Override
    public int getRowCount() {
        return erroneousMessages.size() + super.getRowCount();
    }

    @Override
    protected void clear() {
        super.clear();
        erroneousMessages.clear();
    }

    @Override
    protected List<WebSocketMessageDTO> loadPage(int offset, int length) {
        // erroneous messages are put onto the end of list
        int sqlRowCount = super.getRowCount();
        synchronized (erroneousMessages) {
            int erroneousRowCount = erroneousMessages.size();

            if (offset >= sqlRowCount) {
                offset = offset - (sqlRowCount - 1);
                return new ArrayList<>(
                        erroneousMessages.subList(
                                offset, Math.min(erroneousRowCount, offset + length)));
            } else if (offset + length >= sqlRowCount) {
                int sqlLength = sqlRowCount - offset;
                List<WebSocketMessageDTO> page = super.loadPage(offset, sqlLength);
                page.addAll(
                        erroneousMessages.subList(
                                0, Math.min(erroneousRowCount, length - sqlLength)));
                return page;
            } else {
                return super.loadPage(offset, length);
            }
        }
    }

    public void addResult(final WebSocketFuzzResult result, int count, boolean forceRefresh) {
        final WebSocketFuzzMessageDTO message = result.getWebSocketMessage();
        if (message.state == WebSocketFuzzMessageDTO.State.ERROR) {
            EventQueue.invokeLater(() -> addErroneousWebSocketMessage(message));
        } else {
            try {
                getTable().insertMessage(message);
                if (count % 10 == 0 || forceRefresh) {
                    try {
                        fireMessageArrived(message);
                    } catch (IndexOutOfBoundsException e) {
                    }
                }
            } catch (DatabaseException e) {
                logger.warn("Failed to persist fuzzer message:", e);
            }
        }
    }
}
