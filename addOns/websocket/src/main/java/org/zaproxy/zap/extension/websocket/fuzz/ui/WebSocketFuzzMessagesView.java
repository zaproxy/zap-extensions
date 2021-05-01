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

import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.util.List;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.websocket.ui.WebSocketMessagesView;
import org.zaproxy.zap.extension.websocket.ui.WebSocketMessagesViewModel;

/**
 * The fuzzing tab with its WebSocket messsages view differs slightly from the messages view in the
 * WebSockets tab, as there are 2 more columns here.
 *
 * <p>Moreover it is not backed by the database but a {@link List}. You have to add messages
 * yourself via {@link WebSocketFuzzMessagesView#addFuzzResult(FuzzResult)}.
 */
public class WebSocketFuzzMessagesView extends WebSocketMessagesView {

    public static final String TABLE_NAME = "fuzz.websocket.table";

    public WebSocketFuzzMessagesView(WebSocketMessagesViewModel model) {
        super(model);
    }

    @Override
    protected String getViewComponentName() {
        return TABLE_NAME;
    }

    @Override
    public void setColumnWidths() {
        super.setColumnWidths();

        // state
        setColumnWidth(6, 75, 80);

        // fuzz part (do not set preferred size => stretches to maximum)
        setColumnWidth(7, 50, -1);
    }

    @Override
    protected MouseListener getMouseListener() {
        final JTable view = this.view;

        return new MouseAdapter() {

            @Override
            public void mousePressed(MouseEvent e) {

                if (SwingUtilities.isRightMouseButton(e)) {

                    // Select table item
                    int row = view.rowAtPoint(e.getPoint());
                    if (row < 0 || !view.getSelectionModel().isSelectedIndex(row)) {
                        view.getSelectionModel().clearSelection();
                        if (row >= 0) {
                            view.getSelectionModel().setSelectionInterval(row, row);
                        }
                    }

                    View.getSingleton().getPopupMenu().show(e.getComponent(), e.getX(), e.getY());
                }
            }
        };
    }

    public void clear() {
        ((WebSocketFuzzMessagesViewModel) model).clear();
    }
}
