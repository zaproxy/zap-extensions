/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP Development Team
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
package org.zaproxy.zap.extension.websocket.ui;

import javax.swing.JTable;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;

/** Helper for context menus on {@link WebSocketMessagesView}. */
public class WebSocketPopupHelper {

    private JTable messagesView;

    public WebSocketPopupHelper(JTable invoker) {
        messagesView = invoker;
    }

    public WebSocketMessageDTO getSelectedMessage() {
        WebSocketMessageDTO message = null;
        int[] rows = messagesView.getSelectedRows();
        if (rows.length == 1) {
            int index = rows[0];
            WebSocketMessagesViewModel model = (WebSocketMessagesViewModel) messagesView.getModel();
            message = model.getDTO(index);
        }
        return message;
    }

    public boolean isOneRowSelected() {
        return 1 == messagesView.getSelectedRowCount();
    }
}
