/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.zap.extension.websocket.manualsend;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.addon.requester.MessageEditorDialog;
import org.zaproxy.addon.requester.MessageEditorPanel;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.ui.WebSocketMessagesPopupMenuItem;
import org.zaproxy.zap.extension.websocket.ui.WebSocketMessagesView;

public class ResendWebSocketMessageEditorDialog extends MessageEditorDialog {

    private static final long serialVersionUID = 1L;

    private MessageEditorPanel panel;

    public ResendWebSocketMessageEditorDialog(MessageEditorPanel panel) {
        super(panel);

        this.panel = panel;

        setTitle(Constant.messages.getString("websocket.manual_send.popup"));
    }

    @Override
    public void load(ExtensionHook extensionHook) {
        super.load(extensionHook);

        extensionHook.getHookMenu().addPopupMenuItem(new ResendWebSocketMessageMenuItem());
    }

    private class ResendWebSocketMessageMenuItem extends WebSocketMessagesPopupMenuItem {

        private static final long serialVersionUID = 1L;

        @Override
        protected String getMenuText() {
            return Constant.messages.getString("websocket.manual_send.resend.menu");
        }

        @Override
        protected void performAction() {
            WebSocketMessageDTO message = getSelectedMessageDTO();
            if (message == null) {
                return;
            }

            panel.setMessage(message);
            ResendWebSocketMessageEditorDialog.this.setVisible(true);
        }

        @Override
        protected String getInvokerName() {
            return WebSocketMessagesView.PANEL_NAME;
        }

        @Override
        public boolean isSafe() {
            return false;
        }
    }
}
