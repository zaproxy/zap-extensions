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
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.view.ZapMenuItem;

public class SendWebSocketMessageEditorDialog extends MessageEditorDialog {

    private static final long serialVersionUID = 1L;

    private MessageEditorPanel panel;

    public SendWebSocketMessageEditorDialog(MessageEditorPanel panel) {
        super(panel);

        this.panel = panel;

        setTitle(Constant.messages.getString("websocket.manual_send.menu"));
    }

    @Override
    public void load(ExtensionHook extensionHook) {
        super.load(extensionHook);

        ZapMenuItem menuItem = new ZapMenuItem("websocket.manual_send.menu");
        menuItem.addActionListener(
                e -> {
                    Message message = panel.getMessage();
                    if (message == null
                            || message instanceof WebSocketMessageDTO
                                    && ((WebSocketMessageDTO) message).getOpcode() == null) {
                        panel.setDefaultMessage();
                    }
                    setVisible(true);
                });
        extensionHook.getHookMenu().addToolsMenuItem(menuItem);
    }
}
