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
package org.zaproxy.zap.extension.plugnhack.manualsend;

import java.awt.Component;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.zaproxy.addon.requester.MessageEditorDialog;
import org.zaproxy.addon.requester.MessageEditorPanel;
import org.zaproxy.zap.extension.plugnhack.ClientMessage;
import org.zaproxy.zap.extension.plugnhack.ClientsPanel;
import org.zaproxy.zap.extension.plugnhack.ExtensionPlugNHack;

@SuppressWarnings("serial")
class ResendClientMessageEditorDialog extends MessageEditorDialog {

    private static final long serialVersionUID = 1L;

    private final MessageEditorPanel panel;
    private final ExtensionPlugNHack extension;

    ResendClientMessageEditorDialog(ExtensionPlugNHack extension, MessageEditorPanel panel) {
        super(panel);

        this.extension = extension;
        this.panel = panel;
        setTitle(Constant.messages.getString("plugnhack.resend.dialog.title"));
    }

    @Override
    public void load(ExtensionHook extensionHook) {
        super.load(extensionHook);

        extensionHook.getHookMenu().addPopupMenuItem(new PopupMenuResend());
    }

    private class PopupMenuResend extends ExtensionPopupMenuItem {

        private static final long serialVersionUID = 1L;

        PopupMenuResend() {
            super(Constant.messages.getString("plugnhack.resend.popup"));

            addActionListener(
                    e -> {
                        ClientMessage msg = extension.getSelectedClientMessage();

                        if (msg != null) {
                            panel.setMessage(new ClientMessage(msg.getClientId(), msg.getJson()));
                            ResendClientMessageEditorDialog.this.setVisible(true);
                        }
                    });
        }

        @Override
        public boolean isEnableForComponent(Component invoker) {
            if (ClientsPanel.CLIENTS_MESSAGE_TABLE_NAME.equals(invoker.getName())) {
                ClientMessage msg = extension.getSelectedClientMessage();
                if (msg != null) {
                    // Can only resend if the page is open
                    setEnabled(extension.isBeingMonitored(msg.getClientId()));
                    return true;
                }
            }
            return false;
        }

        @Override
        public boolean isSafe() {
            return false;
        }
    }
}
