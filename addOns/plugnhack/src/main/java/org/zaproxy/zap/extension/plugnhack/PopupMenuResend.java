/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.plugnhack;

import java.awt.Component;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.zaproxy.zap.extension.plugnhack.manualsend.ManualClientMessageSendEditorDialog;

@SuppressWarnings("serial")
public class PopupMenuResend extends ExtensionPopupMenuItem {

    private static final long serialVersionUID = 1L;

    private ExtensionPlugNHack extension;

    /** */
    public PopupMenuResend(ExtensionPlugNHack extension) {
        super();
        this.extension = extension;
        this.initialize();
    }

    private void initialize() {
        this.setText(Constant.messages.getString("plugnhack.resend.popup"));

        this.addActionListener(
                e -> {
                    ClientMessage msg = extension.getSelectedClientMessage();

                    if (msg != null) {
                        ClientMessage msg2 = new ClientMessage(msg.getClientId(), msg.getJson());
                        ManualClientMessageSendEditorDialog dialog = extension.getResendDialog();
                        dialog.setMessage(msg2);
                        dialog.setVisible(true);
                    }
                });
    }

    @Override
    public boolean isEnableForComponent(Component invoker) {

        if (invoker.getName() != null
                && invoker.getName().equals(ClientsPanel.CLIENTS_MESSAGE_TABLE_NAME)) {

            ClientMessage msg = extension.getSelectedClientMessage();

            if (msg != null) {
                // Can only resend if the page is open
                this.setEnabled(extension.isBeingMonitored(msg.getClientId()));
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
