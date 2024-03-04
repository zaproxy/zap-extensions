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
package org.zaproxy.addon.requester.internal;

import java.awt.event.KeyEvent;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.requester.ExtensionRequester;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.view.ZapMenuItem;

@SuppressWarnings("serial")
public class SendHttpMessageEditorDialog extends AbstractHttpMessageEditorDialog {

    private static final long serialVersionUID = 1L;

    private ExtensionRequester extensionRequester;

    public SendHttpMessageEditorDialog(
            ExtensionRequester extensionRequester, ManualHttpRequestEditorPanel panel) {
        super("requester.send.dialog.title", panel);
        this.extensionRequester = extensionRequester;
    }

    @Override
    public void load(ExtensionHook extensionHook) {
        super.load(extensionHook);

        ZapMenuItem menuItem =
                new ZapMenuItem(
                        "requester.send.toolsmenuitem",
                        View.getSingleton().getMenuShortcutKeyStroke(KeyEvent.VK_M, 0, false));
        menuItem.setIcon(ExtensionRequester.getManualIcon());
        menuItem.addActionListener(
                e -> {
                    Message message = extensionRequester.getSelectedMsg();
                    if (message instanceof HttpMessage
                            && !((HttpMessage) message).getRequestHeader().isEmpty()) {
                        getPanel().setMessage(message);
                    } else {
                        getPanel().setDefaultMessage();
                    }
                    setVisible(true);
                });
        extensionHook.getHookMenu().addToolsMenuItem(menuItem);

        PopupMenuResendMessage popupMenuResendMessage =
                new PopupMenuResendMessage(
                        Constant.messages.getString("requester.resend.popup"),
                        ExtensionRequester.getManualIcon(),
                        msg -> {
                            getPanel().setMessage(msg);
                            setVisible(true);
                        });
        extensionHook.getHookMenu().addPopupMenuItem(popupMenuResendMessage);
    }
}
