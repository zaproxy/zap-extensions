/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.zap.extension.requester;

import java.awt.Toolkit;
import java.awt.event.KeyEvent;
import javax.swing.KeyStroke;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.view.messagecontainer.http.HttpMessageContainer;
import org.zaproxy.zap.view.popup.PopupMenuItemHttpMessageContainer;

public class RightClickMsgMenuRequester extends PopupMenuItemHttpMessageContainer {

    private static final long serialVersionUID = 1L;
    private ExtensionRequester extension = null;

    /** @param label */
    @SuppressWarnings("deprecation")
    public RightClickMsgMenuRequester(String label) {
        super(label);
        this.setAccelerator(
                KeyStroke.getKeyStroke(
                        // TODO Remove warn suppression and use View.getMenuShortcutKeyStroke with
                        // newer ZAP (or use getMenuShortcutKeyMaskEx() with Java 10+)
                        KeyEvent.VK_W,
                        Toolkit.getDefaultToolkit().getMenuShortcutKeyMask(),
                        false));
    }

    @Override
    public void performAction(HttpMessage msg) {
        getExtension().newRequesterPane(msg);
    }

    public ExtensionRequester getExtension() {
        return extension;
    }

    public void setExtension(ExtensionRequester extension) {
        this.extension = extension;
    }

    @Override
    public boolean isEnableForInvoker(Invoker invoker, HttpMessageContainer httpMessageContainer) {
        // This is enabled for all tabs which list messages
        // You can examine the invoker is you wish to restrict this to specific tabs
        return true;
    }
}
