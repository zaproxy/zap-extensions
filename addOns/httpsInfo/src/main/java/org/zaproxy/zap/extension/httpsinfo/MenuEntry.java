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
package org.zaproxy.zap.extension.httpsinfo;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.view.messagecontainer.http.HttpMessageContainer;
import org.zaproxy.zap.view.popup.PopupMenuItemHttpMessageContainer;

/** This class defines the extension's popup menu item. */
public class MenuEntry extends PopupMenuItemHttpMessageContainer {

    private static final long serialVersionUID = 1L;
    private final ExtensionHttpsInfo extension;

    public MenuEntry(String label, ExtensionHttpsInfo extension) {
        super(label);
        this.extension = extension;
    }

    @Override
    public boolean isEnableForInvoker(Invoker invoker, HttpMessageContainer httpMessageContainer) {
        return invoker == Invoker.SITES_PANEL || invoker == Invoker.HISTORY_PANEL;
    }

    @Override
    protected boolean isButtonEnabledForSelectedHttpMessage(HttpMessage message) {
        return message.getRequestHeader().isSecure();
    }

    @Override
    protected void performAction(HttpMessage msg) {
        extension.addTab(msg);
    }
}
