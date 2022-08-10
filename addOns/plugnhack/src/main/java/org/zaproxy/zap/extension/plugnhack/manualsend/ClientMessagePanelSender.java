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
package org.zaproxy.zap.extension.plugnhack.manualsend;

import org.parosproxy.paros.extension.manualrequest.MessageSender;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.extension.plugnhack.ClientMessage;
import org.zaproxy.zap.extension.plugnhack.ExtensionPlugNHack;

/** Knows how to send {@link HttpMessage} objects. Contains a list of valid WebSocket channels. */
@SuppressWarnings("serial")
public class ClientMessagePanelSender implements MessageSender {

    private ExtensionPlugNHack extension = null;

    public ClientMessagePanelSender(ExtensionPlugNHack extension) {
        this.extension = extension;
    }

    @Override
    public void handleSendMessage(Message aMessage) {
        this.extension.resend((ClientMessage) aMessage);
    }

    @Override
    public void cleanup() {}
}
