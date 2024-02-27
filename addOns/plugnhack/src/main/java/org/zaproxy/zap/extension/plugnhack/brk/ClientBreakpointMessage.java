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
package org.zaproxy.zap.extension.plugnhack.brk;

import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.brk.AbstractBreakPointMessage;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.extension.plugnhack.ClientMessage;

public class ClientBreakpointMessage extends AbstractBreakPointMessage {

    private static final String TYPE = "Client";

    private String messageType;
    private String client;
    private Pattern payloadPattern = null;

    public ClientBreakpointMessage(String messageType, String client, String payloadPattern)
            throws PatternSyntaxException {
        this.messageType = messageType;
        this.client = client;
        setPayloadPattern(payloadPattern);
    }

    @Override
    public String getType() {
        return TYPE;
    }

    public String getPayloadPattern() {
        if (payloadPattern != null) {
            return payloadPattern.pattern();
        }
        return null;
    }

    public String getMessageType() {
        return messageType;
    }

    public void setMessageType(String messageType) {
        if (messageType == null || messageType.length() == 0) {
            this.messageType = null;
        } else {
            this.messageType = messageType;
        }
    }

    public String getClient() {
        return client;
    }

    public void setClient(String client) {
        if (client == null || client.length() == 0) {
            this.client = null;
        } else {
            this.client = client;
        }
    }

    /**
     * Catch {@link PatternSyntaxException} in dialog & show warning. You can do this by <code>
     * View.getSingleton().showWarningDialog(message)</code>.
     *
     * @param PayloadPattern
     * @throws PatternSyntaxException
     */
    public void setPayloadPattern(String PayloadPattern) throws PatternSyntaxException {
        if (PayloadPattern == null || PayloadPattern.length() == 0) {
            this.payloadPattern = null;
        } else {
            this.payloadPattern = Pattern.compile(PayloadPattern, Pattern.MULTILINE);
        }
    }

    @Override
    public boolean match(Message aMessage, boolean isRequest, boolean onlyIfInScope) {
        if (aMessage instanceof ClientMessage) {
            ClientMessage msg = (ClientMessage) aMessage;

            if (this.messageType != null && !this.messageType.equals(msg.getType())) {
                // Didnt match the message type
                return false;
            }

            if (this.client != null && !this.client.equals(msg.getClientId())) {
                // Didnt match the client id
                return false;
            }

            if (this.payloadPattern != null && !this.payloadPattern.matcher(msg.getData()).find()) {
                // Didnt match the payload pattern
                return false;
            }

            return true;
        }

        return false;
    }

    @Override
    public String getDisplayMessage() {
        return Constant.messages.getString(
                "plugnhack.brk.display",
                messageType == null ? "*" : messageType,
                client == null ? "*" : client,
                getPayloadPattern() == null ? "" : getPayloadPattern());
    }
}
