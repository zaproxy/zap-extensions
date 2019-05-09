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

import org.zaproxy.zap.extension.brk.BreakpointManagementInterface;
import org.zaproxy.zap.extension.brk.BreakpointMessageHandler2;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.extension.plugnhack.ClientMessage;

/**
 * Wraps WebSocket specific options to determine if breakpoint should be applied on given {@link
 * ClientMessage}.
 */
public class ClientBreakpointMessageHandler extends BreakpointMessageHandler2 {

    public ClientBreakpointMessageHandler(BreakpointManagementInterface breakMgmt) {
        super(breakMgmt);
    }

    /**
     * Only break on all requests when 'Break on all' is enabled for WebSockets.
     *
     * @param aMessage
     * @param isRequest
     * @return True if it breaks on all requests.
     */
    @Override
    public boolean isBreakOnAllRequests(Message aMessage, boolean isRequest) {
        if (aMessage instanceof ClientMessage) {
            ClientMessage cmsg = (ClientMessage) aMessage;
            if (!cmsg.getBoolean("intercept")) {
                // Only break on messages that have intercept=true set
                return false;
            }
        }
        return super.isBreakOnAllRequests(aMessage, isRequest);
    }

    /**
     * Only break on all responses when 'Break on all' is enabled for WebSockets.
     *
     * @param aMessage
     * @param isRequest
     * @return True if it breaks on all responses.
     */
    @Override
    public boolean isBreakOnAllResponses(Message aMessage, boolean isRequest) {
        if (aMessage instanceof ClientMessage) {
            ClientMessage cmsg = (ClientMessage) aMessage;
            if (!cmsg.getBoolean("intercept")) {
                // Only break on messages that have intercept=true set
                return false;
            }
        }
        return super.isBreakOnAllResponses(aMessage, isRequest);
    }

    /**
     * Only break on stepping if opcode is allowed.
     *
     * @param aMessage
     * @param isRequest
     * @return True if it breaks on stepping through action.
     */
    @Override
    protected boolean isBreakOnStepping(Message aMessage, boolean isRequest) {
        return aMessage instanceof ClientMessage && super.isBreakOnStepping(aMessage, isRequest);
    }
}
