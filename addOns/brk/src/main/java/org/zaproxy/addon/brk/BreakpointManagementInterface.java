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
package org.zaproxy.addon.brk;

import org.parosproxy.paros.control.Control.Mode;
import org.zaproxy.zap.extension.httppanel.Message;

public interface BreakpointManagementInterface {

    boolean isBreakRequest();

    boolean isBreakResponse();

    boolean isBreakAll();

    void breakpointHit();

    boolean isHoldMessage(Message aMessage);

    boolean isStepping();

    boolean isToBeDropped();

    Message getMessage();

    void setMessage(Message aMessage, boolean isRequest);

    boolean isRequest();

    void saveMessage(boolean isRequest);

    void clearAndDisableRequest();

    void clearAndDisableResponse();

    void init();

    void reset();

    void sessionModeChanged(Mode mode);

    void setBreakAllRequests(boolean brk);

    void setBreakAllResponses(boolean brk);

    void setBreakAll(boolean brk);

    void step();

    void cont();

    void drop();

    void breakpointDisplayed();
}
