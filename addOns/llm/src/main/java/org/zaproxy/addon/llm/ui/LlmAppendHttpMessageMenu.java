/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.llm.ui;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.view.popup.PopupMenuItemHttpMessageContainer;

@SuppressWarnings("serial")
public class LlmAppendHttpMessageMenu extends PopupMenuItemHttpMessageContainer {

    private static final long serialVersionUID = 1L;

    private final LlmChatPanel llmChatPanel;
    private final boolean includeRequest;
    private final boolean includeResponse;

    public LlmAppendHttpMessageMenu(
            LlmChatPanel llmChatPanel,
            String label,
            boolean includeRequest,
            boolean includeResponse) {
        super(label, true);
        this.llmChatPanel = llmChatPanel;
        this.includeRequest = includeRequest;
        this.includeResponse = includeResponse;
    }

    @Override
    public void performAction(HttpMessage httpMessage) {
        appendHttpMessageToInput(httpMessage, includeRequest, includeResponse);
    }

    private void appendHttpMessageToInput(
            HttpMessage httpMessage, boolean includeRequest, boolean includeResponse) {
        StringBuilder sb = new StringBuilder();

        LlmChatPanel.appendFormattedMsg(
                sb,
                Constant.messages.getString("llm.chat.append.http.message.label"),
                httpMessage.getRequestHeader().getURI().toString());
        sb.append("\n");

        if (includeRequest) {
            sb.append(Constant.messages.getString("llm.chat.append.http.request.header"))
                    .append("\n");
            sb.append(httpMessage.getRequestHeader().toString());
            if (httpMessage.getRequestBody().length() > 0) {
                sb.append("\n");
                sb.append(httpMessage.getRequestBody().toString());
            }
            sb.append("\n\n");
        }

        if (includeResponse && !httpMessage.getResponseHeader().isEmpty()) {
            sb.append(Constant.messages.getString("llm.chat.append.http.response.header"))
                    .append("\n");
            sb.append(httpMessage.getResponseHeader().toString());
            if (httpMessage.getResponseBody().length() > 0) {
                sb.append("\n");
                sb.append(httpMessage.getResponseBody().toString());
            }
            sb.append("\n");
        }

        llmChatPanel.appendToInput(sb.toString(), true);
    }

    @Override
    public String getParentMenuName() {
        return Constant.messages.getString("llm.aiassisted.popup");
    }

    @Override
    public boolean isSubMenu() {
        return true;
    }

    @Override
    public boolean isSafe() {
        return true;
    }
}
