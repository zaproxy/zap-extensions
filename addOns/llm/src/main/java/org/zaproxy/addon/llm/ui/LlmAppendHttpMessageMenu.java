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

import java.util.LinkedHashMap;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.view.popup.PopupMenuItemHttpMessageContainer;

@SuppressWarnings("serial")
public class LlmAppendHttpMessageMenu extends PopupMenuItemHttpMessageContainer {

    private static final long serialVersionUID = 1L;
    private static final Logger LOGGER = LogManager.getLogger(LlmAppendHttpMessageMenu.class);

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
        llmChatPanel.appendUntrustedDataToInput(
                buildStructuredPayload(httpMessage, includeRequest, includeResponse), true);
    }

    protected static Map<String, Object> buildStructuredPayload(
            HttpMessage httpMessage, boolean includeRequest, boolean includeResponse) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("type", "http_message");
        payload.put("uri", httpMessage.getRequestHeader().getURI().toString());

        if (includeRequest) {
            Map<String, Object> request = new LinkedHashMap<>();
            request.put("header", httpMessage.getRequestHeader().toString());
            if (httpMessage.getRequestBody().length() > 0) {
                request.put("body", httpMessage.getRequestBody().toString());
            }
            payload.put("request", request);
        }

        if (includeResponse && !httpMessage.getResponseHeader().isEmpty()) {
            Map<String, Object> response = new LinkedHashMap<>();
            response.put("header", httpMessage.getResponseHeader().toString());
            if (httpMessage.getResponseBody().length() > 0) {
                response.put("body", httpMessage.getResponseBody().toString());
            }
            payload.put("response", response);
        }

        return payload;
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
