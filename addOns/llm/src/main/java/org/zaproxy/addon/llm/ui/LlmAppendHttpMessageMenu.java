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

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.llm.ExtensionLlm;
import org.zaproxy.zap.view.popup.PopupMenuItemHttpMessageContainer;

@SuppressWarnings("serial")
public class LlmAppendHttpMessageMenu extends PopupMenuItemHttpMessageContainer {

    private static final long serialVersionUID = 1L;

    private final ExtensionLlm extension;
    private final boolean includeRequest;
    private final boolean includeResponse;

    public LlmAppendHttpMessageMenu(
            ExtensionLlm extension, String label, boolean includeRequest, boolean includeResponse) {
        super(label, true);
        this.extension = extension;
        this.includeRequest = includeRequest;
        this.includeResponse = includeResponse;
    }

    @Override
    public void performAction(HttpMessage httpMessage) {
        LlmChatPanel chatPanel = extension.getLlmChatPanelPublic();
        if (chatPanel != null) {
            chatPanel.appendHttpMessageToInput(httpMessage, includeRequest, includeResponse);
        }
    }

    @Override
    public boolean isSafe() {
        return true;
    }
}
