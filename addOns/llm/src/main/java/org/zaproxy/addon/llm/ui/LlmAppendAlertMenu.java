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

import java.awt.Component;
import java.util.Set;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.addon.llm.ExtensionLlm;
import org.zaproxy.zap.extension.alert.PopupMenuItemAlert;

@SuppressWarnings("serial")
public class LlmAppendAlertMenu extends PopupMenuItemAlert {

    private static final long serialVersionUID = 1L;

    private final ExtensionLlm extension;

    public LlmAppendAlertMenu(ExtensionLlm extension) {
        super(Constant.messages.getString("llm.menu.append.alert.title"), true);
        this.extension = extension;
    }

    @Override
    public void performAction(Alert alert) {
        LlmChatPanel chatPanel = extension.getLlmChatPanelPublic();
        if (chatPanel != null) {
            chatPanel.appendAlertToInput(alert);
        }
    }

    @Override
    protected void performActions(Set<Alert> alerts) {
        LlmChatPanel chatPanel = extension.getLlmChatPanelPublic();
        if (chatPanel != null && !alerts.isEmpty()) {
            for (Alert alert : alerts) {
                chatPanel.appendAlertToInput(alert);
            }
        }
    }

    @Override
    public boolean isEnableForComponent(Component invoker) {
        return super.isEnableForComponent(invoker);
    }

    @Override
    public boolean isSafe() {
        return true;
    }
}
