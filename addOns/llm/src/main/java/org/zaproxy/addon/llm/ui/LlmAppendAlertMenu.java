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
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.zap.extension.alert.PopupMenuItemAlert;

@SuppressWarnings("serial")
public class LlmAppendAlertMenu extends PopupMenuItemAlert {

    private static final long serialVersionUID = 1L;

    private final LlmChatPanel llmChatPanel;

    public LlmAppendAlertMenu(LlmChatPanel llmChatPanel) {
        super(Constant.messages.getString("llm.menu.append.alert.title"), true);
        this.llmChatPanel = llmChatPanel;
    }

    @Override
    public void performAction(Alert alert) {
        llmChatPanel.appendUntrustedDataToInput(buildStructuredPayload(alert), true);
    }

    protected static Map<String, Object> buildStructuredPayload(Alert alert) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("type", "alert");
        putIfNotBlank(payload, "name", alert.getName());

        int risk = alert.getRisk();
        if (risk >= 0 && risk < Alert.MSG_RISK.length) {
            payload.put("risk", Alert.MSG_RISK[risk]);
        }

        int confidence = alert.getConfidence();
        if (confidence >= 0 && confidence < Alert.MSG_CONFIDENCE.length) {
            payload.put("confidence", Alert.MSG_CONFIDENCE[confidence]);
        }

        putIfNotBlank(payload, "description", alert.getDescription());
        putIfNotBlank(payload, "uri", alert.getUri());
        putIfNotBlank(payload, "param", alert.getParam());
        putIfNotBlank(payload, "attack", alert.getAttack());
        putIfNotBlank(payload, "evidence", alert.getEvidence());
        putIfNotBlank(payload, "otherInfo", alert.getOtherInfo());
        return payload;
    }

    private static void putIfNotBlank(Map<String, Object> payload, String key, String value) {
        if (StringUtils.isNotBlank(value)) {
            payload.put(key, value);
        }
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
