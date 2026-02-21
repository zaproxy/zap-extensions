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
package org.zaproxy.addon.llm.actions;

public enum LlmZapActionType {
    SET_HISTORY_NOTE("set_history_note"),
    ADD_HISTORY_TAGS("add_history_tags"),
    OPEN_REQUESTER_DIALOG("open_requester_dialog"),
    OPEN_REQUESTER_TAB("open_requester_tab"),
    OPEN_FUZZER("open_fuzzer");

    private final String id;

    LlmZapActionType(String id) {
        this.id = id;
    }

    public String getId() {
        return id;
    }

    public static LlmZapActionType fromId(String id) {
        if (id == null) {
            return null;
        }
        String normalized = id.trim().toLowerCase().replace('-', '_');

        // Backwards/forwards compatibility aliases (model might invent these).
        if ("open_request_editor".equals(normalized)) {
            return OPEN_REQUESTER_DIALOG;
        }
        if ("open_requester".equals(normalized)) {
            return OPEN_REQUESTER_TAB;
        }
        if ("open_http_fuzzer".equals(normalized)) {
            return OPEN_FUZZER;
        }

        for (LlmZapActionType t : values()) {
            if (t.id.equals(normalized)) {
                return t;
            }
        }
        return null;
    }
}
