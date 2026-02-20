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

import java.util.ArrayList;
import java.util.List;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.model.HistoryReference;

public class LlmZapActionsExecutor {

    public record ApplyResult(int appliedCount, List<String> errors) {}

    public ApplyResult apply(List<LlmZapAction> actions) {
        if (actions == null || actions.isEmpty()) {
            return new ApplyResult(0, List.of());
        }

        int applied = 0;
        List<String> errors = new ArrayList<>();
        for (LlmZapAction action : actions) {
            if (action == null || action.type() == null) {
                continue;
            }

            HistoryReference href;
            try {
                href = new HistoryReference(action.historyId());
            } catch (Exception e) {
                errors.add(
                        "Failed to load history_id "
                                + action.historyId()
                                + ": "
                                + e.getMessage());
                continue;
            }

            switch (action.type()) {
                case SET_HISTORY_NOTE -> {
                    String note = StringUtils.defaultString(action.note());
                    href.setNote(note);
                    applied++;
                }
                case ADD_HISTORY_TAGS -> {
                    if (action.tags() != null) {
                        List<String> existingTags = href.getTags();
                        for (String tag : action.tags()) {
                            String trimmed = StringUtils.trimToEmpty(tag);
                            if (trimmed.isEmpty()) {
                                continue;
                            }
                            if (!existingTags.contains(trimmed)) {
                                href.addTag(trimmed);
                            }
                        }
                    }
                    applied++;
                }
                default -> errors.add("Unsupported action: " + action.type());
            }
        }
        return new ApplyResult(applied, errors);
    }
}
