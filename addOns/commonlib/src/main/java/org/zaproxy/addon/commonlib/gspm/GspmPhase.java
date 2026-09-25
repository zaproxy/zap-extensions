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
package org.zaproxy.addon.commonlib.gspm;

import java.util.Locale;
import org.parosproxy.paros.Constant;

/**
 * The fixed, top-level grouping shown in the GSPM dialog's tree, independent of {@link GspmTool}.
 *
 * <p>Unlike a tool (a stable registration/query identity, e.g. {@code "ascan"}, {@code "pscan"},
 * {@code "wspscan"}), a phase is purely presentational: several tools may share the same phase,
 * each still contributing its own category nodes underneath it. {@link GspmRegistry} and {@link
 * GspmRuleSet}'s persisted category-key matching are entirely tool-scoped and unaffected by phase.
 *
 * @since 1.45.0
 */
public enum GspmPhase {
    ACTIVE,
    PASSIVE;

    /** Returns the i18n display name for this phase. */
    public String getDisplayName() {
        return Constant.messages.getString(
                "commonlib.gspm.phase." + name().toLowerCase(Locale.ROOT));
    }
}
