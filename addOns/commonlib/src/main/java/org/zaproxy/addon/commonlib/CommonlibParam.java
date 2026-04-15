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
package org.zaproxy.addon.commonlib;

import org.parosproxy.paros.common.AbstractParam;

/** Persisted configuration for the Common Library add-on. */
public class CommonlibParam extends AbstractParam {

    private static final String PARAM_BASE_KEY = "commonlib";

    private static final String PARAM_SHOW_FIX_PROMPT_COPIED_DIALOG =
            PARAM_BASE_KEY + ".alert.generatefixprompt.showCopiedDialog";

    private boolean showFixPromptCopiedDialog = true;

    @Override
    protected void parse() {
        showFixPromptCopiedDialog = getBoolean(PARAM_SHOW_FIX_PROMPT_COPIED_DIALOG, true);
    }

    /**
     * Returns whether the "fix prompt copied to clipboard" confirmation dialog should be shown.
     *
     * @return {@code true} if the dialog should be shown, {@code false} otherwise.
     */
    public boolean isShowFixPromptCopiedDialog() {
        return showFixPromptCopiedDialog;
    }

    /**
     * Sets whether the "fix prompt copied to clipboard" confirmation dialog should be shown.
     *
     * @param show {@code true} if the dialog should be shown, {@code false} otherwise.
     */
    public void setShowFixPromptCopiedDialog(boolean show) {
        if (showFixPromptCopiedDialog != show) {
            showFixPromptCopiedDialog = show;
            getConfig().setProperty(PARAM_SHOW_FIX_PROMPT_COPIED_DIALOG, showFixPromptCopiedDialog);
        }
    }
}
