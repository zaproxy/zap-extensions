/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.paramdigger;

import org.zaproxy.zap.common.VersionedAbstractParam;

public class ParamDiggerOptions extends VersionedAbstractParam {

    public static final boolean DEFAULT_PROMPT_TO_CLEAR_FINISHED_SCANS = true;

    public static final int DEFAULT_MAX_SCANS_IN_UI = 5;

    /**
     * The version of the configurations. Used to keep track of configurations changes between
     * releases, if updates are needed.
     *
     * <p>It only needs to be updated for configurations changes (not releases of the add-on).
     */
    private static final int CURRENT_VERSION = 1;

    private static final String BASE_KEY = "paramdigger";

    private static final String MAX_FINISHED_SCANS_IN_UI_KEY = BASE_KEY + ".maxCompletedScansInUi";
    private static final String PROMPT_TO_CLEAR_FINISHED_SCANS_KEY =
            BASE_KEY + ".promptToClearFinishedScans";

    private int maxFinishedScansInUi;
    private boolean promptToClearFinishedScans;

    @Override
    protected int getCurrentVersion() {
        return CURRENT_VERSION;
    }

    @Override
    protected String getConfigVersionKey() {
        return BASE_KEY + VERSION_ATTRIBUTE;
    }

    @Override
    protected void parseImpl() {
        maxFinishedScansInUi = getInt(MAX_FINISHED_SCANS_IN_UI_KEY, DEFAULT_MAX_SCANS_IN_UI);
        promptToClearFinishedScans =
                getBoolean(
                        PROMPT_TO_CLEAR_FINISHED_SCANS_KEY, DEFAULT_PROMPT_TO_CLEAR_FINISHED_SCANS);
    }

    @Override
    protected void updateConfigsImpl(int fileVersion) {
        // Nothing to do.
    }

    public int getMaxFinishedScansInUi() {
        return maxFinishedScansInUi;
    }

    public void setMaxFinishedScansInUi(int maxScans) {
        if (maxFinishedScansInUi == maxScans) {
            return;
        }
        maxFinishedScansInUi = maxScans;
        getConfig()
                .setProperty(MAX_FINISHED_SCANS_IN_UI_KEY, Integer.valueOf(maxFinishedScansInUi));
    }

    public boolean isPromptToClearFinishedScans() {
        return promptToClearFinishedScans;
    }

    public void setPromptToClearFinishedScans(boolean prompt) {
        if (promptToClearFinishedScans == prompt) {
            return;
        }
        promptToClearFinishedScans = prompt;
        getConfig()
                .setProperty(
                        PROMPT_TO_CLEAR_FINISHED_SCANS_KEY,
                        Boolean.valueOf(promptToClearFinishedScans));
    }
}
