/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.zap.extension.wappalyzer;

import org.zaproxy.zap.common.VersionedAbstractParam;

public class WappalyzerParam extends VersionedAbstractParam {

    /**
     * The version of the configurations. Used to keep track of configurations changes between
     * releases, if updates are needed.
     *
     * <p>It only needs to be updated for configurations changes (not releases of the add-on).
     */
    private static final int PARAM_CURRENT_VERSION = 1;
    /** The base configuration key for all "wappalyzer" configurations. */
    private static final String PARAM_BASE_KEY = "wappalyzer";
    /** The configuration key for the state of wappalyzer functionality. */
    private static final String PARAM_WAPPALYZER_STATE = PARAM_BASE_KEY + ".enabled";

    private static final boolean PARAM_WAPPALYZER_STATE_DEFAULT_VALUE = true;

    private boolean enabled;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        if (this.enabled != enabled) {
            this.enabled = enabled;

            getConfig().setProperty(PARAM_WAPPALYZER_STATE, Boolean.valueOf(enabled));
        }
    }

    @Override
    protected void parseImpl() {
        enabled = getBoolean(PARAM_WAPPALYZER_STATE, PARAM_WAPPALYZER_STATE_DEFAULT_VALUE);
    }

    @Override
    protected String getConfigVersionKey() {
        return PARAM_BASE_KEY + VERSION_ATTRIBUTE;
    }

    @Override
    protected int getCurrentVersion() {
        return PARAM_CURRENT_VERSION;
    }

    @Override
    protected void updateConfigsImpl(int fileVersion) {
        // Nothing to do.
    }
}
