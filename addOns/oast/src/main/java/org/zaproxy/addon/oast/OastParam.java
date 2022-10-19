/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.oast;

import org.zaproxy.zap.common.VersionedAbstractParam;

public class OastParam extends VersionedAbstractParam {

    /** The base configuration key for all OAST configurations. */
    private static final String PARAM_BASE_KEY = "oast";

    private static final String PARAM_ACTIVE_SCAN_SERVICE_NAME =
            PARAM_BASE_KEY + ".activeScanService";

    public static final String NO_ACTIVE_SCAN_SERVICE_SELECTED_OPTION = "None";

    /**
     * The version of the configurations. Used to keep track of configurations changes between
     * releases, if updates are needed.
     */
    private static final int PARAM_CURRENT_VERSION = 1;

    private String activeScanServiceName;

    public OastParam() {}

    public String getActiveScanServiceName() {
        return activeScanServiceName;
    }

    public void setActiveScanServiceName(String activeScanServiceName) {
        this.activeScanServiceName = activeScanServiceName;
        getConfig().setProperty(PARAM_ACTIVE_SCAN_SERVICE_NAME, activeScanServiceName);
    }

    @Override
    protected void parseImpl() {
        activeScanServiceName =
                getString(PARAM_ACTIVE_SCAN_SERVICE_NAME, NO_ACTIVE_SCAN_SERVICE_SELECTED_OPTION);
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
    protected void updateConfigsImpl(int fileVersion) {}
}
