/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.zap.extension.foxhound;

import org.zaproxy.addon.commonlib.Constants;
import org.zaproxy.zap.common.VersionedAbstractParam;

public class FoxhoundOptions extends VersionedAbstractParam {

    /** The base configuration key for all Foxhound configurations. */
    private static final String PARAM_BASE_KEY = "foxhound";

    private static final String PARAM_SERVER_PORT = PARAM_BASE_KEY + ".serverPort";

    /**
     * The version of the configurations. Used to keep track of configurations changes between
     * releases, if updates are needed.
     *
     * <p>It only needs to be updated for configurations changes (not releases of the add-on).
     */
    private static final int PARAM_CURRENT_VERSION = 1;

    // Default values
    public static final int DEFAULT_SERVER_PORT = 55676;

    // Concrete parameters
    private int serverPort = DEFAULT_SERVER_PORT;


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

    }
    @Override
    protected void parseImpl() {
        serverPort = getConfig().getInt(PARAM_SERVER_PORT, DEFAULT_SERVER_PORT);
    }

    public int getServerPort() {
        return this.serverPort;
    }

    public void setServerPort(int serverPort) {
        this.serverPort = serverPort;
        getConfig().setProperty(PARAM_SERVER_PORT, serverPort);
    }
}
