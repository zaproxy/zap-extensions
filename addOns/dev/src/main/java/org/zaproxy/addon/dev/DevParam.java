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
package org.zaproxy.addon.dev;

import org.parosproxy.paros.Constant;
import org.zaproxy.zap.common.VersionedAbstractParam;

public class DevParam extends VersionedAbstractParam {

    /** The base configuration key for all Dev configurations. */
    private static final String PARAM_BASE_KEY = "dev";

    private static final String PARAM_BASE_DIRECTORY = PARAM_BASE_KEY + ".dir";
    private static final String PARAM_TEST_PORT = PARAM_BASE_KEY + ".testPort";
    private static final String PARAM_TEST_HOST = PARAM_BASE_KEY + ".testHost";

    /**
     * The version of the configurations. Used to keep track of configurations changes between
     * releases, if updates are needed.
     *
     * <p>It only needs to be updated for configurations changes (not releases of the add-on).
     */
    private static final int PARAM_CURRENT_VERSION = 1;

    private String baseDirectory;

    private int testPort;

    private String testHost;

    public String getBaseDirectory() {
        return baseDirectory;
    }

    public void setBaseDirectory(String baseDirectory) {
        this.baseDirectory = baseDirectory;
        getConfig().setProperty(PARAM_BASE_DIRECTORY, baseDirectory);
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
    protected void parseImpl() {
        baseDirectory =
                getString(
                        PARAM_BASE_DIRECTORY, Constant.getZapHome() + ExtensionDev.DIRECTORY_NAME);
        testPort = getInt(PARAM_TEST_PORT, 9091);
        testHost = getString(PARAM_TEST_HOST, "127.0.0.1");
    }

    @Override
    protected void updateConfigsImpl(int fileVersion) {}

    public int getTestPort() {
        return testPort;
    }

    public String getTestHost() {
        return testHost;
    }
}
