/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.jython;

import org.zaproxy.zap.common.VersionedAbstractParam;

public class JythonOptionsParam extends VersionedAbstractParam {

    /**
     * The version of the configurations. Used to keep track of configurations changes between
     * releases, if updates are needed.
     *
     * <p>It only needs to be updated for configurations changes (not releases of the add-on).
     */
    private static final int CURRENT_VERSION = 1;

    /** The base configuration key for all "jython" configurations. */
    private static final String BASE_KEY = "jython";

    public static final String MODULE_PATH_PROPERTY = BASE_KEY + ".modulepath";

    /** The path to python modules */
    private String modulePath;

    public String getModulePath() {
        return this.modulePath;
    }

    public void setModulePath(String modulePath) {
        this.modulePath = modulePath;
        super.getConfig().setProperty(MODULE_PATH_PROPERTY, modulePath);
    }

    @Override
    protected void parseImpl() {
        this.modulePath = getString(MODULE_PATH_PROPERTY, "");
    }

    @Override
    protected String getConfigVersionKey() {
        return BASE_KEY + VERSION_ATTRIBUTE;
    }

    @Override
    protected int getCurrentVersion() {
        return CURRENT_VERSION;
    }

    @Override
    protected void updateConfigsImpl(int fileVersion) {}
}
