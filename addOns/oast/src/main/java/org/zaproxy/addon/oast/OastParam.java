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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.common.VersionedAbstractParam;

public class OastParam extends VersionedAbstractParam {

    /** Update this if params are added, changed or deleted. */
    private static final int PARAM_CURRENT_VERSION = 1;

    private static final String PARAM_BASE_KEY = "oast";
    private static final String PARAM_SERVER = PARAM_BASE_KEY + ".server";

    private static final Logger LOG = LogManager.getLogger(OastParam.class);

    private String oastServer;

    public OastParam() {}

    public String getOastServer() {
        return oastServer;
    }

    public void setOastServer(String oastServer) {
        this.oastServer = oastServer;
        getConfig().setProperty(PARAM_SERVER, oastServer);
    }

    @Override
    protected void parseImpl() {
        oastServer = getString(PARAM_SERVER, Constant.messages.getString("oast.callback.name"));
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
