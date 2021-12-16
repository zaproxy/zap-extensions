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
package org.zaproxy.addon.callhome;

import java.util.UUID;
import org.zaproxy.zap.common.VersionedAbstractParam;

public class CallHomeParam extends VersionedAbstractParam {

    private static final int PARAM_CURRENT_VERSION = 1;
    private static final String CALL_HOME_KEY = "callhome";

    private static final String TEL_UUID_KEY = CALL_HOME_KEY + ".tel.uuid";
    private static final String TEL_ENABLED_KEY = CALL_HOME_KEY + ".tel.enabled";

    private String telUuid;
    private boolean telEnabled = true;

    public CallHomeParam() {
        // Nothing to do
    }

    public String getTelemetryUuid() {
        return telUuid;
    }

    public boolean isTelemetryEnabled() {
        return telEnabled;
    }

    public void setTelemetryEnabled(boolean enabled) {
        this.telEnabled = enabled;
        getConfig().setProperty(TEL_ENABLED_KEY, this.telEnabled);
    }

    @Override
    protected void parseImpl() {
        this.telUuid = this.getString(TEL_UUID_KEY, null);
        if (this.telUuid == null) {
            this.telUuid = UUID.randomUUID().toString();
            getConfig().setProperty(TEL_UUID_KEY, this.telUuid);
        }
        this.telEnabled = getBoolean(TEL_ENABLED_KEY, true);
    }

    @Override
    protected String getConfigVersionKey() {
        return CALL_HOME_KEY + VERSION_ATTRIBUTE;
    }

    @Override
    protected int getCurrentVersion() {
        return PARAM_CURRENT_VERSION;
    }

    @Override
    protected void updateConfigsImpl(int fileVersion) {
        // Nothing to do
    }
}
