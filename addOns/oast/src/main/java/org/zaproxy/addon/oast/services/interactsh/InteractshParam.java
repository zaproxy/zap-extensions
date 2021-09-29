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
package org.zaproxy.addon.oast.services.interactsh;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.common.VersionedAbstractParam;

public class InteractshParam extends VersionedAbstractParam {

    private static final int PARAM_CURRENT_VERSION = 1;
    private static final Logger LOGGER = LogManager.getLogger(InteractshParam.class);

    private static final String PARAM_BASE_KEY = "oast.interactsh";
    private static final String PARAM_SERVER_URL = PARAM_BASE_KEY + ".serverUrl";
    static final String PARAM_POLLING_FREQUENCY = PARAM_BASE_KEY + ".pollingFrequency";
    private static final String PARAM_AUTH_TOKEN = PARAM_BASE_KEY + ".authToken";

    static final int MINIMUM_POLLING_FREQUENCY = 10;

    private String serverUrl; // the URL for the interactsh server
    private int pollingFrequency;
    private String authToken; // if the server requires authentication

    public InteractshParam() {}

    /** For unit tests */
    InteractshParam(String serverUrl, int pollingFrequency, String authToken) {
        this.serverUrl = serverUrl;
        this.pollingFrequency = pollingFrequency;
        this.authToken = authToken;
    }

    @Override
    protected void parseImpl() {
        serverUrl = getString(PARAM_SERVER_URL, "https://interactsh.com");
        setPollingFrequency(getInt(PARAM_POLLING_FREQUENCY, 60));
        authToken = getString(PARAM_AUTH_TOKEN, "");
    }

    public String getServerUrl() {
        return serverUrl;
    }

    public void setServerUrl(String serverUrl) {
        this.serverUrl = serverUrl;
        getConfig().setProperty(PARAM_SERVER_URL, serverUrl);
    }

    public int getPollingFrequency() {
        return pollingFrequency;
    }

    public void setPollingFrequency(int pollingFrequency) {
        if (pollingFrequency < MINIMUM_POLLING_FREQUENCY) {
            LOGGER.info(
                    Constant.messages.getString(
                            "oast.boast.param.info.minPollingFrequency", pollingFrequency));
            pollingFrequency = MINIMUM_POLLING_FREQUENCY;
        }
        this.pollingFrequency = pollingFrequency;
        getConfig().setProperty(PARAM_POLLING_FREQUENCY, pollingFrequency);
    }

    public String getAuthToken() {
        return authToken;
    }

    public void setAuthToken(String authToken) {
        this.authToken = authToken;
        getConfig().setProperty(PARAM_AUTH_TOKEN, authToken);
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
