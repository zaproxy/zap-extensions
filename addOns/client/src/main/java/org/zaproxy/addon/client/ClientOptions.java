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
package org.zaproxy.addon.client;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.zap.common.VersionedAbstractParam;

public class ClientOptions extends VersionedAbstractParam {

    private static final Logger LOGGER = LogManager.getLogger(ClientOptions.class);

    protected static final int CURRENT_CONFIG_VERSION = 1;

    static final String CLIENT_BASE_KEY = "client";

    private static final String CONFIG_VERSION_KEY = CLIENT_BASE_KEY + VERSION_ATTRIBUTE;
    private static final String PSCAN_ENABLED_KEY = CLIENT_BASE_KEY + ".pscanEnabled";
    private static final String PSCAN_DISABLED_RULES_KEY = CLIENT_BASE_KEY + ".pscanRulesDisabled";

    private boolean pscanEnabled;

    private List<Integer> pscanRulesDisabled;

    @Override
    protected void parseImpl() {
        this.pscanEnabled = getBoolean(PSCAN_ENABLED_KEY, true);

        try {
            pscanRulesDisabled =
                    getConfig().getList(PSCAN_DISABLED_RULES_KEY).stream()
                            .map(Object::toString)
                            .map(Integer::parseInt)
                            .collect(Collectors.toList());
        } catch (Exception e) {
            LOGGER.warn(e.getMessage(), e);
            pscanRulesDisabled = new ArrayList<>();
        }
    }

    @Override
    protected int getCurrentVersion() {
        return CURRENT_CONFIG_VERSION;
    }

    @Override
    protected void updateConfigsImpl(int fileVersion) {
        // first version, nothing to update yet
    }

    @Override
    protected String getConfigVersionKey() {
        return CONFIG_VERSION_KEY;
    }

    public boolean isPscanEnabled() {
        return pscanEnabled;
    }

    public void setPscanEnabled(boolean pscanEnabled) {
        this.pscanEnabled = pscanEnabled;
        getConfig().setProperty(PSCAN_ENABLED_KEY, pscanEnabled);
    }

    public List<Integer> getPscanRulesDisabled() {
        return pscanRulesDisabled;
    }

    public void setPscanRulesDisabled(List<Integer> pscanDisabled) {
        this.pscanRulesDisabled = pscanDisabled;
        getConfig().setProperty(PSCAN_DISABLED_RULES_KEY, pscanDisabled);
    }
}
