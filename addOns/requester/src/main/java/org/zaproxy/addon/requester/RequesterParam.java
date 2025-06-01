/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.addon.requester;

import org.zaproxy.zap.common.VersionedAbstractParam;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/**
 * Manages the requester configurations saved in the configuration file.
 *
 * <p>It allows to change, programmatically, the following requester option:
 *
 * <ul>
 *   <li>Set focus on Requester - Allows you to configure if ZAP should set the focus on Requester
 *       after creating a new tab.
 * </ul>
 */
public class RequesterParam extends VersionedAbstractParam {

    private static final String PARAM_BASE_KEY = "requester";

    /**
     * The current version of the configurations. Used to keep track of configuration changes
     * between releases, in case changes/updates are needed.
     *
     * <p>It only needs to be incremented for configuration changes (not releases of the add-on).
     *
     * @see #CONFIG_VERSION_KEY
     * @see #updateConfigsImpl(int)
     */
    private static final int CURRENT_CONFIG_VERSION = 2;

    /**
     * The key for the version of the configurations.
     *
     * @see #CURRENT_CONFIG_VERSION
     */
    private static final String CONFIG_VERSION_KEY = PARAM_BASE_KEY + VERSION_ATTRIBUTE;

    private static final String PARAM_REQUESTER_AUTO_FOCUS = PARAM_BASE_KEY + ".autoFocus";

    private boolean autoFocus = true;

    public RequesterParam() {
        super();
    }

    @Override
    protected int getCurrentVersion() {
        return CURRENT_CONFIG_VERSION;
    }

    @Override
    protected String getConfigVersionKey() {
        return CONFIG_VERSION_KEY;
    }

    @Override
    protected void parseImpl() {
        autoFocus = getConfig().getBoolean(PARAM_REQUESTER_AUTO_FOCUS, true);
    }

    @Override
    protected void updateConfigsImpl(int fileVersion) {
        switch (fileVersion) {
            case NO_CONFIG_VERSION:
            case 1:
                // Remove the old Resend dialog configs, if present
                if (this.getConfig() instanceof ZapXmlConfiguration) {
                    ZapXmlConfiguration zapConfig = (ZapXmlConfiguration) this.getConfig();
                    zapConfig.clearTree("view.resend");
                }
                break;
            default:
        }
    }

    public boolean isAutoFocus() {
        return autoFocus;
    }

    public void setAutoFocus(boolean autoFocus) {
        this.autoFocus = autoFocus;
        getConfig().setProperty(PARAM_REQUESTER_AUTO_FOCUS, Boolean.valueOf(autoFocus));
    }
}
