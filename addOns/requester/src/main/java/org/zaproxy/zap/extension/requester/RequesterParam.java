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
package org.zaproxy.zap.extension.requester;

import org.parosproxy.paros.common.AbstractParam;

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
public class RequesterParam extends AbstractParam {

    private static final String PARAM_BASE_KEY = "requester";

    private static final String PARAM_REQUESTER_AUTO_FOCUS = PARAM_BASE_KEY + ".autoFocus";

    private boolean autoFocus = true;

    public RequesterParam() {
        super();
    }

    @Override
    protected void parse() {
        autoFocus = getConfig().getBoolean(PARAM_REQUESTER_AUTO_FOCUS, true);
    }

    public boolean isAutoFocus() {
        return autoFocus;
    }

    public void setAutoFocus(boolean autoFocus) {
        this.autoFocus = autoFocus;
        getConfig().setProperty(PARAM_REQUESTER_AUTO_FOCUS, Boolean.valueOf(autoFocus));
    }
}
