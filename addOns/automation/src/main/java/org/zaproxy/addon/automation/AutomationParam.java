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
package org.zaproxy.addon.automation;

import org.apache.commons.configuration.ConfigurationException;
import org.parosproxy.paros.common.AbstractParam;

public class AutomationParam extends AbstractParam {

    private static final String AUTO_KEY = "automation";

    private static final String PLAN_DIRECTORY_KEY = AUTO_KEY + ".plandir";
    private static final String SHOW_GUI_KEY = AUTO_KEY + ".gui";

    private boolean showGui = true;

    private String planDirectory;

    public AutomationParam() {}

    @Override
    protected void parse() {
        this.planDirectory = this.getString(PLAN_DIRECTORY_KEY, System.getProperty("user.home"));
        this.showGui = getBoolean(SHOW_GUI_KEY, true);
    }

    public String getPlanDirectory() {
        return planDirectory;
    }

    public void setPlanDirectory(String planDirectory) {
        this.planDirectory = planDirectory;
        getConfig().setProperty(PLAN_DIRECTORY_KEY, planDirectory);
        try {
            getConfig().save();
        } catch (ConfigurationException e) {
            // Ignore
        }
    }

    public boolean isShowGui() {
        return showGui;
    }
}
