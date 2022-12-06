/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.plugnhack;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.view.popup.PopupMenuItemHttpMessageContainer;

@SuppressWarnings("serial")
public class PopupMenuMonitorSubtree extends PopupMenuItemHttpMessageContainer {

    private static final long serialVersionUID = 1L;
    private MonitoredPagesManager mpm = null;
    private boolean monitored = false;

    /** @param label */
    public PopupMenuMonitorSubtree(MonitoredPagesManager mpm) {
        super(Constant.messages.getString("plugnhack.menu.monitor.include"));
        this.mpm = mpm;
    }

    @Override
    public String getParentMenuName() {
        return Constant.messages.getString("plugnhack.menu.monitor");
    }

    @Override
    public boolean isSubMenu() {
        return true;
    }

    @Override
    public void performAction(HttpMessage msg) {
        this.mpm.setMonitorSubtree(msg, !monitored);
    }

    @Override
    public boolean isButtonEnabledForSelectedHttpMessage(HttpMessage msg) {
        if (this.mpm.isMonitored(msg)) {
            this.monitored = true;
            this.setText(Constant.messages.getString("plugnhack.menu.monitor.exclude"));
        } else {
            this.monitored = false;
            this.setText(Constant.messages.getString("plugnhack.menu.monitor.include"));
        }
        return true;
    }

    @Override
    public boolean isSafe() {
        return true;
    }
}
