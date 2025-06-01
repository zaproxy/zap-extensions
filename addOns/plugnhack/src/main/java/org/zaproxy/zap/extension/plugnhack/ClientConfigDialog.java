/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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

import java.awt.Dimension;
import java.awt.Frame;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class ClientConfigDialog extends StandardFieldsDialog {

    private static final String FIELD_HEARTBEAT = "plugnhack.dialog.clientconf.heartbeat";
    private static final String FIELD_MONITOR_POST_MESSAGE =
            "plugnhack.dialog.clientconf.monitorPostMessage";
    private static final String FIELD_INTERCEPT_POST_MESSAGE =
            "plugnhack.dialog.clientconf.interceptPostMessage";
    private static final String FIELD_MONITOR_EVENTS = "plugnhack.dialog.clientconf.monitorEvents";
    private static final String FIELD_INTERCEPT_EVENTS =
            "plugnhack.dialog.clientconf.interceptEvents";

    private static final long serialVersionUID = 1L;

    private ExtensionPlugNHack extension = null;
    private MonitoredPage page = null;

    public ClientConfigDialog(ExtensionPlugNHack ext, Frame owner, Dimension dim) {
        super(owner, "plugnhack.dialog.clientconf.title", dim);
        this.extension = ext;
    }

    public void init(MonitoredPage page) {
        this.page = page;

        this.removeAllFields();

        this.addComboField(
                FIELD_HEARTBEAT, new int[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, page.getHeartbeat());
        this.addCheckBoxField(FIELD_MONITOR_POST_MESSAGE, page.isMonitorPostMessage());
        this.addCheckBoxField(FIELD_INTERCEPT_POST_MESSAGE, page.isInterceptPostMessage());
        this.addCheckBoxField(FIELD_MONITOR_EVENTS, page.isMonitorEvents());
        this.addCheckBoxField(FIELD_INTERCEPT_EVENTS, page.isInterceptEvents());
        this.addPadding();
    }

    @Override
    public void save() {

        if (page.getHeartbeat() != this.getIntValue(FIELD_HEARTBEAT)) {
            page.setHeartbeat(this.getIntValue(FIELD_HEARTBEAT));
            this.extension.setClientConfig(page, "heartbeatInterval", page.getHeartbeat() * 1000);
        }

        if (page.isMonitorPostMessage() != this.getBoolValue(FIELD_MONITOR_POST_MESSAGE)) {
            page.setMonitorPostMessage(this.getBoolValue(FIELD_MONITOR_POST_MESSAGE));
            this.extension.setClientConfig(page, "monitorPostMessage", page.isMonitorPostMessage());
        }

        if (page.isInterceptPostMessage() != this.getBoolValue(FIELD_INTERCEPT_POST_MESSAGE)) {
            page.setInterceptPostMessage(this.getBoolValue(FIELD_INTERCEPT_POST_MESSAGE));
            this.extension.setClientConfig(
                    page, "interceptPostMessage", page.isInterceptPostMessage());
        }

        if (page.isMonitorEvents() != this.getBoolValue(FIELD_MONITOR_EVENTS)) {
            page.setMonitorEvents(this.getBoolValue(FIELD_MONITOR_EVENTS));
            this.extension.setClientConfig(page, "monitorEvents", page.isMonitorEvents());
        }

        if (page.isInterceptEvents() != this.getBoolValue(FIELD_INTERCEPT_EVENTS)) {
            page.setInterceptEvents(this.getBoolValue(FIELD_INTERCEPT_EVENTS));
            this.extension.setClientConfig(page, "interceptEvents", page.isInterceptEvents());
        }
    }

    @Override
    public String validateFields() {
        // Nothing to do
        return null;
    }
}
