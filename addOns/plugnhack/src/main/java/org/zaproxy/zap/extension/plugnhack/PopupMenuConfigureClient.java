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

import java.awt.Component;
import javax.swing.JList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;

@SuppressWarnings("serial")
public class PopupMenuConfigureClient extends ExtensionPopupMenuItem {

    private static final long serialVersionUID = 1L;
    private ExtensionPlugNHack extension = null;
    private JList<MonitoredPage> clientsList = null;
    private static Logger log = LogManager.getLogger(PopupMenuConfigureClient.class);

    public PopupMenuConfigureClient(ExtensionPlugNHack extension) {
        super(Constant.messages.getString("plugnhack.clientconf.popup"));

        this.extension = extension;

        initialize();
    }

    private void initialize() {
        this.addActionListener(
                e -> {
                    MonitoredPage page = clientsList.getSelectedValue();
                    if (page != null) {
                        extension.showClientConfigDialog(page);
                    }
                });
    }

    @SuppressWarnings("unchecked")
    @Override
    public boolean isEnableForComponent(Component invoker) {

        if (ClientsPanel.CLIENTS_LIST_NAME.equals(invoker.getName())) {
            try {
                clientsList = (JList<MonitoredPage>) invoker;
                MonitoredPage client = clientsList.getSelectedValue();
                if (client != null && client.isActive()) {
                    this.setEnabled(true);
                } else {
                    this.setEnabled(false);
                }

            } catch (Exception e) {
                log.warn(e.getMessage(), e);
            }
            return true;
        }
        return false;
    }
}
