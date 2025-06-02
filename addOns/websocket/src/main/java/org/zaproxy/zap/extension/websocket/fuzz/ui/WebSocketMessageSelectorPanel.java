/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.websocket.fuzz.ui;

import javax.swing.GroupLayout;
import javax.swing.JLabel;
import javax.swing.JPanel;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.fuzz.MessageSelectorPanel;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;

public class WebSocketMessageSelectorPanel implements MessageSelectorPanel<WebSocketMessageDTO> {

    private final JPanel panel;

    public WebSocketMessageSelectorPanel() {
        panel = new JPanel();
        GroupLayout layout = new GroupLayout(panel);
        panel.setLayout(layout);
        layout.setAutoCreateGaps(true);

        JLabel label =
                new JLabel(
                        Constant.messages.getString(
                                "websocket.fuzzer.select.message.dialogue.warn"));

        layout.setHorizontalGroup(layout.createSequentialGroup().addComponent(label));
        layout.setVerticalGroup(layout.createSequentialGroup().addComponent(label));
    }

    @Override
    public JPanel getPanel() {
        return panel;
    }

    @Override
    public boolean validate() {
        return false;
    }

    @Override
    public WebSocketMessageDTO getSelectedMessage() {
        return null;
    }

    @Override
    public void clear() {}

    @Override
    public String getHelpTarget() {
        // THC add help...
        return null;
    }
}
