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

import java.awt.GridLayout;
import java.awt.Toolkit;
import java.awt.event.KeyEvent;
import javax.swing.KeyStroke;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.network.HttpMessage;

public class RequesterPanel extends AbstractPanel {

    private static final long serialVersionUID = 1L;

    public static final String PANEL_NAME = "requesterpanel";

    private RequesterNumberedTabbedPane requesterNumberedTabbedPane = null;

    @SuppressWarnings("deprecation")
    public RequesterPanel(ExtensionRequester extension) {
        super();
        this.setLayout(new GridLayout(1, 1));
        this.setSize(474, 251);
        this.setName(Constant.messages.getString("requester.panel.title"));
        this.setIcon(ExtensionRequester.REQUESTER_ICON);
        this.setDefaultAccelerator(
                KeyStroke.getKeyStroke(
                        // TODO Remove warn suppression and use View.getMenuShortcutKeyStroke with
                        // newer ZAP (or use getMenuShortcutKeyMaskEx() with Java 10+)
                        KeyEvent.VK_R,
                        Toolkit.getDefaultToolkit().getMenuShortcutKeyMask()
                                | KeyEvent.ALT_DOWN_MASK,
                        false));
        this.setMnemonic(Constant.messages.getChar("requester.panel.mnemonic"));
        this.setShowByDefault(true);
        requesterNumberedTabbedPane = new RequesterNumberedTabbedPane();
        this.add(requesterNumberedTabbedPane);
    }

    public RequesterNumberedTabbedPane getRequesterNumberedTabbedPane() {
        return requesterNumberedTabbedPane;
    }

    public void newRequester(HttpMessage msg) {
        ManualHttpRequestEditorPanel requestPane =
                new ManualHttpRequestEditorPanel(true, "requesterpanel");
        requestPane.setMessage(msg);
        getRequesterNumberedTabbedPane().addTab(requestPane);
    }

    void unload() {
        getRequesterNumberedTabbedPane().unload();
    }
};
