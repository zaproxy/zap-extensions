/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP Development Team
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
package org.zaproxy.zap.extension.websocket.ui;

import java.awt.CardLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.util.regex.PatternSyntaxException;
import javax.swing.JLabel;
import javax.swing.JPanel;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.websocket.ExtensionWebSocket;
import org.zaproxy.zap.extension.websocket.WebSocketException;
import org.zaproxy.zap.view.MultipleRegexesOptionsPanel;

@SuppressWarnings("serial")
public class SessionExcludeFromWebSocket extends AbstractParamPanel {
    public static final String PANEL_NAME =
            Constant.messages.getString("websocket.session.exclude.title");
    private static final long serialVersionUID = -1000465438379563850L;

    private JPanel panelSession = null;
    private MultipleRegexesOptionsPanel regexesPanel;

    private ExtensionWebSocket extWs;
    private OptionsParamWebSocket config;

    public SessionExcludeFromWebSocket(ExtensionWebSocket extWs, OptionsParamWebSocket config) {
        super();
        this.extWs = extWs;
        this.config = config;
        initialize();
    }

    private void initialize() {
        setLayout(new CardLayout());
        setName(PANEL_NAME);
        regexesPanel = new MultipleRegexesOptionsPanel(View.getSingleton().getSessionDialog());
        add(getPanelSession(), getPanelSession().getName());
    }

    private JPanel getPanelSession() {
        if (panelSession == null) {
            panelSession = new JPanel();
            panelSession.setLayout(new GridBagLayout());
            panelSession.setName("Ignorewebsocket");

            java.awt.GridBagConstraints gridBagConstraints2 = new GridBagConstraints();
            java.awt.GridBagConstraints gridBagConstraints1 = new GridBagConstraints();

            javax.swing.JLabel jLabel = new JLabel();

            jLabel.setText(Constant.messages.getString("websocket.session.label.ignore"));
            gridBagConstraints1.gridx = 0;
            gridBagConstraints1.gridy = 0;
            gridBagConstraints1.gridheight = 1;
            gridBagConstraints1.insets = new java.awt.Insets(10, 0, 5, 0);
            gridBagConstraints1.anchor = java.awt.GridBagConstraints.NORTHWEST;
            gridBagConstraints1.fill = java.awt.GridBagConstraints.HORIZONTAL;
            gridBagConstraints1.weightx = 0.0D;

            gridBagConstraints2.gridx = 0;
            gridBagConstraints2.gridy = 1;
            gridBagConstraints2.weightx = 1.0;
            gridBagConstraints2.weighty = 1.0;
            gridBagConstraints2.fill = java.awt.GridBagConstraints.BOTH;
            gridBagConstraints2.ipadx = 0;
            gridBagConstraints2.insets = new java.awt.Insets(0, 0, 0, 0);
            gridBagConstraints2.anchor = java.awt.GridBagConstraints.NORTHWEST;
            panelSession.add(jLabel, gridBagConstraints1);
            panelSession.add(regexesPanel, gridBagConstraints2);
        }
        return panelSession;
    }

    @Override
    public void initParam(Object obj) {
        regexesPanel.setRegexes(extWs.getChannelIgnoreList());
        regexesPanel.setRemoveWithoutConfirmation(!config.isConfirmRemoveProxyExcludeRegex());
    }

    @Override
    public void validateParam(Object obj) throws PatternSyntaxException {
        // Nothing to validate.
    }

    @Override
    public void saveParam(Object obj) throws WebSocketException {
        config.setConfirmRemoveProxyExcludeRegex(!regexesPanel.isRemoveWithoutConfirmation());
        extWs.setChannelIgnoreList(regexesPanel.getRegexes());
    }

    @Override
    public String getHelpIndex() {
        return "websocket.sessionProperties";
    }
}
