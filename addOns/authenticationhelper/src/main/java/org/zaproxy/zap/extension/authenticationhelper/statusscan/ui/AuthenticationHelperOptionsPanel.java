/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.authenticationhelper.statusscan.ui;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import javax.swing.JLabel;
import javax.swing.JPanel;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.authenticationhelper.OptionsParamAuthenticationHelper;
import org.zaproxy.zap.view.MultipleRegexesOptionsPanel;

public class AuthenticationHelperOptionsPanel extends AbstractParamPanel {

    public static final String PANEL_NAME =
            Constant.messages.getString("authenticationhelper.options.title");
    private static final long serialVersionUID = 1L;

    private JPanel extensionToIgnorePanel = null;
    private MultipleRegexesOptionsPanel regexesPanel;

    private final OptionsParamAuthenticationHelper config;

    public AuthenticationHelperOptionsPanel(OptionsParamAuthenticationHelper config) {
        super();

        this.config = config;

        initialize();
    }

    @Override
    public String getHelpIndex() {
        return "authenticationhelper.options";
    }

    private void initialize() {
        regexesPanel = new MultipleRegexesOptionsPanel(View.getSingleton().getSessionDialog());

        setName(PANEL_NAME);
        setLayout(new GridBagLayout());

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.weightx = 1.0;
        gbc.anchor = GridBagConstraints.LINE_START;
        gbc.fill = GridBagConstraints.BOTH;

        add(
                new JLabel(Constant.messages.getString("authenticationhelper.options.regex.label")),
                gbc);

        gbc.weighty = 1.0;
        add(getExtensionToIgnorePanel(), gbc);
    }

    private JPanel getExtensionToIgnorePanel() {
        if (extensionToIgnorePanel == null) {

            extensionToIgnorePanel = new JPanel();
            extensionToIgnorePanel.setLayout(new GridBagLayout());
            extensionToIgnorePanel.setName("IgnoreFromAuthenticationCheck");

            GridBagConstraints gridBagConstraints1 = new GridBagConstraints();

            gridBagConstraints1.gridx = 0;
            gridBagConstraints1.gridy = 0;
            gridBagConstraints1.weightx = 1.0;
            gridBagConstraints1.weighty = 1.0;
            gridBagConstraints1.fill = java.awt.GridBagConstraints.BOTH;
            gridBagConstraints1.ipadx = 0;
            gridBagConstraints1.insets = new java.awt.Insets(0, 0, 0, 0);
            gridBagConstraints1.anchor = java.awt.GridBagConstraints.NORTHWEST;

            extensionToIgnorePanel.add(regexesPanel, gridBagConstraints1);
        }
        return extensionToIgnorePanel;
    }

    @Override
    public void initParam(Object obj) {
        regexesPanel.setRegexes(config.getRegexesToIgnore());
        regexesPanel.setRemoveWithoutConfirmation(!config.isConfirmRemoveExcludeRegex());
    }

    @Override
    public void saveParam(Object obj) throws Exception {
        config.setConfirmRemoveExcludeRegex(!regexesPanel.isRemoveWithoutConfirmation());
        config.setRegexesToIgnore(regexesPanel.getRegexes());
    }
}
