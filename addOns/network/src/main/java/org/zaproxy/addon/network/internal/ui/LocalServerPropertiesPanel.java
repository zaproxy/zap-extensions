/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.network.internal.ui;

import java.awt.event.ActionListener;
import java.util.HashMap;
import java.util.Map;
import javax.swing.ButtonGroup;
import javax.swing.GroupLayout;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.network.internal.TlsUtils;
import org.zaproxy.addon.network.internal.server.http.LocalServerConfig;
import org.zaproxy.addon.network.internal.server.http.LocalServerConfig.ServerMode;

@SuppressWarnings("serial")
public class LocalServerPropertiesPanel extends JPanel {

    private static final long serialVersionUID = 1L;

    private final SecurityProtocolsPanel securityProtocolsPanel;
    private final JRadioButton apiAndProxyRadioButton;
    private final JCheckBox behindNatCheckBox;
    private final JCheckBox removeAcceptEncodingCheckBox;
    private final JCheckBox decodeResponseCheckBox;
    private final ButtonGroup modeButtonGroup;
    private final Map<ServerMode, JRadioButton> modeRadioButtons;
    private ServerMode selectedMode;

    public LocalServerPropertiesPanel(boolean canDisableProxy) {
        modeButtonGroup = new ButtonGroup();
        modeRadioButtons = new HashMap<>();

        GroupLayout layout = new GroupLayout(this);
        setLayout(layout);
        layout.setAutoCreateGaps(true);

        securityProtocolsPanel = new SecurityProtocolsPanel();

        behindNatCheckBox =
                new JCheckBox(
                        Constant.messages.getString(
                                "network.ui.options.localservers.field.behindnat"));
        behindNatCheckBox.setToolTipText(
                Constant.messages.getString(
                        "network.ui.options.localservers.field.behindnat.tooltip"));

        removeAcceptEncodingCheckBox =
                new JCheckBox(
                        Constant.messages.getString(
                                "network.ui.options.localservers.field.removeacceptencoding"));
        removeAcceptEncodingCheckBox.setToolTipText(
                Constant.messages.getString(
                        "network.ui.options.localservers.field.removeacceptencoding.tooltip"));

        decodeResponseCheckBox =
                new JCheckBox(
                        Constant.messages.getString(
                                "network.ui.options.localservers.field.decoderesponse"));
        decodeResponseCheckBox.setToolTipText(
                Constant.messages.getString(
                        "network.ui.options.localservers.field.decoderesponse.tooltip"));

        JLabel mode =
                new JLabel(
                        Constant.messages.getString("network.ui.options.localservers.field.mode"));
        ActionListener modeListener =
                e -> {
                    selectedMode =
                            (ServerMode) ((JComponent) e.getSource()).getClientProperty("zap.mode");
                    boolean proxy = selectedMode != ServerMode.API;
                    removeAcceptEncodingCheckBox.setEnabled(proxy);
                    decodeResponseCheckBox.setEnabled(proxy);
                };
        apiAndProxyRadioButton = createRadioButton(ServerMode.API_AND_PROXY, modeListener);
        JRadioButton apiRadioButton = createRadioButton(ServerMode.API, modeListener);
        JRadioButton proxyRadioButton = createRadioButton(ServerMode.PROXY, modeListener);
        apiRadioButton.setVisible(canDisableProxy);
        apiAndProxyRadioButton.doClick();

        layout.setHorizontalGroup(
                layout.createParallelGroup()
                        .addComponent(securityProtocolsPanel)
                        .addGroup(
                                layout.createSequentialGroup()
                                        .addGroup(
                                                layout.createSequentialGroup()
                                                        .addComponent(mode)
                                                        .addGroup(
                                                                layout.createSequentialGroup()
                                                                        .addComponent(
                                                                                apiAndProxyRadioButton)
                                                                        .addComponent(
                                                                                apiRadioButton)
                                                                        .addComponent(
                                                                                proxyRadioButton))))
                        .addComponent(behindNatCheckBox)
                        .addComponent(removeAcceptEncodingCheckBox)
                        .addComponent(decodeResponseCheckBox));

        layout.setVerticalGroup(
                layout.createSequentialGroup()
                        .addComponent(securityProtocolsPanel)
                        .addGroup(
                                layout.createParallelGroup()
                                        .addComponent(mode)
                                        .addComponent(apiAndProxyRadioButton)
                                        .addComponent(apiRadioButton)
                                        .addComponent(proxyRadioButton))
                        .addComponent(behindNatCheckBox)
                        .addComponent(removeAcceptEncodingCheckBox)
                        .addComponent(decodeResponseCheckBox));

        reset();
    }

    private JRadioButton createRadioButton(ServerMode mode, ActionListener listener) {
        String modeKey;
        switch (mode) {
            case API:
                modeKey = "api";
                break;
            case PROXY:
                modeKey = "proxy";
                break;
            default:
            case API_AND_PROXY:
                modeKey = "apiproxy";
        }

        String label =
                Constant.messages.getString(
                        "network.ui.options.localservers.field.mode." + modeKey);

        JRadioButton button = new JRadioButton(label);
        button.putClientProperty("zap.mode", mode);
        button.addActionListener(listener);
        modeButtonGroup.add(button);
        modeRadioButtons.put(mode, button);
        return button;
    }

    public void reset() {
        securityProtocolsPanel.setSecurityProtocolsEnabled(TlsUtils.getSupportedProtocols());
        apiAndProxyRadioButton.doClick();
        behindNatCheckBox.setSelected(false);
        removeAcceptEncodingCheckBox.setSelected(true);
        decodeResponseCheckBox.setSelected(true);
    }

    public boolean validateFields() {
        return securityProtocolsPanel.validateSecurityProtocols();
    }

    public void init(LocalServerConfig serverConfig) {
        modeRadioButtons.get(serverConfig.getMode()).doClick();
        securityProtocolsPanel.setSecurityProtocolsEnabled(serverConfig.getTlsProtocols());
        behindNatCheckBox.setSelected(serverConfig.isBehindNat());
        removeAcceptEncodingCheckBox.setSelected(serverConfig.isRemoveAcceptEncoding());
        decodeResponseCheckBox.setSelected(serverConfig.isDecodeResponse());
    }

    public void update(LocalServerConfig serverConfig) {
        serverConfig.setMode(selectedMode);
        serverConfig.setTlsProtocols(securityProtocolsPanel.getSelectedProtocols());
        serverConfig.setBehindNat(behindNatCheckBox.isSelected());
        serverConfig.setRemoveAcceptEncoding(removeAcceptEncodingCheckBox.isSelected());
        serverConfig.setDecodeResponse(decodeResponseCheckBox.isSelected());
    }
}
