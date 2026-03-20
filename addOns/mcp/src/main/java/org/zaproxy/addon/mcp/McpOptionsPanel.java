/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.mcp;

import java.awt.CardLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.border.EmptyBorder;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.zap.utils.ZapNumberSpinner;
import org.zaproxy.zap.view.LayoutHelper;

/** The options panel for the MCP add-on. */
public class McpOptionsPanel extends AbstractParamPanel {

    private static final long serialVersionUID = 1L;

    private ZapNumberSpinner portSpinner;
    private JCheckBox securityKeyEnabledCheckBox;
    private JPasswordField securityKeyField;
    private JButton generateKeyButton;
    private JCheckBox recordInHistoryCheckBox;
    private JCheckBox secureOnlyCheckBox;

    public McpOptionsPanel() {
        super();
        setName(Constant.messages.getString("mcp.optionspanel.name"));

        setLayout(new CardLayout());

        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(new EmptyBorder(2, 2, 2, 2));

        int row = 0;

        JLabel portLabel = new JLabel(Constant.messages.getString("mcp.optionspanel.port.label"));
        portLabel.setLabelFor(getPortSpinner());
        panel.add(
                portLabel,
                LayoutHelper.getGBC(
                        0, row, GridBagConstraints.RELATIVE, 1.0, new Insets(2, 2, 2, 2)));
        panel.add(
                getPortSpinner(),
                LayoutHelper.getGBC(
                        1, row, GridBagConstraints.REMAINDER, 1.0, new Insets(2, 2, 2, 2)));
        row++;

        JLabel keyLabel =
                new JLabel(Constant.messages.getString("mcp.optionspanel.securitykey.label"));
        keyLabel.setLabelFor(getSecurityKeyField());
        panel.add(
                keyLabel,
                LayoutHelper.getGBC(
                        0, row, GridBagConstraints.RELATIVE, 1.0, new Insets(2, 2, 2, 2)));
        JPanel keyPanel = new JPanel(new GridBagLayout());
        keyPanel.add(
                getSecurityKeyField(), LayoutHelper.getGBC(0, 0, 1, 1.0, new Insets(0, 0, 0, 2)));
        keyPanel.add(
                getGenerateKeyButton(), LayoutHelper.getGBC(1, 0, 1, 0, new Insets(0, 0, 0, 0)));
        panel.add(
                keyPanel,
                LayoutHelper.getGBC(
                        1, row, GridBagConstraints.REMAINDER, 1.0, new Insets(2, 2, 2, 2)));
        row++;

        panel.add(
                getSecurityKeyEnabledCheckBox(),
                LayoutHelper.getGBC(
                        0, row, GridBagConstraints.REMAINDER, 1.0, new Insets(2, 2, 2, 2)));
        row++;

        panel.add(
                getSecureOnlyCheckBox(),
                LayoutHelper.getGBC(
                        0, row, GridBagConstraints.REMAINDER, 1.0, new Insets(2, 2, 2, 2)));
        row++;

        panel.add(
                getRecordInHistoryCheckBox(),
                LayoutHelper.getGBC(
                        0, row, GridBagConstraints.REMAINDER, 1.0, new Insets(2, 2, 2, 2)));
        row++;

        panel.add(new JLabel(), LayoutHelper.getGBC(0, 10, 1, 0.5D, 1.0D)); // Spacer

        add(panel);
    }

    private ZapNumberSpinner getPortSpinner() {
        if (portSpinner == null) {
            portSpinner = new ZapNumberSpinner(1, McpParam.DEFAULT_PORT, 65535);
        }
        return portSpinner;
    }

    private JCheckBox getSecurityKeyEnabledCheckBox() {
        if (securityKeyEnabledCheckBox == null) {
            securityKeyEnabledCheckBox =
                    new JCheckBox(
                            Constant.messages.getString(
                                    "mcp.optionspanel.securitykey.enabled.label"));
            securityKeyEnabledCheckBox.addItemListener(
                    e -> getSecurityKeyField().setEnabled(securityKeyEnabledCheckBox.isSelected()));
        }
        return securityKeyEnabledCheckBox;
    }

    private JPasswordField getSecurityKeyField() {
        if (securityKeyField == null) {
            securityKeyField = new JPasswordField(32);
        }
        return securityKeyField;
    }

    private JCheckBox getRecordInHistoryCheckBox() {
        if (recordInHistoryCheckBox == null) {
            recordInHistoryCheckBox =
                    new JCheckBox(
                            Constant.messages.getString("mcp.optionspanel.recordinhistory.label"));
        }
        return recordInHistoryCheckBox;
    }

    private JCheckBox getSecureOnlyCheckBox() {
        if (secureOnlyCheckBox == null) {
            secureOnlyCheckBox =
                    new JCheckBox(Constant.messages.getString("mcp.optionspanel.secureonly.label"));
        }
        return secureOnlyCheckBox;
    }

    private JButton getGenerateKeyButton() {
        if (generateKeyButton == null) {
            generateKeyButton =
                    new JButton(
                            Constant.messages.getString(
                                    "mcp.optionspanel.securitykey.generate.label"));
            generateKeyButton.addActionListener(
                    e -> {
                        getSecurityKeyField().setText(McpParam.generateRandomKey());
                        getSecurityKeyEnabledCheckBox().setSelected(true);
                        getSecurityKeyField().setEnabled(true);
                    });
        }
        return generateKeyButton;
    }

    @Override
    public void initParam(Object obj) {
        OptionsParam options = (OptionsParam) obj;
        McpParam param = options.getParamSet(McpParam.class);

        getPortSpinner().setValue(param.getPort());
        getSecurityKeyEnabledCheckBox().setSelected(param.isSecurityKeyEnabled());
        getSecurityKeyField().setText(param.getSecurityKey());
        getSecurityKeyField().setEnabled(param.isSecurityKeyEnabled());
        getRecordInHistoryCheckBox().setSelected(param.isRecordInHistory());
        getSecureOnlyCheckBox().setSelected(param.isSecureOnly());
    }

    @Override
    public void validateParam(Object obj) throws Exception {
        int port = getPortSpinner().getValue();
        if (port < 1 || port > 65535) {
            throw new IllegalStateException(
                    Constant.messages.getString("mcp.optionspanel.port.error.invalid"));
        }
        if (getSecurityKeyEnabledCheckBox().isSelected()) {
            String key = new String(getSecurityKeyField().getPassword());
            if (key.isBlank()) {
                throw new IllegalStateException(
                        Constant.messages.getString("mcp.optionspanel.securitykey.error.empty"));
            }
        }
    }

    @Override
    public void saveParam(Object obj) throws Exception {
        OptionsParam options = (OptionsParam) obj;
        McpParam param = options.getParamSet(McpParam.class);

        param.setPort(getPortSpinner().getValue());
        param.setSecurityKeyEnabled(getSecurityKeyEnabledCheckBox().isSelected());
        param.setSecurityKey(new String(getSecurityKeyField().getPassword()));
        param.setRecordInHistory(getRecordInHistoryCheckBox().isSelected());
        param.setSecureOnly(getSecureOnlyCheckBox().isSelected());
    }

    @Override
    public String getHelpIndex() {
        return "addon.mcp.options";
    }
}
