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

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.stream.Collectors;
import javax.swing.BorderFactory;
import javax.swing.GroupLayout;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.border.TitledBorder;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.network.internal.TlsUtils;
import org.zaproxy.addon.network.internal.handlers.TlsConfig;
import org.zaproxy.zap.utils.FontUtils;

/**
 * A {@code JPanel} to enable and configure TLS ALPN.
 *
 * @see TlsConfig
 */
@SuppressWarnings("serial")
public class AlpnPanel extends JPanel {

    private static final long serialVersionUID = 1L;

    private JCheckBox checkBoxEnable;
    private final Map<String, JCheckBox> checkBoxesProtocols;

    public AlpnPanel() {
        setBorder(
                BorderFactory.createTitledBorder(
                        null,
                        Constant.messages.getString("network.ui.options.alpn.title"),
                        TitledBorder.DEFAULT_JUSTIFICATION,
                        TitledBorder.DEFAULT_POSITION,
                        FontUtils.getFont(FontUtils.Size.standard)));

        checkBoxEnable =
                new JCheckBox(Constant.messages.getString("network.ui.options.alpn.enable.label"));

        JLabel labelProtocols =
                new JLabel(Constant.messages.getString("network.ui.options.alpn.protocols.label"));
        checkBoxesProtocols = new LinkedHashMap<>();
        createCheckBox(TlsUtils.APPLICATION_PROTOCOL_HTTP_1_1, "http1.1");
        createCheckBox(TlsUtils.APPLICATION_PROTOCOL_HTTP_2, "http2");

        GroupLayout layout = new GroupLayout(this);
        this.setLayout(layout);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        GroupLayout.Group protocolsHorizontalGroup = layout.createSequentialGroup();
        protocolsHorizontalGroup.addComponent(labelProtocols);
        checkBoxesProtocols.values().forEach(protocolsHorizontalGroup::addComponent);

        layout.setHorizontalGroup(
                layout.createParallelGroup()
                        .addComponent(checkBoxEnable)
                        .addGroup(protocolsHorizontalGroup));

        GroupLayout.Group protocolsVerticalGroup = layout.createParallelGroup();
        protocolsVerticalGroup.addComponent(labelProtocols);
        checkBoxesProtocols.values().forEach(protocolsVerticalGroup::addComponent);

        layout.setVerticalGroup(
                layout.createSequentialGroup()
                        .addComponent(checkBoxEnable)
                        .addGroup(protocolsVerticalGroup));
    }

    private void createCheckBox(String name, String i18nKey) {
        String label =
                Constant.messages.getString(
                        "network.ui.options.alpn.protocols." + i18nKey + ".label");
        checkBoxesProtocols.put(name, new JCheckBox(label));
    }

    public void setAlpnEnabled(boolean enabled) {
        checkBoxEnable.setSelected(enabled);
    }

    public void setProtocolsSelected(List<String> selectedProtocols) {
        for (JCheckBox checkBox : checkBoxesProtocols.values()) {
            checkBox.setSelected(false);
        }

        for (String protocol : selectedProtocols) {
            JCheckBox checkBox = checkBoxesProtocols.get(protocol);
            if (checkBox != null && checkBox.isEnabled()) {
                checkBox.setSelected(true);
            }
        }
    }

    public boolean validateProtocols() {
        return validateProtocolsImpl(false);
    }

    public void validateProtocolsWithException() {
        validateProtocolsImpl(true);
    }

    private boolean validateProtocolsImpl(boolean exception) {
        for (Entry<String, JCheckBox> entry : checkBoxesProtocols.entrySet()) {
            if (entry.getValue().isSelected()) {
                return true;
            }
        }

        handleValidationError("noprotocolsselected", exception);
        checkBoxesProtocols.get(TlsUtils.APPLICATION_PROTOCOL_HTTP_1_1).requestFocusInWindow();
        return false;
    }

    private void handleValidationError(String key, boolean exception) {
        String message =
                Constant.messages.getString("network.ui.options.alpn.protocols.error." + key);
        if (exception) {
            throw new IllegalArgumentException(message);
        }
        JOptionPane.showMessageDialog(
                this,
                message,
                Constant.messages.getString("network.ui.options.alpn.protocols.error.title"),
                JOptionPane.INFORMATION_MESSAGE);
    }

    public boolean isAlpnEnabled() {
        return checkBoxEnable.isSelected();
    }

    public List<String> getSelectedProtocols() {
        return checkBoxesProtocols.entrySet().stream()
                .filter(e -> e.getValue().isSelected())
                .map(Entry::getKey)
                .collect(Collectors.toList());
    }
}
