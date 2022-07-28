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
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.border.TitledBorder;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.network.internal.TlsUtils;
import org.zaproxy.zap.utils.FontUtils;

/**
 * A {@code JPanel} for selecting security protocols for the servers.
 *
 * @see TlsUtils
 */
@SuppressWarnings("serial")
public class SecurityProtocolsPanel extends JPanel {

    private static final long serialVersionUID = 1L;

    private final Map<String, JCheckBox> checkBoxesSslTlsProtocols;
    private boolean supportedSecurityProtocolsInitialised;

    public SecurityProtocolsPanel() {
        setBorder(
                BorderFactory.createTitledBorder(
                        null,
                        Constant.messages.getString("network.ui.options.securityprotocols.title"),
                        TitledBorder.DEFAULT_JUSTIFICATION,
                        TitledBorder.DEFAULT_POSITION,
                        FontUtils.getFont(FontUtils.Size.standard)));

        checkBoxesSslTlsProtocols = new LinkedHashMap<>();
        createCheckBox(TlsUtils.SSL_V2_HELLO, "ssl2hello");
        createCheckBox(TlsUtils.SSL_V3, "ssl3");
        createCheckBox(TlsUtils.TLS_V1, "tlsv1");
        createCheckBox(TlsUtils.TLS_V1_1, "tlsv1.1");
        createCheckBox(TlsUtils.TLS_V1_2, "tlsv1.2");
        createCheckBox(TlsUtils.TLS_V1_3, "tlsv1.3");

        GroupLayout layout = new GroupLayout(this);
        this.setLayout(layout);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        GroupLayout.Group horizontalGroup = layout.createSequentialGroup();
        checkBoxesSslTlsProtocols.values().forEach(horizontalGroup::addComponent);
        layout.setHorizontalGroup(horizontalGroup);

        GroupLayout.Group verticalGroup = layout.createParallelGroup();
        checkBoxesSslTlsProtocols.values().forEach(verticalGroup::addComponent);
        layout.setVerticalGroup(verticalGroup);
    }

    private void createCheckBox(String name, String i18nKey) {
        String label =
                Constant.messages.getString(
                        "network.ui.options.securityprotocols." + i18nKey + ".label");
        JCheckBox checkBox = new JCheckBox(label);
        checkBox.setEnabled(false);
        checkBoxesSslTlsProtocols.put(name, checkBox);
    }

    public void setSecurityProtocolsEnabled(List<String> selectedProtocols) {
        if (!supportedSecurityProtocolsInitialised) {
            List<String> protocols = TlsUtils.getSupportedProtocols();
            for (String protocol : protocols) {
                JCheckBox checkBox = checkBoxesSslTlsProtocols.get(protocol);
                if (checkBox != null) {
                    checkBox.setEnabled(true);
                }
            }
            String toolTip = null;
            for (JCheckBox checkBox : checkBoxesSslTlsProtocols.values()) {
                if (!checkBox.isEnabled()) {
                    if (toolTip == null) {
                        toolTip =
                                Constant.messages.getString(
                                        "network.ui.options.securityprotocols.protocolnotsupportedtooltip");
                    }
                    checkBox.setToolTipText(toolTip);
                }
            }
            supportedSecurityProtocolsInitialised = true;
        }

        for (JCheckBox checkBox : checkBoxesSslTlsProtocols.values()) {
            checkBox.setSelected(false);
        }

        if (selectedProtocols != null) {
            for (String protocol : selectedProtocols) {
                JCheckBox checkBox = checkBoxesSslTlsProtocols.get(protocol);
                if (checkBox != null && checkBox.isEnabled()) {
                    checkBox.setSelected(true);
                }
            }
        }
    }

    public boolean validateSecurityProtocols() {
        return validateSecurityProtocolsImpl(false);
    }

    public void validateSecurityProtocolsWithException() {
        validateSecurityProtocolsImpl(true);
    }

    private boolean validateSecurityProtocolsImpl(boolean exception) {
        int protocolsSelected = 0;
        JCheckBox checkBoxEnabledProtocol = null;
        for (Entry<String, JCheckBox> entry : checkBoxesSslTlsProtocols.entrySet()) {
            JCheckBox checkBox = entry.getValue();
            if (checkBox.isEnabled()) {
                if (checkBoxEnabledProtocol == null) {
                    checkBoxEnabledProtocol = checkBox;
                }
                if (checkBox.isSelected()) {
                    protocolsSelected++;
                    if (protocolsSelected > 1) {
                        break;
                    }
                }
            }
        }

        if (checkBoxEnabledProtocol != null) {
            if (protocolsSelected == 0) {
                handleValidationError("noprotocolsselected", exception);
                checkBoxEnabledProtocol.requestFocusInWindow();
                return false;
            }

            if (protocolsSelected == 1
                    && checkBoxesSslTlsProtocols.get(TlsUtils.SSL_V2_HELLO).isSelected()) {
                handleValidationError("justsslv2helloselected", exception);
                checkBoxEnabledProtocol.requestFocusInWindow();
                return false;
            }
        }
        return true;
    }

    private void handleValidationError(String key, boolean exception) {
        String message =
                Constant.messages.getString("network.ui.options.securityprotocols.error." + key);
        if (exception) {
            throw new IllegalArgumentException(message);
        }
        JOptionPane.showMessageDialog(
                this,
                message,
                Constant.messages.getString("network.ui.options.securityprotocols.error.title"),
                JOptionPane.INFORMATION_MESSAGE);
    }

    public List<String> getSelectedProtocols() {
        return checkBoxesSslTlsProtocols.entrySet().stream()
                .filter(
                        e -> {
                            JCheckBox checkBox = e.getValue();
                            return checkBox.isEnabled() && checkBox.isSelected();
                        })
                .map(Entry::getKey)
                .collect(Collectors.toList());
    }
}
