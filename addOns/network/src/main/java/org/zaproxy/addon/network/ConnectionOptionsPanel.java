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
package org.zaproxy.addon.network;

import java.awt.Component;
import java.awt.event.ItemEvent;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.net.PasswordAuthentication;
import java.util.Arrays;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.ButtonGroup;
import javax.swing.GroupLayout;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JRadioButton;
import javax.swing.JTabbedPane;
import javax.swing.border.TitledBorder;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.network.ConnectionParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.addon.network.internal.client.CommonUserAgents;
import org.zaproxy.addon.network.internal.client.HttpProxy;
import org.zaproxy.addon.network.internal.client.SocksProxy;
import org.zaproxy.addon.network.internal.ui.HttpProxyExclusionTableModel;
import org.zaproxy.addon.network.internal.ui.HttpProxyExclusionTablePanel;
import org.zaproxy.addon.network.internal.ui.SecurityProtocolsPanel;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.utils.ZapNumberSpinner;
import org.zaproxy.zap.utils.ZapPortNumberSpinner;
import org.zaproxy.zap.utils.ZapTextField;

@SuppressWarnings("serial")
class ConnectionOptionsPanel extends AbstractParamPanel {

    private static final long serialVersionUID = 1L;

    private final GeneralPanel generalPanel;
    private final HttpProxyPanel httpProxyPanel;
    private final SocksProxyPanel socksProxyPanel;

    public ConnectionOptionsPanel() {
        generalPanel = new GeneralPanel();
        httpProxyPanel = new HttpProxyPanel();
        socksProxyPanel = new SocksProxyPanel();

        setName(Constant.messages.getString("network.ui.options.connection.name"));

        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.add(
                Constant.messages.getString("network.ui.options.connection.general.tab"),
                generalPanel.getPanel());
        tabbedPane.add(
                Constant.messages.getString("network.ui.options.connection.httpproxy.tab"),
                httpProxyPanel.getPanel());
        tabbedPane.add(
                Constant.messages.getString("network.ui.options.connection.socksproxy.tab"),
                socksProxyPanel.getPanel());

        GroupLayout mainLayout = new GroupLayout(this);
        setLayout(mainLayout);
        mainLayout.setAutoCreateGaps(true);
        mainLayout.setAutoCreateContainerGaps(true);

        mainLayout.setHorizontalGroup(mainLayout.createParallelGroup().addComponent(tabbedPane));
        mainLayout.setVerticalGroup(mainLayout.createSequentialGroup().addComponent(tabbedPane));
    }

    @Override
    public void initParam(Object mainOptions) {
        ConnectionOptions options = getConnectionOptions(mainOptions);

        generalPanel.init(options);
        httpProxyPanel.init(options);
        socksProxyPanel.init(options);
    }

    private static ConnectionOptions getConnectionOptions(Object mainOptions) {
        return ((OptionsParam) mainOptions).getParamSet(ConnectionOptions.class);
    }

    @Override
    public void validateParam(Object mainOptions) throws Exception {
        generalPanel.validate();
        httpProxyPanel.validate();
        socksProxyPanel.validate();
    }

    @Override
    public void saveParam(Object mainOptions) throws Exception {
        ConnectionOptions options = getConnectionOptions(mainOptions);

        generalPanel.save(options);
        httpProxyPanel.save(options);
        socksProxyPanel.save(options);
    }

    @Override
    public String getHelpIndex() {
        return "addon.network.options.connection";
    }

    private static class GeneralPanel {

        private final ZapNumberSpinner timeoutNumberSpinner;
        private final JComboBox<String> systemsComboBox;
        private final ZapTextField userAgentTextField;
        private final JCheckBox globalHttpStateCheckBox;
        private final ZapNumberSpinner dnsTtlSuccessfulNumberSpinner;
        private final SecurityProtocolsPanel securityProtocolsPanel;
        private final JCheckBox allowUnsafeRenegotiationCheckBox;
        private final JPanel panel;

        GeneralPanel() {
            JLabel timeoutLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "network.ui.options.connection.general.timeout"));
            timeoutNumberSpinner =
                    new ZapNumberSpinner(0, ConnectionOptions.DEFAULT_TIMEOUT, Integer.MAX_VALUE);
            timeoutLabel.setLabelFor(timeoutNumberSpinner);

            userAgentTextField = new ZapTextField();
            userAgentTextField.addActionListener(e -> updateUserAgentsComboBox());
            userAgentTextField.addKeyListener(
                    new KeyAdapter() {

                        @Override
                        public void keyReleased(KeyEvent e) {
                            updateUserAgentsComboBox();
                        }
                    });
            JLabel userAgentLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "network.ui.options.connection.general.useragent"));
            systemsComboBox = new JComboBox<>(CommonUserAgents.getSystems());
            if (systemsComboBox.getItemCount() == 0) {
                systemsComboBox.setEnabled(false);
            }
            systemsComboBox.addItem("");
            systemsComboBox.addActionListener(
                    e -> {
                        String userAgent =
                                CommonUserAgents.getUserAgentFromSystem(
                                        (String) systemsComboBox.getSelectedItem());
                        if (userAgent != null) {
                            userAgentTextField.setText(userAgent);
                        }
                    });
            userAgentLabel.setLabelFor(systemsComboBox);

            globalHttpStateCheckBox =
                    new JCheckBox(
                            Constant.messages.getString(
                                    "network.ui.options.connection.general.globalhttpstate"));

            dnsTtlSuccessfulNumberSpinner =
                    new ZapNumberSpinner(
                            -1,
                            ConnectionOptions.DNS_DEFAULT_TTL_SUCCESSFUL_QUERIES,
                            Integer.MAX_VALUE);

            JPanel dnsPanel = new JPanel();
            dnsPanel.setBorder(
                    BorderFactory.createTitledBorder(
                            null,
                            Constant.messages.getString("conn.options.dns.title"),
                            TitledBorder.DEFAULT_JUSTIFICATION,
                            TitledBorder.DEFAULT_POSITION,
                            FontUtils.getFont(FontUtils.Size.standard)));

            GroupLayout layout = new GroupLayout(dnsPanel);
            dnsPanel.setLayout(layout);
            layout.setAutoCreateGaps(true);
            layout.setAutoCreateContainerGaps(true);

            JLabel dnsTtlSuccessfulLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "conn.options.dns.ttlSuccessfulQueries.label"));
            dnsTtlSuccessfulLabel.setToolTipText(
                    Constant.messages.getString("conn.options.dns.ttlSuccessfulQueries.toolTip"));
            dnsTtlSuccessfulLabel.setLabelFor(dnsTtlSuccessfulNumberSpinner);

            layout.setHorizontalGroup(
                    layout.createSequentialGroup()
                            .addComponent(dnsTtlSuccessfulLabel)
                            .addComponent(dnsTtlSuccessfulNumberSpinner));

            layout.setVerticalGroup(
                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                            .addComponent(dnsTtlSuccessfulLabel)
                            .addComponent(dnsTtlSuccessfulNumberSpinner));

            securityProtocolsPanel = new SecurityProtocolsPanel();
            allowUnsafeRenegotiationCheckBox =
                    new JCheckBox(
                            Constant.messages.getString(
                                    "network.ui.options.connection.general.unsaferenegotiation"));
            allowUnsafeRenegotiationCheckBox.setToolTipText(
                    Constant.messages.getString(
                            "network.ui.options.connection.general.unsaferenegotiation.tooltip"));

            Component spacer = Box.createHorizontalGlue();

            panel = new JPanel();
            layout = new GroupLayout(panel);
            panel.setLayout(layout);
            layout.setAutoCreateGaps(true);
            layout.setAutoCreateContainerGaps(true);

            layout.setHorizontalGroup(
                    layout.createParallelGroup()
                            .addGroup(
                                    layout.createSequentialGroup()
                                            .addGroup(
                                                    layout.createParallelGroup(
                                                                    GroupLayout.Alignment.TRAILING)
                                                            .addComponent(timeoutLabel)
                                                            .addComponent(userAgentLabel))
                                            .addGroup(
                                                    layout.createParallelGroup(
                                                                    GroupLayout.Alignment.LEADING)
                                                            .addComponent(timeoutNumberSpinner)
                                                            .addComponent(systemsComboBox)))
                            .addComponent(userAgentTextField)
                            .addComponent(globalHttpStateCheckBox)
                            .addComponent(spacer)
                            .addComponent(dnsPanel)
                            .addComponent(securityProtocolsPanel)
                            .addComponent(allowUnsafeRenegotiationCheckBox));

            layout.setVerticalGroup(
                    layout.createSequentialGroup()
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(timeoutLabel)
                                            .addComponent(timeoutNumberSpinner))
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(userAgentLabel)
                                            .addComponent(systemsComboBox))
                            .addComponent(
                                    userAgentTextField,
                                    GroupLayout.PREFERRED_SIZE,
                                    GroupLayout.PREFERRED_SIZE,
                                    GroupLayout.PREFERRED_SIZE)
                            .addComponent(globalHttpStateCheckBox)
                            .addComponent(spacer)
                            .addComponent(dnsPanel)
                            .addComponent(securityProtocolsPanel)
                            .addComponent(allowUnsafeRenegotiationCheckBox));
        }

        private void updateUserAgentsComboBox() {
            String name = CommonUserAgents.getSystemFromUserAgent(userAgentTextField.getText());
            systemsComboBox.setSelectedItem(name != null ? name : "");
        }

        JPanel getPanel() {
            return panel;
        }

        void init(ConnectionOptions options) {
            timeoutNumberSpinner.setValue(options.getTimeoutInSecs());
            userAgentTextField.setText(options.getDefaultUserAgent());
            updateUserAgentsComboBox();
            userAgentTextField.discardAllEdits();
            globalHttpStateCheckBox.setSelected(options.isUseGlobalHttpState());
            dnsTtlSuccessfulNumberSpinner.setValue(options.getDnsTtlSuccessfulQueries());
            securityProtocolsPanel.setSecurityProtocolsEnabled(options.getTlsProtocols());
            allowUnsafeRenegotiationCheckBox.setSelected(options.isAllowUnsafeRenegotiation());
        }

        void validate() throws Exception {
            securityProtocolsPanel.validateSecurityProtocolsWithException();
        }

        void save(ConnectionOptions options) {
            options.setTimeoutInSecs(timeoutNumberSpinner.getValue());
            options.setDefaultUserAgent(userAgentTextField.getText());
            options.setUseGlobalHttpState(globalHttpStateCheckBox.isSelected());
            options.setDnsTtlSuccessfulQueries(dnsTtlSuccessfulNumberSpinner.getValue());
            options.setTlsProtocols(securityProtocolsPanel.getSelectedProtocols());
            options.setAllowUnsafeRenegotiation(allowUnsafeRenegotiationCheckBox.isSelected());
        }
    }

    private static class HttpProxyPanel {

        private final JCheckBox proxyEnabledCheckBox;
        private final ZapTextField hostTextField;
        private final ZapPortNumberSpinner portNumberSpinner;
        private final JCheckBox authEnabledCheckBox;
        private final JCheckBox storePassCheckBox;
        private final ZapTextField realmTextField;
        private final ZapTextField usernameTextField;
        private final JPasswordField passwordField;
        private final HttpProxyExclusionTableModel tableModel;
        private final HttpProxyExclusionTablePanel tablePanel;
        private final JPanel panel;

        HttpProxyPanel() {
            panel = new JPanel();
            GroupLayout layout = new GroupLayout(panel);
            panel.setLayout(layout);
            layout.setAutoCreateGaps(true);
            layout.setAutoCreateContainerGaps(true);

            hostTextField = new ZapTextField();
            hostTextField.setText(ConnectionParam.DEFAULT_SOCKS_PROXY.getHost());
            JLabel hostLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "network.ui.options.connection.httpproxy.host"));
            hostLabel.setLabelFor(hostTextField);

            portNumberSpinner =
                    new ZapPortNumberSpinner(ConnectionParam.DEFAULT_SOCKS_PROXY.getPort());
            JLabel portLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "network.ui.options.connection.httpproxy.port"));
            portLabel.setLabelFor(portNumberSpinner);

            realmTextField = new ZapTextField();
            JLabel realmLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "network.ui.options.connection.httpproxy.realm"));
            realmLabel.setLabelFor(realmTextField);

            usernameTextField = new ZapTextField();
            JLabel usernameLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "network.ui.options.connection.httpproxy.username"));
            usernameLabel.setLabelFor(usernameTextField);

            passwordField = new JPasswordField();
            JLabel passwordLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "network.ui.options.connection.httpproxy.password"));
            passwordLabel.setLabelFor(passwordField);

            storePassCheckBox =
                    new JCheckBox(
                            Constant.messages.getString(
                                    "network.ui.options.connection.httpproxy.auth.storepass"),
                            true);

            JLabel authEnabledLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "network.ui.options.connection.httpproxy.auth.enabled"));
            authEnabledCheckBox = new JCheckBox((String) null, true);
            authEnabledCheckBox.addItemListener(
                    e -> {
                        boolean state =
                                authEnabledCheckBox.isEnabled()
                                        && e.getStateChange() == ItemEvent.SELECTED;
                        storePassCheckBox.setEnabled(state);
                        realmTextField.setEnabled(state);
                        usernameTextField.setEnabled(state);
                        passwordField.setEnabled(state);
                    });
            authEnabledCheckBox.setSelected(false);
            authEnabledLabel.setLabelFor(authEnabledCheckBox);

            JLabel exclusionsLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "network.ui.options.connection.httpproxy.exclusions"));
            tableModel = new HttpProxyExclusionTableModel();
            tablePanel = new HttpProxyExclusionTablePanel(tableModel);

            JLabel proxyEnabledLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "network.ui.options.connection.httpproxy.enabled"));
            proxyEnabledCheckBox = new JCheckBox((String) null, true);
            proxyEnabledCheckBox.addItemListener(
                    e -> {
                        boolean state = e.getStateChange() == ItemEvent.SELECTED;
                        hostTextField.setEnabled(state);
                        portNumberSpinner.setEnabled(state);
                        authEnabledCheckBox.setEnabled(state);
                        boolean authState = state && authEnabledCheckBox.isSelected();
                        storePassCheckBox.setEnabled(authState);
                        realmTextField.setEnabled(authState);
                        usernameTextField.setEnabled(authState);
                        passwordField.setEnabled(authState);
                        tablePanel.setComponentEnabled(state);
                    });
            proxyEnabledCheckBox.setSelected(false);
            proxyEnabledLabel.setLabelFor(proxyEnabledCheckBox);

            layout.setHorizontalGroup(
                    layout.createParallelGroup()
                            .addGroup(
                                    layout.createSequentialGroup()
                                            .addGroup(
                                                    layout.createParallelGroup(
                                                                    GroupLayout.Alignment.TRAILING)
                                                            .addComponent(proxyEnabledLabel)
                                                            .addComponent(hostLabel)
                                                            .addComponent(portLabel)
                                                            .addComponent(authEnabledLabel)
                                                            .addComponent(realmLabel)
                                                            .addComponent(usernameLabel)
                                                            .addComponent(passwordLabel))
                                            .addGroup(
                                                    layout.createParallelGroup(
                                                                    GroupLayout.Alignment.LEADING)
                                                            .addComponent(proxyEnabledCheckBox)
                                                            .addComponent(hostTextField)
                                                            .addComponent(portNumberSpinner)
                                                            .addComponent(authEnabledCheckBox)
                                                            .addComponent(realmTextField)
                                                            .addComponent(usernameTextField)
                                                            .addComponent(passwordField)
                                                            .addComponent(storePassCheckBox)))
                            .addGroup(
                                    layout.createParallelGroup()
                                            .addComponent(exclusionsLabel)
                                            .addComponent(tablePanel)));

            layout.setVerticalGroup(
                    layout.createSequentialGroup()
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(proxyEnabledLabel)
                                            .addComponent(proxyEnabledCheckBox))
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(hostLabel)
                                            .addComponent(hostTextField))
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(portLabel)
                                            .addComponent(portNumberSpinner))
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(authEnabledLabel)
                                            .addComponent(authEnabledCheckBox))
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(realmLabel)
                                            .addComponent(realmTextField))
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(usernameLabel)
                                            .addComponent(usernameTextField))
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(passwordLabel)
                                            .addComponent(passwordField))
                            .addComponent(storePassCheckBox)
                            .addComponent(exclusionsLabel)
                            .addComponent(tablePanel));
        }

        JPanel getPanel() {
            return panel;
        }

        void init(ConnectionOptions options) {
            proxyEnabledCheckBox.setSelected(options.isHttpProxyEnabled());

            HttpProxy httpProxy = options.getHttpProxy();
            hostTextField.setText(httpProxy.getHost());
            hostTextField.discardAllEdits();
            portNumberSpinner.setValue(httpProxy.getPort());

            authEnabledCheckBox.setSelected(options.isHttpProxyAuthEnabled());
            storePassCheckBox.setSelected(options.isStoreHttpProxyPass());
            realmTextField.setText(httpProxy.getRealm());
            realmTextField.discardAllEdits();
            PasswordAuthentication passwordAuthentication = httpProxy.getPasswordAuthentication();
            usernameTextField.setText(passwordAuthentication.getUserName());
            usernameTextField.discardAllEdits();
            passwordField.setText(new String(passwordAuthentication.getPassword()));

            tableModel.setHttpProxyExclusions(options.getHttpProxyExclusions());
        }

        void validate() throws Exception {
            if (!proxyEnabledCheckBox.isSelected()) {
                if (hostTextField.getText().isEmpty()) {
                    hostTextField.setText(ConnectionOptions.DEFAULT_HTTP_PROXY.getHost());
                }
                return;
            }

            if (hostTextField.getText().isEmpty()) {
                hostTextField.requestFocus();
                throw new Exception(
                        Constant.messages.getString(
                                "network.ui.options.connection.httpproxy.host.empty"));
            }

            if (!authEnabledCheckBox.isSelected()) {
                return;
            }

            if (usernameTextField.getText().isEmpty()) {
                usernameTextField.requestFocus();
                throw new Exception(
                        Constant.messages.getString(
                                "network.ui.options.connection.httpproxy.username.empty"));
            }
        }

        void save(ConnectionOptions options) {
            options.setHttpProxyEnabled(proxyEnabledCheckBox.isSelected());
            options.setHttpProxyAuthEnabled(authEnabledCheckBox.isSelected());
            options.setStoreHttpProxyPass(storePassCheckBox.isSelected());

            HttpProxy oldHttpProxy = options.getHttpProxy();
            PasswordAuthentication passwordAuthentication =
                    oldHttpProxy.getPasswordAuthentication();
            char[] password = passwordField.getPassword();
            if (!oldHttpProxy.getHost().equals(hostTextField.getText())
                    || oldHttpProxy.getPort() != portNumberSpinner.getValue()
                    || !oldHttpProxy.getRealm().equals(realmTextField.getText())
                    || !passwordAuthentication.getUserName().equals(usernameTextField.getText())
                    || !Arrays.equals(passwordAuthentication.getPassword(), password)) {
                options.setHttpProxy(
                        new HttpProxy(
                                hostTextField.getText(),
                                portNumberSpinner.getValue(),
                                realmTextField.getText(),
                                new PasswordAuthentication(usernameTextField.getText(), password)));
            }

            options.setHttpProxyExclusions(tableModel.getElements());
        }
    }

    private static class SocksProxyPanel {

        private final JCheckBox proxyEnabledCheckBox;
        private final ZapTextField hostTextField;
        private final ZapPortNumberSpinner portNumberSpinner;
        private final JRadioButton version4RadioButton;
        private final JRadioButton version5RadioButton;
        private final JCheckBox useSocksDnsCheckBox;
        private final ZapTextField usernameTextField;
        private final JPasswordField passwordField;
        private final JPanel panel;

        public SocksProxyPanel() {
            panel = new JPanel();
            GroupLayout layout = new GroupLayout(panel);
            panel.setLayout(layout);
            layout.setAutoCreateGaps(true);
            layout.setAutoCreateContainerGaps(true);

            hostTextField = new ZapTextField();
            hostTextField.setText(ConnectionParam.DEFAULT_SOCKS_PROXY.getHost());
            JLabel hostLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "network.ui.options.connection.socksproxy.host"));
            hostLabel.setLabelFor(hostTextField);

            portNumberSpinner =
                    new ZapPortNumberSpinner(ConnectionParam.DEFAULT_SOCKS_PROXY.getPort());
            JLabel portLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "network.ui.options.connection.socksproxy.port"));
            portLabel.setLabelFor(portNumberSpinner);

            JLabel versionLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "network.ui.options.connection.socksproxy.version"));
            version4RadioButton = new JRadioButton("4a");
            version5RadioButton = new JRadioButton("5");

            ButtonGroup versionButtonGroup = new ButtonGroup();
            versionButtonGroup.add(version4RadioButton);
            versionButtonGroup.add(version5RadioButton);
            version4RadioButton.setSelected(true);

            useSocksDnsCheckBox =
                    new JCheckBox(
                            Constant.messages.getString(
                                    "network.ui.options.connection.socksproxy.dns"));
            useSocksDnsCheckBox.setToolTipText(
                    Constant.messages.getString(
                            "network.ui.options.connection.socksproxy.dns.tooltip"));
            useSocksDnsCheckBox.setSelected(true);

            usernameTextField = new ZapTextField();
            JLabel usernameLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "network.ui.options.connection.socksproxy.username"));
            usernameLabel.setLabelFor(usernameTextField);

            passwordField = new JPasswordField();
            JLabel passwordLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "network.ui.options.connection.socksproxy.password"));
            passwordLabel.setLabelFor(passwordField);

            JLabel proxyEnabledLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "network.ui.options.connection.socksproxy.enabled"));
            proxyEnabledCheckBox = new JCheckBox((String) null, true);
            proxyEnabledCheckBox.addItemListener(
                    e -> {
                        boolean state = e.getStateChange() == ItemEvent.SELECTED;
                        hostTextField.setEnabled(state);
                        portNumberSpinner.setEnabled(state);
                        version4RadioButton.setEnabled(state);
                        version5RadioButton.setEnabled(state);
                        useSocksDnsCheckBox.setEnabled(state && version5RadioButton.isSelected());
                        usernameTextField.setEnabled(state);
                        passwordField.setEnabled(state);
                    });
            proxyEnabledCheckBox.setSelected(false);
            proxyEnabledLabel.setLabelFor(proxyEnabledCheckBox);

            version5RadioButton.addItemListener(
                    e ->
                            useSocksDnsCheckBox.setEnabled(
                                    e.getStateChange() == ItemEvent.SELECTED
                                            && proxyEnabledCheckBox.isSelected()));
            setSelectedVersion(ConnectionOptions.DEFAULT_SOCKS_PROXY.getVersion());

            layout.setHorizontalGroup(
                    layout.createSequentialGroup()
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                            .addComponent(proxyEnabledLabel)
                                            .addComponent(hostLabel)
                                            .addComponent(portLabel)
                                            .addComponent(versionLabel)
                                            .addComponent(usernameLabel)
                                            .addComponent(passwordLabel))
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                            .addComponent(proxyEnabledCheckBox)
                                            .addComponent(hostTextField)
                                            .addComponent(portNumberSpinner)
                                            .addGroup(
                                                    layout.createParallelGroup()
                                                            .addGroup(
                                                                    layout.createSequentialGroup()
                                                                            .addComponent(
                                                                                    version4RadioButton)
                                                                            .addComponent(
                                                                                    version5RadioButton))
                                                            .addComponent(useSocksDnsCheckBox))
                                            .addComponent(usernameTextField)
                                            .addComponent(passwordField)));

            layout.setVerticalGroup(
                    layout.createSequentialGroup()
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(proxyEnabledLabel)
                                            .addComponent(proxyEnabledCheckBox))
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(hostLabel)
                                            .addComponent(hostTextField))
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(portLabel)
                                            .addComponent(portNumberSpinner))
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(versionLabel)
                                            .addComponent(version4RadioButton)
                                            .addComponent(version5RadioButton))
                            .addComponent(useSocksDnsCheckBox)
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(usernameLabel)
                                            .addComponent(usernameTextField))
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(passwordLabel)
                                            .addComponent(passwordField)));
        }

        JPanel getPanel() {
            return panel;
        }

        private void setSelectedVersion(SocksProxy.Version version) {
            switch (version) {
                case SOCKS4A:
                    version4RadioButton.setSelected(true);
                    break;
                case SOCKS5:
                default:
                    version5RadioButton.setSelected(true);
            }
        }

        private SocksProxy.Version getSelectedVersion() {
            if (version4RadioButton.isSelected()) {
                return SocksProxy.Version.SOCKS4A;
            }
            return SocksProxy.Version.SOCKS5;
        }

        void init(ConnectionOptions options) {
            proxyEnabledCheckBox.setSelected(options.isSocksProxyEnabled());

            SocksProxy socksProxy = options.getSocksProxy();
            hostTextField.setText(socksProxy.getHost());
            hostTextField.discardAllEdits();
            portNumberSpinner.setValue(socksProxy.getPort());
            setSelectedVersion(socksProxy.getVersion());
            useSocksDnsCheckBox.setSelected(socksProxy.isUseDns());

            PasswordAuthentication passwordAuthentication = socksProxy.getPasswordAuthentication();
            usernameTextField.setText(passwordAuthentication.getUserName());
            usernameTextField.discardAllEdits();
            passwordField.setText(new String(passwordAuthentication.getPassword()));
        }

        void validate() throws Exception {
            if (!hostTextField.getText().isEmpty()) {
                return;
            }

            if (proxyEnabledCheckBox.isSelected()) {
                hostTextField.requestFocus();
                throw new Exception(
                        Constant.messages.getString(
                                "network.ui.options.connection.socksproxy.host.empty"));
            }
            hostTextField.setText(ConnectionOptions.DEFAULT_SOCKS_PROXY.getHost());
        }

        void save(ConnectionOptions options) {
            options.setSocksProxyEnabled(proxyEnabledCheckBox.isSelected());

            SocksProxy oldSocksProxy = options.getSocksProxy();
            PasswordAuthentication passwordAuthentication =
                    oldSocksProxy.getPasswordAuthentication();
            char[] password = passwordField.getPassword();
            if (!oldSocksProxy.getHost().equals(hostTextField.getText())
                    || oldSocksProxy.getPort() != portNumberSpinner.getValue()
                    || oldSocksProxy.getVersion() != getSelectedVersion()
                    || oldSocksProxy.isUseDns() != useSocksDnsCheckBox.isSelected()
                    || !passwordAuthentication.getUserName().equals(usernameTextField.getText())
                    || !Arrays.equals(passwordAuthentication.getPassword(), password)) {
                options.setSocksProxy(
                        new SocksProxy(
                                hostTextField.getText(),
                                portNumberSpinner.getValue(),
                                getSelectedVersion(),
                                useSocksDnsCheckBox.isSelected(),
                                new PasswordAuthentication(usernameTextField.getText(), password)));
            }
        }
    }
}
