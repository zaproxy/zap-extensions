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
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import javax.swing.BorderFactory;
import javax.swing.GroupLayout;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.border.TitledBorder;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.addon.network.internal.server.http.LocalServerConfig;
import org.zaproxy.addon.network.internal.ui.AliasTableModel;
import org.zaproxy.addon.network.internal.ui.AliasTablePanel;
import org.zaproxy.addon.network.internal.ui.LocalServersTableModel;
import org.zaproxy.addon.network.internal.ui.LocalServersTablePanel;
import org.zaproxy.addon.network.internal.ui.MainProxyPanel;
import org.zaproxy.addon.network.internal.ui.PassThroughTableModel;
import org.zaproxy.addon.network.internal.ui.PassThroughTablePanel;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.utils.ZapLabel;

@SuppressWarnings("serial")
class LocalServersOptionsPanel extends AbstractParamPanel {

    private static final long serialVersionUID = 1L;

    private final ServersPanel serversPanel;
    private final AliasPanel aliasPanel;
    private final PassThroughPanel passThroughPanel;

    public LocalServersOptionsPanel(ExtensionNetwork extensionNetwork) {
        serversPanel = new ServersPanel(extensionNetwork);
        aliasPanel = new AliasPanel();
        passThroughPanel = new PassThroughPanel();

        setName(Constant.messages.getString("network.ui.options.localservers.name"));

        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.add(
                Constant.messages.getString("network.ui.options.localservers.name"),
                serversPanel.getPanel());
        tabbedPane.add(
                Constant.messages.getString("network.ui.options.alias.tab"), aliasPanel.getPanel());
        tabbedPane.add(
                Constant.messages.getString("network.ui.options.passthrough.tab"),
                passThroughPanel.getPanel());

        GroupLayout mainLayout = new GroupLayout(this);
        setLayout(mainLayout);
        mainLayout.setAutoCreateGaps(true);
        mainLayout.setAutoCreateContainerGaps(true);

        mainLayout.setHorizontalGroup(mainLayout.createParallelGroup().addComponent(tabbedPane));
        mainLayout.setVerticalGroup(mainLayout.createSequentialGroup().addComponent(tabbedPane));
    }

    @Override
    public void initParam(Object mainOptions) {
        LocalServersOptions options = getLocalServersOptions(mainOptions);

        serversPanel.init(options);
        aliasPanel.init(options);
        passThroughPanel.init(options);
    }

    private static LocalServersOptions getLocalServersOptions(Object mainOptions) {
        return ((OptionsParam) mainOptions).getParamSet(LocalServersOptions.class);
    }

    @Override
    public void validateParam(Object mainOptions) throws Exception {
        LocalServersOptions options = getLocalServersOptions(mainOptions);

        serversPanel.validate(options);
    }

    @Override
    public void saveParam(Object mainOptions) throws Exception {
        LocalServersOptions options = getLocalServersOptions(mainOptions);

        serversPanel.save(options);
        aliasPanel.save(options);
        passThroughPanel.save(options);
    }

    @Override
    public String getHelpIndex() {
        return "addon.network.options.localservers";
    }

    private static class ServersPanel {

        private final ExtensionNetwork extensionNetwork;
        private final MainProxyPanel mainProxyPanel;
        private final LocalServersTablePanel localServersTablePanel;
        private final LocalServersTableModel localServersTableModel;
        private final JPanel panel;

        ServersPanel(ExtensionNetwork extensionNetwork) {
            this.extensionNetwork = extensionNetwork;

            ZapLabel labelDesc =
                    new ZapLabel(
                            Constant.messages.getString("network.ui.options.localservers.desc"));

            mainProxyPanel = new MainProxyPanel();
            mainProxyPanel.setFont(FontUtils.getFont(FontUtils.Size.standard));
            mainProxyPanel.setBorder(
                    BorderFactory.createTitledBorder(
                            null,
                            Constant.messages.getString(
                                    "network.ui.options.localservers.mainproxy.title"),
                            TitledBorder.DEFAULT_JUSTIFICATION,
                            TitledBorder.DEFAULT_POSITION,
                            FontUtils.getFont(FontUtils.Size.standard)));

            localServersTableModel = new LocalServersTableModel();
            localServersTablePanel =
                    new LocalServersTablePanel(this::validateAddress, localServersTableModel);
            localServersTablePanel.setBorder(
                    BorderFactory.createTitledBorder(
                            null,
                            Constant.messages.getString(
                                    "network.ui.options.localservers.servers.title"),
                            TitledBorder.DEFAULT_JUSTIFICATION,
                            TitledBorder.DEFAULT_POSITION,
                            FontUtils.getFont(FontUtils.Size.standard)));

            panel = new JPanel();
            GroupLayout layout = new GroupLayout(panel);
            panel.setLayout(layout);
            layout.setAutoCreateGaps(true);
            layout.setAutoCreateContainerGaps(true);

            layout.setHorizontalGroup(
                    layout.createParallelGroup()
                            .addComponent(labelDesc)
                            .addComponent(mainProxyPanel)
                            .addComponent(localServersTablePanel));

            layout.setVerticalGroup(
                    layout.createSequentialGroup()
                            .addComponent(
                                    labelDesc,
                                    GroupLayout.PREFERRED_SIZE,
                                    GroupLayout.PREFERRED_SIZE,
                                    GroupLayout.PREFERRED_SIZE)
                            .addComponent(
                                    mainProxyPanel,
                                    GroupLayout.PREFERRED_SIZE,
                                    GroupLayout.PREFERRED_SIZE,
                                    GroupLayout.PREFERRED_SIZE)
                            .addComponent(localServersTablePanel));
        }

        private boolean validateAddress(Component parent, String address, int port) {
            if (hasSameAddress(address, port, mainProxyPanel.getServerConfig())
                    || localServersTableModel.getElements().stream()
                            .anyMatch(e -> hasSameAddress(address, port, e))) {
                JOptionPane.showMessageDialog(
                        parent,
                        Constant.messages.getString(
                                "network.ui.options.localservers.servers.duplicated",
                                address + ":" + port),
                        Constant.messages.getString(
                                "network.ui.options.localservers.servers.duplicated.title"),
                        JOptionPane.INFORMATION_MESSAGE);
                return false;
            }

            return true;
        }

        private static boolean hasSameAddress(String address, int port, LocalServerConfig server) {
            return address.equals(server.getAddress()) && port == server.getPort();
        }

        JPanel getPanel() {
            return panel;
        }

        void init(LocalServersOptions options) {
            mainProxyPanel.setServerConfig(options.getMainProxy());
            localServersTableModel.setServers(options.getServers());
            localServersTablePanel.setRemoveWithoutConfirmation(!options.isConfirmRemoveServer());
        }

        void validate(LocalServersOptions options) throws Exception {
            mainProxyPanel.validateFields();

            validateListeningAddresses(options);
        }

        void save(LocalServersOptions options) {
            options.setMainProxy(mainProxyPanel.getServerConfig());
            options.setServers(localServersTableModel.getElements());
            options.setConfirmRemoveServer(!localServersTablePanel.isRemoveWithoutConfirmation());
        }

        private void validateListeningAddresses(LocalServersOptions options) throws Exception {
            Set<LocalServerConfig> requiredConfigs =
                    new TreeSet<>(
                            (o1, o2) -> {
                                int result = Integer.compare(o1.getPort(), o2.getPort());
                                if (result != 0) {
                                    return result;
                                }
                                return o1.getAddress().compareToIgnoreCase(o2.getAddress());
                            });

            requiredConfigs.add(mainProxyPanel.getServerConfig());
            for (LocalServerConfig server : localServersTableModel.getElements()) {
                if (server.isEnabled() && !requiredConfigs.add(server)) {
                    throw newDuplicatedServerException(server);
                }
            }

            extensionNetwork.removeStartedLocalServers(requiredConfigs);

            Set<ListeningAddress> listeningAddresses = new HashSet<>();
            for (LocalServerConfig requiredConfig : requiredConfigs) {
                try (ServerSocket socket =
                        new ServerSocket(
                                requiredConfig.getPort(),
                                0,
                                InetAddress.getByName(requiredConfig.getAddress()))) {
                    if (!listeningAddresses.add(
                            new ListeningAddress(socket.getInetAddress(), socket.getLocalPort()))) {
                        throw newDuplicatedServerException(requiredConfig);
                    }
                } catch (IOException e) {
                    throw new Exception(
                            Constant.messages.getString(
                                    "network.ui.options.localservers.servers.binderror",
                                    toAddress(requiredConfig)));
                }
            }
        }

        private static Exception newDuplicatedServerException(LocalServerConfig serverConfig) {
            return new Exception(
                    Constant.messages.getString(
                            "network.ui.options.localservers.servers.duplicated",
                            toAddress(serverConfig)));
        }

        private static String toAddress(LocalServerConfig config) {
            return config.getAddress() + ":" + config.getPort();
        }

        private static class ListeningAddress {
            private final byte[] address;
            private final int port;

            ListeningAddress(InetAddress address, int port) {
                this.address = address.getAddress();
                this.port = port;
            }

            @Override
            public int hashCode() {
                final int prime = 31;
                int result = prime + Arrays.hashCode(address);
                result = prime * result + Objects.hash(port);
                return result;
            }

            @Override
            public boolean equals(Object obj) {
                ListeningAddress other = (ListeningAddress) obj;
                return Arrays.equals(address, other.address) && port == other.port;
            }
        }
    }

    private static class AliasPanel {

        private final AliasTableModel tableModel;
        private final AliasTablePanel tablePanel;
        private final JPanel panel;

        AliasPanel() {
            tableModel = new AliasTableModel();
            tablePanel = new AliasTablePanel(tableModel);

            panel = new JPanel();
            GroupLayout layout = new GroupLayout(panel);
            panel.setLayout(layout);
            layout.setAutoCreateGaps(true);
            layout.setAutoCreateContainerGaps(true);

            layout.setHorizontalGroup(layout.createParallelGroup().addComponent(tablePanel));

            layout.setVerticalGroup(layout.createSequentialGroup().addComponent(tablePanel));
        }

        JPanel getPanel() {
            return panel;
        }

        void init(LocalServersOptions options) {
            tableModel.setAliases(options.getAliases());
            tablePanel.setRemoveWithoutConfirmation(!options.isConfirmRemoveAlias());
        }

        void save(LocalServersOptions options) {
            options.setAliases(tableModel.getElements());
            options.setConfirmRemoveAlias(!tablePanel.isRemoveWithoutConfirmation());
        }
    }

    private static class PassThroughPanel {

        private final PassThroughTableModel tableModel;
        private final PassThroughTablePanel tablePanel;
        private final JPanel panel;

        PassThroughPanel() {
            tableModel = new PassThroughTableModel();
            tablePanel = new PassThroughTablePanel(tableModel);

            panel = new JPanel();
            GroupLayout layout = new GroupLayout(panel);
            panel.setLayout(layout);
            layout.setAutoCreateGaps(true);
            layout.setAutoCreateContainerGaps(true);

            layout.setHorizontalGroup(layout.createParallelGroup().addComponent(tablePanel));

            layout.setVerticalGroup(layout.createSequentialGroup().addComponent(tablePanel));
        }

        JPanel getPanel() {
            return panel;
        }

        void init(LocalServersOptions options) {
            tableModel.setPassThroughs(options.getPassThroughs());
            tablePanel.setRemoveWithoutConfirmation(!options.isConfirmRemovePassThrough());
        }

        void save(LocalServersOptions options) {
            options.setPassThroughs(tableModel.getElements());
            options.setConfirmRemovePassThrough(!tablePanel.isRemoveWithoutConfirmation());
        }
    }
}
