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

import java.util.List;
import java.util.Objects;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import javax.swing.JLabel;
import javax.swing.JToolBar;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.MainFooterPanel;
import org.zaproxy.addon.network.LocalServersOptions;
import org.zaproxy.addon.network.LocalServersOptions.ServersChangedListener;
import org.zaproxy.addon.network.internal.server.http.LocalServerConfig;

/** Shows information about the local servers in the footer panel. */
public class LocalServerInfoLabel {

    private static final String NEWLINE = "<br>";

    private final MainFooterPanel mainFooterPanel;
    private final LocalServersOptions localServersOptions;
    private final JToolBar.Separator separator;
    private final JLabel label;

    /**
     * Constructs a {@code LocalServerInfoLabel} with the given data.
     *
     * @param mainFooterPanel the footer panel.
     * @param localServersOptions the source of the info.
     * @throws NullPointerException if the given panel or options is {@code null}.
     */
    public LocalServerInfoLabel(
            MainFooterPanel mainFooterPanel, LocalServersOptions localServersOptions) {
        this.mainFooterPanel = Objects.requireNonNull(mainFooterPanel);
        this.localServersOptions = Objects.requireNonNull(localServersOptions);

        separator = new JToolBar.Separator();
        label = new JLabel();

        mainFooterPanel.addFooterToolbarLeftComponent(separator);
        mainFooterPanel.addFooterToolbarLeftComponent(label);

        localServersOptions.addServersChangedListener(
                new ServersChangedListener() {

                    @Override
                    public void mainProxySet(LocalServerConfig mainProxyConfig) {
                        update();
                    }

                    @Override
                    public void serverAdded(LocalServerConfig serverConfig) {
                        update();
                    }

                    @Override
                    public void serverRemoved(LocalServerConfig serverConfig) {
                        update();
                    }

                    @Override
                    public void serversSet(List<LocalServerConfig> servers) {
                        update();
                    }
                });
    }

    /** Unloads the info from the panel. */
    public void unload() {
        mainFooterPanel.removeFooterToolbarLeftComponent(separator);
        mainFooterPanel.removeFooterToolbarLeftComponent(label);
    }

    /** Updates the info label with current options. */
    public void update() {
        LocalServerConfig mainProxy = localServersOptions.getMainProxy();
        List<LocalServerConfig> servers = localServersOptions.getServers();
        String text =
                Constant.messages.getString(
                        "network.ui.footer.proxies.main", getProxyRepresentation(mainProxy));
        label.setText(text);
        label.setToolTipText(createTooltip(mainProxy, servers));
    }

    private static String createTooltip(
            LocalServerConfig mainProxy, List<LocalServerConfig> servers) {
        StringBuilder strBuilder = new StringBuilder(150);
        strBuilder
                .append("<html>")
                .append(Constant.messages.getString("network.ui.footer.proxies.tooltip.main"))
                .append(NEWLINE)
                .append(getProxyRepresentation(mainProxy));
        addAdditionalProxiesToolTip(
                strBuilder,
                servers,
                "network.ui.footer.proxies.tooltip.additional.enabled",
                LocalServerConfig::isEnabled);
        addAdditionalProxiesToolTip(
                strBuilder,
                servers,
                "network.ui.footer.proxies.tooltip.additional.disabled",
                ((Predicate<LocalServerConfig>) LocalServerConfig::isEnabled).negate());
        strBuilder.append("</html>");
        return strBuilder.toString();
    }

    private static void addAdditionalProxiesToolTip(
            StringBuilder strBuilder,
            List<LocalServerConfig> servers,
            String titleKey,
            Predicate<LocalServerConfig> predicate) {
        if (servers.isEmpty()) {
            return;
        }

        List<String> labels =
                servers.stream()
                        .filter(e -> e.getMode().hasProxy())
                        .filter(predicate)
                        .map(LocalServerInfoLabel::getProxyRepresentation)
                        .collect(Collectors.toList());
        if (labels.isEmpty()) {
            return;
        }

        strBuilder.append(NEWLINE).append(NEWLINE);
        strBuilder.append(Constant.messages.getString(titleKey));
        labels.forEach(label -> strBuilder.append(NEWLINE).append(label));
    }

    private static String getProxyRepresentation(LocalServerConfig config) {
        return Constant.messages.getString(
                "network.ui.footer.proxies.representation",
                config.getAddress(),
                String.valueOf(config.getPort()));
    }
}
