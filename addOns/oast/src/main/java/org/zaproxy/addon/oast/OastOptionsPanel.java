/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.addon.oast;

import java.awt.CardLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.addon.oast.base.OastServer;
import org.zaproxy.zap.view.LayoutHelper;

public class OastOptionsPanel extends AbstractParamPanel {

    private static final long serialVersionUID = 1L;

    private final ExtensionOast extOast;

    private JComboBox<String> serverOptions = null;

    public OastOptionsPanel(ExtensionOast extOast) {
        super();
        this.extOast = extOast;
        setName(Constant.messages.getString("oast.options.title"));

        setLayout(new GridBagLayout());

        JLabel serversLabel = new JLabel(Constant.messages.getString("oast.options.label.server"));
        serversLabel.setLabelFor(getOastServerOptions());
        add(
                serversLabel,
                LayoutHelper.getGBC(
                        0, 0, GridBagConstraints.RELATIVE, 0.4, new Insets(2, 2, 2, 2)));
        add(
                getOastServerOptions(),
                LayoutHelper.getGBC(
                        1, 0, GridBagConstraints.REMAINDER, 0.6, new Insets(2, 2, 2, 5)));

        JPanel serverPanels = new JPanel(new CardLayout());
        for (OastServer server : extOast.getOastServers().values()) {
            serverPanels.add(server.getOptionsPanelCard(), server.getName());
        }

        getOastServerOptions()
                .addActionListener(
                        (e) -> {
                            CardLayout servers = (CardLayout) serverPanels.getLayout();
                            servers.show(
                                    serverPanels,
                                    getOastServerOptions().getSelectedItem().toString());
                        });

        add(
                serverPanels,
                LayoutHelper.getGBC(
                        0,
                        1,
                        GridBagConstraints.REMAINDER,
                        1.0,
                        1.0,
                        GridBagConstraints.BOTH,
                        new Insets(0, 0, 0, 3)));
    }

    @Override
    public void initParam(Object obj) {
        final OptionsParam options = (OptionsParam) obj;
        final OastParam param = options.getParamSet(OastParam.class);

        getOastServerOptions().setSelectedItem(param.getOastServer());

        for (OastServer server : extOast.getOastServers().values()) {
            server.getOptionsPanelCard().initParam(obj);
        }
    }

    @Override
    public void saveParam(Object obj) {
        final OptionsParam options = (OptionsParam) obj;
        final OastParam param = options.getParamSet(OastParam.class);

        param.setOastServer((String) getOastServerOptions().getSelectedItem());

        for (OastServer server : extOast.getOastServers().values()) {
            server.getOptionsPanelCard().saveParam(obj);
        }
    }

    private JComboBox<String> getOastServerOptions() {
        if (serverOptions == null) {
            serverOptions =
                    new JComboBox<>(extOast.getOastServers().keySet().toArray(new String[0]));
        }
        return serverOptions;
    }

    @Override
    public String getHelpIndex() {
        return "oast.options";
    }
}
