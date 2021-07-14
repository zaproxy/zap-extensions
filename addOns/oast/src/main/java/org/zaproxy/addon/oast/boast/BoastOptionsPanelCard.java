/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.oast.boast;

import java.awt.GridBagConstraints;
import java.awt.Insets;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import net.sf.json.JSONObject;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.oast.base.OastOptionsPanelCard;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.LayoutHelper;

public class BoastOptionsPanelCard extends OastOptionsPanelCard {

    private static final long serialVersionUID = 1L;

    private BoastServer boastServer;
    private ZapTextField boastUri;
    private JTextField boastId;
    private JTextField boastCanary;
    private JButton boastRegisterButton;

    public BoastOptionsPanelCard(BoastServer boastServer) {
        super(boastServer);

        this.boastServer = boastServer;

        JLabel boastUriLabel =
                new JLabel(Constant.messages.getString("oast.boast.options.label.uri"));
        boastUriLabel.setLabelFor(getBoastUri());
        int rowIndex = -1;
        this.add(boastUriLabel, LayoutHelper.getGBC(0, ++rowIndex, 1, 0.4, new Insets(2, 2, 2, 2)));
        this.add(getBoastUri(), LayoutHelper.getGBC(1, rowIndex, 1, 0.6, new Insets(2, 2, 2, 2)));

        JLabel boastIdLabel =
                new JLabel(Constant.messages.getString("oast.boast.options.label.id"));
        boastIdLabel.setLabelFor(getBoastId());
        this.add(boastIdLabel, LayoutHelper.getGBC(0, ++rowIndex, 1, 0.4, new Insets(2, 2, 2, 2)));
        this.add(getBoastId(), LayoutHelper.getGBC(1, rowIndex, 1, 0.6, new Insets(2, 2, 2, 2)));

        JLabel boastCanaryLabel =
                new JLabel(Constant.messages.getString("oast.boast.options.label.canary"));
        boastCanaryLabel.setLabelFor(getBoastCanary());
        this.add(
                boastCanaryLabel,
                LayoutHelper.getGBC(0, ++rowIndex, 1, 0.4, new Insets(2, 2, 2, 2)));
        this.add(
                getBoastCanary(), LayoutHelper.getGBC(1, rowIndex, 1, 0.6, new Insets(2, 2, 2, 2)));

        this.add(
                getBoastRegisterButton(),
                LayoutHelper.getGBC(1, ++rowIndex, 1, 0, new Insets(2, 2, 2, 2)));

        this.add(
                new JLabel(),
                LayoutHelper.getGBC(0, ++rowIndex, GridBagConstraints.REMAINDER, 0, 1.0));
    }

    ZapTextField getBoastUri() {
        if (boastUri == null) {
            boastUri = new ZapTextField();
        }
        return boastUri;
    }

    JTextField getBoastId() {
        if (boastId == null) {
            boastId = new JTextField();
            boastId.setEditable(false);
        }
        return boastId;
    }

    JTextField getBoastCanary() {
        if (boastCanary == null) {
            boastCanary = new JTextField();
            boastCanary.setEditable(false);
        }
        return boastCanary;
    }

    private JButton getBoastRegisterButton() {
        if (boastRegisterButton == null) {
            boastRegisterButton =
                    new JButton(Constant.messages.getString("oast.boast.options.button.register"));
            boastRegisterButton.addActionListener(
                    e -> SwingUtilities.invokeLater(this::registerButtonAction));
        }
        return boastRegisterButton;
    }

    private void registerButtonAction() {
        try {
            JSONObject response = boastServer.register(getBoastUri().getText());
            getBoastId().setText(response.getString("id"));
            getBoastCanary().setText(response.getString("canary"));
        } catch (Exception exception) {
            View.getSingleton().showWarningDialog(this, exception.getLocalizedMessage());
        }
    }

    @Override
    public void initParam(Object obj) {
        final OptionsParam options = (OptionsParam) obj;
        final BoastParam param = options.getParamSet(BoastParam.class);
        getBoastUri().setText(param.getBoastUri());
    }

    @Override
    public void saveParam(Object obj) {
        final OptionsParam options = (OptionsParam) obj;
        final BoastParam param = options.getParamSet(BoastParam.class);
        param.setBoastUri(getBoastUri().getText());
    }
}
