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
package org.zaproxy.addon.oast.services.callback;

import java.awt.GridBagConstraints;
import java.awt.Insets;
import java.util.List;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.SwingUtilities;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.zaproxy.addon.oast.ui.OastOptionsPanelTab;
import org.zaproxy.zap.utils.NetworkUtils;
import org.zaproxy.zap.utils.ZapPortNumberSpinner;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.LayoutHelper;

@SuppressWarnings("serial")
public class CallbackOptionsPanelTab extends OastOptionsPanelTab {

    private static final long serialVersionUID = 1L;
    private static final String TEST_URL_PATH = "ZapTest";

    private final CallbackService callbackService;
    private JComboBox<String> localAddress = null;
    private JComboBox<String> remoteAddress = null;
    private ZapTextField testURL = null;
    private JCheckBox randomPort = null;
    private ZapPortNumberSpinner spinnerPort = null;
    private JCheckBox secure;

    public CallbackOptionsPanelTab(CallbackService callbackService) {
        super(callbackService.getName());

        this.callbackService = callbackService;

        int currentRowIndex = -1;

        JLabel localAddrLabel =
                new JLabel(Constant.messages.getString("oast.callback.options.label.localaddress"));
        localAddrLabel.setLabelFor(getLocalAddress());
        this.add(
                localAddrLabel,
                LayoutHelper.getGBC(0, ++currentRowIndex, 1, 0.5D, new Insets(2, 2, 2, 2)));
        this.add(
                getLocalAddress(),
                LayoutHelper.getGBC(1, currentRowIndex, 1, 0.5D, new Insets(2, 2, 2, 2)));

        JLabel remoteAddrLabel =
                new JLabel(
                        Constant.messages.getString("oast.callback.options.label.remoteaddress"));
        remoteAddrLabel.setLabelFor(getRemoteAddress());
        this.add(
                remoteAddrLabel,
                LayoutHelper.getGBC(0, ++currentRowIndex, 1, 0.5D, new Insets(2, 2, 2, 2)));
        this.add(
                getRemoteAddress(),
                LayoutHelper.getGBC(1, currentRowIndex, 1, 0.5D, new Insets(2, 2, 2, 2)));

        JLabel secureLabel =
                new JLabel(Constant.messages.getString("oast.callback.options.label.secure"));
        secureLabel.setLabelFor(getSecure());
        this.add(
                secureLabel,
                LayoutHelper.getGBC(0, ++currentRowIndex, 1, 0.5D, new Insets(2, 2, 2, 2)));
        this.add(
                getSecure(),
                LayoutHelper.getGBC(1, currentRowIndex, 1, 0.5D, new Insets(2, 2, 2, 2)));

        JLabel rndPortLabel =
                new JLabel(Constant.messages.getString("oast.callback.options.label.rndport"));
        rndPortLabel.setLabelFor(getSpinnerPort());
        this.add(
                rndPortLabel,
                LayoutHelper.getGBC(0, ++currentRowIndex, 1, 0.5D, new Insets(2, 2, 2, 2)));
        this.add(
                this.getRandomPort(),
                LayoutHelper.getGBC(1, currentRowIndex, 1, 0.5D, new Insets(2, 2, 2, 2)));

        JLabel portLabel =
                new JLabel(Constant.messages.getString("oast.callback.options.label.port"));
        portLabel.setLabelFor(getSpinnerPort());
        this.add(
                portLabel,
                LayoutHelper.getGBC(0, ++currentRowIndex, 1, 0.5D, new Insets(2, 2, 2, 2)));
        this.add(
                getSpinnerPort(),
                LayoutHelper.getGBC(1, currentRowIndex, 1, 0.5D, new Insets(2, 2, 2, 2)));

        JLabel testUrlLabel =
                new JLabel(Constant.messages.getString("oast.callback.options.label.testurl"));
        testUrlLabel.setLabelFor(getTestURL());
        this.add(
                testUrlLabel,
                LayoutHelper.getGBC(0, ++currentRowIndex, 1, 0.5D, new Insets(2, 2, 2, 2)));
        this.add(
                getTestURL(),
                LayoutHelper.getGBC(1, currentRowIndex, 1, 0.5D, new Insets(2, 2, 2, 2)));

        this.add(
                new JLabel(),
                LayoutHelper.getGBC(0, ++currentRowIndex, GridBagConstraints.REMAINDER, 0, 1.0));
    }

    private JComboBox<String> getLocalAddress() {
        if (localAddress == null) {
            localAddress = new JComboBox<>();
        }
        return localAddress;
    }

    private JComboBox<String> getRemoteAddress() {
        if (remoteAddress == null) {
            remoteAddress = new JComboBox<>();
            remoteAddress.setEditable(true);
            remoteAddress.addActionListener(e -> SwingUtilities.invokeLater(this::updateTestUri));
        }
        return remoteAddress;
    }

    private ZapTextField getTestURL() {
        if (testURL == null) {
            testURL = new ZapTextField();
            testURL.setEditable(false);
        }
        return testURL;
    }

    private JCheckBox getRandomPort() {
        if (randomPort == null) {
            randomPort = new JCheckBox();
            randomPort.addActionListener(
                    e -> getSpinnerPort().setEnabled(!randomPort.isSelected()));
        }
        return randomPort;
    }

    private JCheckBox getSecure() {
        if (secure == null) {
            secure = new JCheckBox();
            secure.addItemListener(e -> SwingUtilities.invokeLater(this::updateTestUri));
        }
        return secure;
    }

    private ZapPortNumberSpinner getSpinnerPort() {
        if (spinnerPort == null) {
            spinnerPort = new ZapPortNumberSpinner(0);
            spinnerPort.addChangeListener(e -> SwingUtilities.invokeLater(this::updateTestUri));
        }
        return spinnerPort;
    }

    private void updateTestUri() {
        Object selectedAddress = getRemoteAddress().getSelectedItem();
        String address = selectedAddress != null ? selectedAddress.toString() : "";
        String testUrl =
                callbackService.getAddress(
                                address, getSpinnerPort().getValue(), getSecure().isSelected())
                        + TEST_URL_PATH;
        getTestURL().setText(testUrl);
    }

    @Override
    public void initParam(OptionsParam options) {
        CallbackParam proxyParam = options.getParamSet(CallbackParam.class);

        List<String> allAddrs = NetworkUtils.getAvailableAddresses(false);
        localAddress.removeAllItems();
        localAddress.addItem("0.0.0.0");
        for (String addr : allAddrs) {
            localAddress.addItem(addr);
        }
        localAddress.setSelectedItem(proxyParam.getLocalAddress());

        remoteAddress.removeAllItems();
        for (String addr : allAddrs) {
            remoteAddress.addItem(addr);
        }
        remoteAddress.setSelectedItem(proxyParam.getRemoteAddress());

        secure.setSelected(proxyParam.isSecure());

        if (proxyParam.getPort() == 0) {
            getRandomPort().setSelected(true);
            getSpinnerPort().setEnabled(false);
            getSpinnerPort().setValue(callbackService.getPort()); // As 0 isn't a valid port
        } else {
            getSpinnerPort().setEnabled(true);
            getSpinnerPort().setValue(proxyParam.getPort());
        }

        getTestURL().setText(callbackService.getCallbackAddress() + TEST_URL_PATH);
    }

    @Override
    public void saveParam(OptionsParam options) {
        CallbackParam proxyParam = options.getParamSet(CallbackParam.class);

        proxyParam.setLocalAddress((String) localAddress.getSelectedItem());
        proxyParam.setRemoteAddress((String) remoteAddress.getSelectedItem());
        proxyParam.setSecure(secure.isSelected());
        if (getRandomPort().isSelected()) {
            proxyParam.setPort(0);
        } else {
            proxyParam.setPort(spinnerPort.getValue());
        }
    }
}
