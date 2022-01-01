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
package org.zaproxy.addon.oast.services.interactsh;

import java.awt.GridBagConstraints;
import java.awt.Insets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import org.apache.commons.lang3.StringUtils;
import org.jdesktop.swingx.JXTable;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.oast.ui.OastOptionsPanelTab;
import org.zaproxy.zap.utils.ThreadUtils;
import org.zaproxy.zap.utils.ZapNumberSpinner;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.LayoutHelper;

public class InteractshOptionsPanelTab extends OastOptionsPanelTab {

    private static final long serialVersionUID = 1L;

    private final InteractshService interactshService;
    private final List<String> payloads = new ArrayList<>();
    private ZapTextField serverUrl;
    private ZapTextField authToken;
    private ZapNumberSpinner pollingFrequencySpinner;
    private JXTable payloadsTable;
    private PayloadsTableModel payloadsTableModel;
    private JButton newPayloadButton;
    private String originalServerUrl;
    private String originalAuthToken;

    public InteractshOptionsPanelTab(InteractshService interactshService) {
        super(interactshService.getName());

        this.interactshService = interactshService;

        int rowIndex = -1;

        JLabel serverUrlLabel =
                new JLabel(Constant.messages.getString("oast.interactsh.options.label.url"));
        serverUrlLabel.setLabelFor(getServerUrl());
        this.add(
                serverUrlLabel, LayoutHelper.getGBC(0, ++rowIndex, 1, 0.4, new Insets(2, 2, 2, 2)));
        this.add(getServerUrl(), LayoutHelper.getGBC(1, rowIndex, 1, 0.6, new Insets(2, 2, 2, 2)));

        JLabel authTokenLabel =
                new JLabel(Constant.messages.getString("oast.interactsh.options.label.authToken"));
        authTokenLabel.setLabelFor(getAuthToken());
        this.add(
                authTokenLabel, LayoutHelper.getGBC(0, ++rowIndex, 1, 0.4, new Insets(2, 2, 2, 2)));
        this.add(getAuthToken(), LayoutHelper.getGBC(1, rowIndex, 1, 0.6, new Insets(2, 2, 2, 2)));

        JLabel pollingFrequencyLabel =
                new JLabel(
                        Constant.messages.getString(
                                "oast.interactsh.options.label.pollingFrequency"));
        pollingFrequencyLabel.setLabelFor(getPollingFrequencySpinner());
        this.add(
                pollingFrequencyLabel,
                LayoutHelper.getGBC(0, ++rowIndex, 1, 0.4, new Insets(2, 2, 2, 2)));
        this.add(
                getPollingFrequencySpinner(),
                LayoutHelper.getGBC(1, rowIndex, 1, 0.6, new Insets(2, 2, 2, 2)));

        this.add(
                getNewPayloadButton(),
                LayoutHelper.getGBC(1, ++rowIndex, 1, 0, new Insets(2, 2, 2, 2)));

        JScrollPane scrollPane = new JScrollPane(getPayloadsTable());
        scrollPane.setBorder(
                new TitledBorder(
                        Constant.messages.getString(
                                "oast.interactsh.options.label.activePayloads")));
        this.add(
                scrollPane,
                LayoutHelper.getGBC(0, ++rowIndex, GridBagConstraints.REMAINDER, 1.0, 1.0));
    }

    ZapTextField getServerUrl() {
        if (serverUrl == null) {
            serverUrl = new ZapTextField();
            addChangeListenerToRefreshPayloadButtonEnabledState(serverUrl);
        }
        return serverUrl;
    }

    ZapTextField getAuthToken() {
        if (authToken == null) {
            authToken = new ZapTextField();
            addChangeListenerToRefreshPayloadButtonEnabledState(authToken);
        }
        return authToken;
    }

    ZapNumberSpinner getPollingFrequencySpinner() {
        if (pollingFrequencySpinner == null) {
            pollingFrequencySpinner =
                    new ZapNumberSpinner(
                            InteractshParam.MINIMUM_POLLING_FREQUENCY,
                            60,
                            (int) TimeUnit.HOURS.toSeconds(6));
        }
        return pollingFrequencySpinner;
    }

    private JXTable getPayloadsTable() {
        if (payloadsTable == null) {
            payloadsTable = new JXTable(getPayloadsTableModel());
            payloadsTable.setCellSelectionEnabled(true);
        }
        return payloadsTable;
    }

    private PayloadsTableModel getPayloadsTableModel() {
        if (payloadsTableModel == null) {
            payloadsTableModel = new PayloadsTableModel();
        }
        return payloadsTableModel;
    }

    private JButton getNewPayloadButton() {
        if (newPayloadButton == null) {
            newPayloadButton =
                    new JButton(
                            Constant.messages.getString(
                                    "oast.interactsh.options.button.newPayload"));
            newPayloadButton.addActionListener(
                    e -> ThreadUtils.invokeAndWaitHandled(this::newPayloadButtonAction));
        }
        return newPayloadButton;
    }

    private void newPayloadButtonAction() {
        try {
            payloads.add(interactshService.getNewPayload());
            getPayloadsTableModel().fireTableDataChanged();
        } catch (Exception exception) {
            View.getSingleton().showWarningDialog(this, exception.getLocalizedMessage());
        }
    }

    private void addChangeListenerToRefreshPayloadButtonEnabledState(JTextField textField) {
        textField
                .getDocument()
                .addDocumentListener(
                        new DocumentListener() {

                            @Override
                            public void changedUpdate(DocumentEvent e) {
                                refreshPayloadButtonEnabledState();
                            }

                            @Override
                            public void removeUpdate(DocumentEvent e) {
                                refreshPayloadButtonEnabledState();
                            }

                            @Override
                            public void insertUpdate(DocumentEvent e) {
                                refreshPayloadButtonEnabledState();
                            }
                        });
    }

    @Override
    public void initParam(OptionsParam options) {
        final InteractshParam param = options.getParamSet(InteractshParam.class);
        this.originalServerUrl = param.getServerUrl();
        this.originalAuthToken = param.getAuthToken();
        getServerUrl().setText(param.getServerUrl());
        getAuthToken().setText(param.getAuthToken());
        getPollingFrequencySpinner().setValue(param.getPollingFrequency());
        payloadsTableModel = null;
        getPayloadsTable().setModel(getPayloadsTableModel());
    }

    @Override
    public void saveParam(OptionsParam options) {
        final InteractshParam param = options.getParamSet(InteractshParam.class);
        param.setServerUrl(getServerUrl().getText());
        param.setAuthToken(getAuthToken().getText());
        param.setPollingFrequency(getPollingFrequencySpinner().getValue());
    }

    private void refreshPayloadButtonEnabledState() {
        if (newPayloadButton == null) {
            return;
        }

        newPayloadButton.setEnabled(
                Objects.equals(getServerUrl().getText(), originalServerUrl)
                        && Objects.equals(getAuthToken().getText(), originalAuthToken));
    }

    private class PayloadsTableModel extends AbstractTableModel {

        private static final long serialVersionUID = 1L;

        @Override
        public int getRowCount() {
            return payloads.size();
        }

        @Override
        public int getColumnCount() {
            return 2;
        }

        @Override
        public String getColumnName(int columnIndex) {
            switch (columnIndex) {
                case 0:
                    return Constant.messages.getString(
                            "oast.interactsh.options.activePayloads.payload");
                case 1:
                    return Constant.messages.getString(
                            "oast.interactsh.options.activePayloads.canary");
                default:
                    return "";
            }
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            return String.class;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            switch (columnIndex) {
                case 0:
                    return payloads.get(rowIndex);
                case 1:
                    String payload = payloads.get(rowIndex);
                    return StringUtils.reverse(payload.substring(0, payload.indexOf('.')));
                default:
                    return "";
            }
        }
    }
}
