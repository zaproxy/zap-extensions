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
package org.zaproxy.addon.oast.services.boast;

import java.awt.GridBagConstraints;
import java.awt.Insets;
import java.util.concurrent.TimeUnit;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.border.TitledBorder;
import javax.swing.table.AbstractTableModel;
import org.jdesktop.swingx.JXTable;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.oast.ui.OastOptionsPanelTab;
import org.zaproxy.zap.utils.ThreadUtils;
import org.zaproxy.zap.utils.ZapNumberSpinner;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.LayoutHelper;

@SuppressWarnings("serial")
public class BoastOptionsPanelTab extends OastOptionsPanelTab {

    private static final long serialVersionUID = 1L;

    private final BoastService boastService;
    private ZapTextField boastUri;
    private ZapNumberSpinner pollingFrequencySpinner;
    private JXTable boastServersTable;
    private BoastServersTableModel boastServersTableModel;
    private JButton boastRegisterButton;

    public BoastOptionsPanelTab(BoastService boastService) {
        super(boastService.getName());

        this.boastService = boastService;

        int rowIndex = -1;

        JLabel boastUriLabel =
                new JLabel(Constant.messages.getString("oast.boast.options.label.uri"));
        boastUriLabel.setLabelFor(getBoastUri());
        this.add(boastUriLabel, LayoutHelper.getGBC(0, ++rowIndex, 1, 0.4, new Insets(2, 2, 2, 2)));
        this.add(getBoastUri(), LayoutHelper.getGBC(1, rowIndex, 1, 0.6, new Insets(2, 2, 2, 2)));

        JLabel pollingFrequencyLabel =
                new JLabel(
                        Constant.messages.getString("oast.boast.options.label.pollingFrequency"));
        pollingFrequencyLabel.setLabelFor(getPollingFrequencySpinner());
        this.add(
                pollingFrequencyLabel,
                LayoutHelper.getGBC(0, ++rowIndex, 1, 0.4, new Insets(2, 2, 2, 2)));
        this.add(
                getPollingFrequencySpinner(),
                LayoutHelper.getGBC(1, rowIndex, 1, 0.6, new Insets(2, 2, 2, 2)));

        this.add(
                getBoastRegisterButton(),
                LayoutHelper.getGBC(1, ++rowIndex, 1, 0, new Insets(2, 2, 2, 2)));

        JScrollPane boastServersScrollPane = new JScrollPane(getBoastServersTable());
        boastServersScrollPane.setBorder(
                new TitledBorder(
                        Constant.messages.getString("oast.boast.options.label.activeServers")));
        this.add(
                boastServersScrollPane,
                LayoutHelper.getGBC(0, ++rowIndex, GridBagConstraints.REMAINDER, 1.0, 1.0));
    }

    ZapTextField getBoastUri() {
        if (boastUri == null) {
            boastUri = new ZapTextField();
        }
        return boastUri;
    }

    ZapNumberSpinner getPollingFrequencySpinner() {
        if (pollingFrequencySpinner == null) {
            pollingFrequencySpinner =
                    new ZapNumberSpinner(
                            BoastParam.MINIMUM_POLLING_FREQUENCY,
                            60,
                            (int) TimeUnit.HOURS.toSeconds(6));
        }
        return pollingFrequencySpinner;
    }

    private JXTable getBoastServersTable() {
        if (boastServersTable == null) {
            boastServersTable = new JXTable(getBoastServersTableModel());
            boastServersTable.setCellSelectionEnabled(true);
        }
        return boastServersTable;
    }

    private BoastServersTableModel getBoastServersTableModel() {
        if (boastServersTableModel == null) {
            boastServersTableModel = new BoastServersTableModel();
        }
        return boastServersTableModel;
    }

    private JButton getBoastRegisterButton() {
        if (boastRegisterButton == null) {
            boastRegisterButton =
                    new JButton(Constant.messages.getString("oast.boast.options.button.register"));
            boastRegisterButton.addActionListener(
                    e -> ThreadUtils.invokeAndWaitHandled(this::registerButtonAction));
        }
        return boastRegisterButton;
    }

    private void registerButtonAction() {
        try {
            saveParam(Model.getSingleton().getOptionsParam());
            boastService.register();
            getBoastServersTableModel().fireTableDataChanged();
        } catch (Exception exception) {
            View.getSingleton().showWarningDialog(this, exception.getLocalizedMessage());
        }
    }

    @Override
    public void initParam(OptionsParam options) {
        final BoastParam param = options.getParamSet(BoastParam.class);
        getBoastUri().setText(param.getBoastUri());
        getPollingFrequencySpinner().setValue(param.getPollingFrequency());
        boastServersTableModel = null;
        getBoastServersTable().setModel(getBoastServersTableModel());
    }

    @Override
    public void saveParam(OptionsParam options) {
        final BoastParam param = options.getParamSet(BoastParam.class);
        param.setBoastUri(getBoastUri().getText());
        param.setPollingFrequency(getPollingFrequencySpinner().getValue());
    }

    private class BoastServersTableModel extends AbstractTableModel {

        private static final long serialVersionUID = 1L;

        @Override
        public int getRowCount() {
            return boastService.getRegisteredServers().size();
        }

        @Override
        public int getColumnCount() {
            return 2;
        }

        @Override
        public String getColumnName(int columnIndex) {
            switch (columnIndex) {
                case 0:
                    return Constant.messages.getString("oast.boast.options.activeServers.payload");
                case 1:
                    return Constant.messages.getString("oast.boast.options.activeServers.canary");
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
                    return boastService.getRegisteredServers().get(rowIndex).getPayload();
                case 1:
                    return boastService.getRegisteredServers().get(rowIndex).getCanary();
                default:
                    return "";
            }
        }
    }
}
