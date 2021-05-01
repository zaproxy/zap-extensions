/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.custompayloads;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import javax.swing.JLabel;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;

public class CustomPayloadsOptionsPanel extends AbstractParamPanel {

    private static final long serialVersionUID = 1L;
    private static final String OPTIONS_TITLE =
            Constant.messages.getString("custompayloads.options.title");
    CustomPayloadsMultipleOptionsTablePanel tablePanel;
    CustomPayloadMultipleOptionsTableModel tableModel;

    public CustomPayloadsOptionsPanel() {
        this.tableModel = new CustomPayloadMultipleOptionsTableModel();
        this.tablePanel = new CustomPayloadsMultipleOptionsTablePanel(tableModel);
        this.setName(OPTIONS_TITLE);
        this.setLayout(new GridBagLayout());

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.weightx = 1.0;
        gbc.anchor = GridBagConstraints.LINE_START;
        gbc.fill = GridBagConstraints.BOTH;

        this.add(new JLabel(OPTIONS_TITLE), gbc);
        gbc.weighty = 1.0;
        this.add(tablePanel, gbc);
    }

    @Override
    public void initParam(Object obj) {
        OptionsParam optionsParam = (OptionsParam) obj;
        CustomPayloadsParam param = optionsParam.getParamSet(CustomPayloadsParam.class);
        tableModel.clear();
        tableModel.addModels(param.getPayloads());
        tableModel.setDefaultPayloads(param.getDefaultPayloads());
        tableModel.setNextPayloadId(param.getNextPayloadId());
        tablePanel.setRemoveWithoutConfirmation(param.isConfirmRemoveToken());
    }

    @Override
    public void saveParam(Object obj) throws Exception {
        OptionsParam optionsParam = (OptionsParam) obj;
        CustomPayloadsParam param = optionsParam.getParamSet(CustomPayloadsParam.class);
        param.setPayloads(tableModel.getElements());
        param.setNextPayloadId(tableModel.getNextPayloadId());
        param.setConfirmRemoveToken(tablePanel.isRemoveWithoutConfirmation());
    }
}
