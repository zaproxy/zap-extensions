/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.addon.insights.internal;

import java.awt.CardLayout;
import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.zap.utils.ZapNumberSpinner;
import org.zaproxy.zap.view.LayoutHelper;

public class OptionsPanel extends AbstractParamPanel {

    private static final long serialVersionUID = 1L;

    private ZapNumberSpinner msgLowThreshold;
    private ZapNumberSpinner msgHighThreshold;
    private ZapNumberSpinner memLowThreshold;
    private ZapNumberSpinner memHighThreshold;
    private JComboBox<Integer> slowResponse;
    private JCheckBox exitAutoOnHigh;

    public OptionsPanel() {
        super();
        setName(Constant.messages.getString("insights.optionspanel.name"));

        this.setLayout(new CardLayout());

        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(new EmptyBorder(2, 2, 2, 2));

        int rowIndex = 0;

        addParamField(
                panel,
                rowIndex++,
                new JLabel(Constant.messages.getString("insights.options.exitAutoOnHigh")),
                getExitAutoOnHigh());
        addParamField(
                panel,
                rowIndex++,
                new JLabel(Constant.messages.getString("insights.options.msgLowThreshold")),
                getMsgLowThreshold());
        addParamField(
                panel,
                rowIndex++,
                new JLabel(Constant.messages.getString("insights.options.msgHighThreshold")),
                getMsgHighThreshold());
        addParamField(
                panel,
                rowIndex++,
                new JLabel(Constant.messages.getString("insights.options.memLowThreshold")),
                getMemLowThreshold());
        addParamField(
                panel,
                rowIndex++,
                new JLabel(Constant.messages.getString("insights.options.memHighThreshold")),
                getMemHighThreshold());
        addParamField(
                panel,
                rowIndex++,
                new JLabel(Constant.messages.getString("insights.options.slowResponse")),
                getSlowResponse());

        panel.add(new JLabel(), LayoutHelper.getGBC(0, 10, 1, 0.5D, 1.0D)); // Spacer

        add(panel);
    }

    private void addParamField(JPanel panel, int index, JLabel label, Component component) {
        label.setLabelFor(component);
        panel.add(
                label,
                LayoutHelper.getGBC(
                        0, index, GridBagConstraints.RELATIVE, 1.0, new Insets(2, 2, 2, 2)));
        panel.add(
                component,
                LayoutHelper.getGBC(
                        1, index, GridBagConstraints.REMAINDER, 1.0, new Insets(2, 2, 2, 2)));
    }

    private ZapNumberSpinner getMsgLowThreshold() {
        if (msgLowThreshold == null) {
            msgLowThreshold = new ZapNumberSpinner(0, InsightsParam.DEFAULT_MSG_LOW_THRESHOLD, 100);
        }
        return msgLowThreshold;
    }

    private ZapNumberSpinner getMsgHighThreshold() {
        if (msgHighThreshold == null) {
            msgHighThreshold =
                    new ZapNumberSpinner(0, InsightsParam.DEFAULT_MSG_HIGH_THRESHOLD, 100);
        }
        return msgHighThreshold;
    }

    private ZapNumberSpinner getMemLowThreshold() {
        if (memLowThreshold == null) {
            memLowThreshold = new ZapNumberSpinner(0, InsightsParam.DEFAULT_MEM_LOW_THRESHOLD, 100);
        }
        return memLowThreshold;
    }

    private ZapNumberSpinner getMemHighThreshold() {
        if (memHighThreshold == null) {
            memHighThreshold =
                    new ZapNumberSpinner(0, InsightsParam.DEFAULT_MEM_HIGH_THRESHOLD, 100);
        }
        return memHighThreshold;
    }

    private JComboBox<Integer> getSlowResponse() {
        if (slowResponse == null) {
            slowResponse = new JComboBox<>();
            for (int v = 128; v <= 8192; v <<= 1) {
                slowResponse.addItem(Integer.valueOf(v));
            }
        }
        return slowResponse;
    }

    private JCheckBox getExitAutoOnHigh() {
        if (exitAutoOnHigh == null) {
            exitAutoOnHigh = new JCheckBox();
        }
        return exitAutoOnHigh;
    }

    @Override
    public void initParam(Object obj) {
        OptionsParam options = (OptionsParam) obj;
        InsightsParam param = options.getParamSet(InsightsParam.class);

        getExitAutoOnHigh().setSelected(param.isExitAutoOnHigh());
        getMsgLowThreshold().setValue(param.getMessagesLowThreshold());
        getMsgHighThreshold().setValue(param.getMessagesHighThreshold());
        getMemLowThreshold().setValue(param.getMemoryLowThreshold());
        getMemHighThreshold().setValue(param.getMemoryHighThreshold());
        getSlowResponse().setSelectedItem(Integer.valueOf(param.getSlowResponse()));
    }

    @Override
    public void validateParam(Object obj) throws Exception {
        // Currently nothing to validate
    }

    @Override
    public void saveParam(Object obj) throws Exception {
        OptionsParam options = (OptionsParam) obj;
        InsightsParam param = options.getParamSet(InsightsParam.class);

        param.setExitAutoOnHigh(getExitAutoOnHigh().isSelected());
        param.setMessagesLowThreshold(getMsgLowThreshold().getValue());
        param.setMessagesHighThreshold(getMsgHighThreshold().getValue());
        param.setMemoryLowThreshold(getMemLowThreshold().getValue());
        param.setMemoryHighThreshold(getMemHighThreshold().getValue());
        param.setSlowResponse((Integer) getSlowResponse().getSelectedItem());
    }

    @Override
    public String getHelpIndex() {
        return "addon.insights-options";
    }
}
