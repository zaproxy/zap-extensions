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
package org.zaproxy.zap.extension.llmheader;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import javax.swing.ButtonGroup;
import javax.swing.JComboBox;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JRadioButton;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.zap.utils.ZapTextField;

public class LLMHeaderOptionsPanel extends AbstractParamPanel {

    private static final long serialVersionUID = 1L;

    private JCheckBox enabledCheckBox;
    private JCheckBox anonymizeCheckBox;
    private JRadioButton manualModeButton;
    private JRadioButton autoSampleModeButton;
    private JRadioButton autoAllModeButton;
    private ZapTextField samplingRateField;
    private ZapTextField rateLimitField;
    private ZapTextField bridgeUrlField;
    private ZapTextField geminiKeyField;
    private JComboBox<String> geminiModelComboBox;
    private JCheckBox autoAlertCheckBox;

    public LLMHeaderOptionsPanel() {
        super();
        setName(Constant.messages.getString("llmheader.options.panel.name"));
        setLayout(new GridBagLayout());

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(2, 2, 2, 2);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;

        enabledCheckBox = new JCheckBox(Constant.messages.getString("llmheader.options.enable"));
        add(enabledCheckBox, gbc);

        gbc.gridy++;
        anonymizeCheckBox = new JCheckBox(Constant.messages.getString("llmheader.options.anonymize"));
        add(anonymizeCheckBox, gbc);

        gbc.gridy++;
        manualModeButton = new JRadioButton(Constant.messages.getString("llmheader.options.mode.manual"));
        autoSampleModeButton = new JRadioButton(Constant.messages.getString("llmheader.options.mode.auto.sample"));
        autoAllModeButton = new JRadioButton(Constant.messages.getString("llmheader.options.mode.auto.all"));

        ButtonGroup modeGroup = new ButtonGroup();
        modeGroup.add(manualModeButton);
        modeGroup.add(autoSampleModeButton);
        modeGroup.add(autoAllModeButton);

        add(manualModeButton, gbc);
        gbc.gridy++;
        add(autoSampleModeButton, gbc);
        gbc.gridy++;
        add(autoAllModeButton, gbc);

        gbc.gridy++;
        add(new JLabel(Constant.messages.getString("llmheader.options.sampling")), gbc);
        samplingRateField = new ZapTextField();
        add(samplingRateField, gbc);

        gbc.gridy++;
        add(new JLabel(Constant.messages.getString("llmheader.options.ratelimit")), gbc);
        rateLimitField = new ZapTextField();
        add(rateLimitField, gbc);

        gbc.gridy++;
        add(new JLabel(Constant.messages.getString("llmheader.options.bridge.url")), gbc);
        bridgeUrlField = new ZapTextField();
        add(bridgeUrlField, gbc);

        gbc.gridy++;
        add(new JLabel(Constant.messages.getString("llmheader.options.gemini.key")), gbc);
        geminiKeyField = new ZapTextField();
        add(geminiKeyField, gbc);

        gbc.gridy++;
        add(new JLabel(Constant.messages.getString("llmheader.options.gemini.model")), gbc);
        geminiModelComboBox = new JComboBox<>(new String[] {
            "gemini-1.5-flash",
            "gemini-1.5-pro",
            "gemini-2.0-flash-exp",
            "gemini-2.5-flash"
        });
        geminiModelComboBox.setEditable(true);
        add(geminiModelComboBox, gbc);

        gbc.gridy++;
        autoAlertCheckBox = new JCheckBox(Constant.messages.getString("llmheader.options.alert"));
        add(autoAlertCheckBox, gbc);
        
        // Add filler to push everything up
        gbc.gridy++;
        gbc.weighty = 1.0;
        add(new JLabel(), gbc);
    }

    @Override
    public void initParam(Object obj) {
        OptionsParam options = (OptionsParam) obj;
        LLMHeaderOptions param = options.getParamSet(LLMHeaderOptions.class);

        enabledCheckBox.setSelected(param.isEnabled());
        anonymizeCheckBox.setSelected(param.isAnonymize());

        switch (param.getMode()) {
            case LLMHeaderOptions.MODE_AUTO_SAMPLE:
                autoSampleModeButton.setSelected(true);
                break;
            case LLMHeaderOptions.MODE_AUTO_ALL:
                autoAllModeButton.setSelected(true);
                break;
            default:
                manualModeButton.setSelected(true);
        }

        samplingRateField.setText(String.valueOf(param.getSamplingRate()));
        rateLimitField.setText(String.valueOf(param.getRateLimit()));
        bridgeUrlField.setText(param.getBridgeUrl());
        geminiKeyField.setText(param.getGeminiKey());
        geminiModelComboBox.setSelectedItem(param.getGeminiModel());
        autoAlertCheckBox.setSelected(param.isAutoAlert());
    }

    @Override
    public void saveParam(Object obj) throws Exception {
        OptionsParam options = (OptionsParam) obj;
        LLMHeaderOptions param = options.getParamSet(LLMHeaderOptions.class);

        param.setEnabled(enabledCheckBox.isSelected());
        param.setAnonymize(anonymizeCheckBox.isSelected());

        if (autoSampleModeButton.isSelected()) {
            param.setMode(LLMHeaderOptions.MODE_AUTO_SAMPLE);
        } else if (autoAllModeButton.isSelected()) {
            param.setMode(LLMHeaderOptions.MODE_AUTO_ALL);
        } else {
            param.setMode(LLMHeaderOptions.MODE_MANUAL);
        }

        try {
            param.setSamplingRate(Integer.parseInt(samplingRateField.getText()));
        } catch (NumberFormatException e) {
            // Ignore
        }

        try {
            param.setRateLimit(Integer.parseInt(rateLimitField.getText()));
        } catch (NumberFormatException e) {
            // Ignore
        }

        param.setBridgeUrl(bridgeUrlField.getText());
        param.setGeminiKey(geminiKeyField.getText());
        Object selectedItem = geminiModelComboBox.getSelectedItem();
        param.setGeminiModel(selectedItem != null ? selectedItem.toString() : "gemini-1.5-flash");
        param.setAutoAlert(autoAlertCheckBox.isSelected());
    }

    @Override
    public String getHelpIndex() {
        return "llmheader";
    }
}
