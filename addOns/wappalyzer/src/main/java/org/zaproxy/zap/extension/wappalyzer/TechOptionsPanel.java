/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.zap.extension.wappalyzer;

import java.awt.BorderLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingConstants;
import javax.swing.border.EmptyBorder;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.zap.extension.wappalyzer.ExtensionWappalyzer.Mode;

@SuppressWarnings("serial")
public class TechOptionsPanel extends AbstractParamPanel {

    private static final long serialVersionUID = -4195576861254405033L;

    private static final String NAME = Constant.messages.getString("wappalyzer.optionspanel.name");
    private static final String MODE_LABEL =
            Constant.messages.getString("wappalyzer.optionspanel.mode");

    private JComboBox<Mode> modeComboBox;
    private JCheckBox raiseAlertsCheckBox;

    public TechOptionsPanel() {
        super();
        setName(NAME);

        setLayout(new BorderLayout(0, 0));

        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(new EmptyBorder(2, 2, 2, 2));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.insets = new java.awt.Insets(2, 2, 2, 2);
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weighty = 0.0D;
        gbc.weightx = 1.0D;
        JLabel modeLabel = new JLabel(MODE_LABEL);
        modeLabel.setLabelFor(getModeComboBox());
        panel.add(modeLabel, gbc);
        gbc.gridx = 1;
        panel.add(getModeComboBox(), gbc);
        gbc.gridx = 0;
        gbc.gridy = 1;
        panel.add(getRaiseAlertsCheckBox(), gbc);

        add(panel, BorderLayout.NORTH);
    }

    private JComboBox<Mode> getModeComboBox() {
        if (modeComboBox == null) {
            modeComboBox = new JComboBox<>(new DefaultComboBoxModel<>(Mode.values()));
        }
        return modeComboBox;
    }

    private JCheckBox getRaiseAlertsCheckBox() {
        if (raiseAlertsCheckBox == null) {
            raiseAlertsCheckBox =
                    new JCheckBox(
                            Constant.messages.getString("wappalyzer.optionspanel.raisealerts"));
            raiseAlertsCheckBox.setHorizontalTextPosition(SwingConstants.LEADING);
        }
        return raiseAlertsCheckBox;
    }

    @Override
    public void initParam(Object obj) {
        OptionsParam options = (OptionsParam) obj;
        TechDetectParam param = options.getParamSet(TechDetectParam.class);

        modeComboBox.setSelectedItem(param.getMode());
        raiseAlertsCheckBox.setSelected(param.isRaiseAlerts());
    }

    @Override
    public void saveParam(Object obj) throws Exception {
        OptionsParam options = (OptionsParam) obj;
        TechDetectParam param = options.getParamSet(TechDetectParam.class);

        param.setMode((Mode) modeComboBox.getSelectedItem());
        param.setRaiseAlerts(raiseAlertsCheckBox.isSelected());
    }

    @Override
    public String getHelpIndex() {
        return "addon.wappalyzer.options";
    }
}
