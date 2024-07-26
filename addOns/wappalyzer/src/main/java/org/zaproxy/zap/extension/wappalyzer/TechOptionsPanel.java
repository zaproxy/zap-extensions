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
import javax.swing.BorderFactory;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.zap.extension.wappalyzer.ExtensionWappalyzer.Mode;
import org.zaproxy.zap.utils.FontUtils;

@SuppressWarnings("serial")
public class TechOptionsPanel extends AbstractParamPanel {

    private static final long serialVersionUID = -4195576861254405033L;

    private static final String NAME = Constant.messages.getString("wappalyzer.optionspanel.name");
    private static final String NAME_MODE =
            Constant.messages.getString("wappalyzer.optionspanel.mode");

    private JComboBox<Mode> modeComboBox;
    private JPanel modePanel;

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
        panel.add(getModePanel(), gbc);

        add(panel, BorderLayout.NORTH);
    }

    private JPanel getModePanel() {
        if (modePanel == null) {
            modePanel = new JPanel();
            modePanel.setLayout(new GridBagLayout());

            GridBagConstraints gbc = new GridBagConstraints();

            modePanel.setBorder(
                    BorderFactory.createTitledBorder(
                            null,
                            NAME_MODE,
                            TitledBorder.DEFAULT_JUSTIFICATION,
                            TitledBorder.DEFAULT_POSITION,
                            FontUtils.getFont(FontUtils.Size.standard)));

            gbc.gridx = 0;
            gbc.gridy = 0;
            gbc.insets = new java.awt.Insets(2, 2, 2, 2);
            gbc.anchor = GridBagConstraints.WEST;
            gbc.fill = GridBagConstraints.HORIZONTAL;
            gbc.weightx = 0.5D;
            modePanel.add(new JLabel(NAME_MODE), gbc);

            gbc.gridx = 1;
            gbc.gridy = 0;
            gbc.ipadx = 50;
            modePanel.add(getModeComboBox(), gbc);
        }
        return modePanel;
    }

    private JComboBox<Mode> getModeComboBox() {
        if (modeComboBox == null) {
            modeComboBox = new JComboBox<>(new DefaultComboBoxModel<>(Mode.values()));
        }
        return modeComboBox;
    }

    @Override
    public void initParam(Object obj) {
        OptionsParam options = (OptionsParam) obj;
        WappalyzerParam param = options.getParamSet(WappalyzerParam.class);

        modeComboBox.setSelectedItem(param.getMode());
    }

    @Override
    public void saveParam(Object obj) throws Exception {
        OptionsParam options = (OptionsParam) obj;
        WappalyzerParam param = options.getParamSet(WappalyzerParam.class);

        param.setMode((Mode) modeComboBox.getSelectedItem());
    }
}
