/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.zap.extension.scripts;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import javax.swing.Box;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.border.TitledBorder;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.zap.extension.scripts.ScriptConsoleOptions.DefaultScriptChangedBehaviour;
import org.zaproxy.zap.utils.ZapNumberSpinner;
import org.zaproxy.zap.view.LayoutHelper;

public class ScriptConsoleOptionsPanel extends AbstractParamPanel {

    private static final long serialVersionUID = 1L;

    private static final String NAME =
            Constant.messages.getString("scripts.console.options.panelName");

    private JComboBox<DefaultScriptChangedBehaviour> defaultScriptChangedBehaviour;
    private JPanel codeStylePanel;
    private ZapNumberSpinner tabSizeSpinner;
    private JCheckBox useTabCharacterCheckBox;

    public ScriptConsoleOptionsPanel() {
        super();
        setName(NAME);
        setLayout(new GridBagLayout());

        int row = 0;
        var defaultScriptChangedBehaviourLabel =
                new JLabel(
                        Constant.messages.getString(
                                "scripts.console.options.defaultScriptChangedBehaviourLabel"));
        add(
                defaultScriptChangedBehaviourLabel,
                LayoutHelper.getGBC(0, ++row, 1, 0.5, new Insets(2, 4, 4, 2)));
        add(
                getDefaultScriptChangedBehaviour(),
                LayoutHelper.getGBC(1, row, 1, 0.5, new Insets(2, 2, 4, 4)));
        add(getCodeStylePanel(), LayoutHelper.getGBC(0, ++row, 2, 1.0, new Insets(0, 4, 4, 4)));

        add(
                Box.createHorizontalGlue(),
                LayoutHelper.getGBC(
                        0,
                        ++row,
                        GridBagConstraints.REMAINDER,
                        1.0,
                        1.0,
                        GridBagConstraints.BOTH,
                        new Insets(0, 0, 0, 0)));
    }

    @Override
    public void initParam(Object mainOptions) {
        ScriptConsoleOptions options = getScriptConsoleOptions(mainOptions);
        getDefaultScriptChangedBehaviour()
                .setSelectedItem(options.getDefaultScriptChangedBehaviour());
        getTabSizeSpinner().setValue(options.getTabSize());
        getUseTabCharacterCheckBox().setSelected(options.isUseTabCharacter());
    }

    @Override
    public void saveParam(Object mainOptions) throws Exception {
        ScriptConsoleOptions options = getScriptConsoleOptions(mainOptions);
        options.setDefaultScriptChangedBehaviour(
                (DefaultScriptChangedBehaviour)
                        getDefaultScriptChangedBehaviour().getSelectedItem());
        options.setTabSize(getTabSizeSpinner().getValue());
        options.setUseTabCharacter(getUseTabCharacterCheckBox().isSelected());
    }

    private static ScriptConsoleOptions getScriptConsoleOptions(Object mainOptions) {
        return ((OptionsParam) mainOptions).getParamSet(ScriptConsoleOptions.class);
    }

    @Override
    public String getHelpIndex() {
        return "addon.scripts.options";
    }

    private JComboBox<DefaultScriptChangedBehaviour> getDefaultScriptChangedBehaviour() {
        if (defaultScriptChangedBehaviour == null) {
            defaultScriptChangedBehaviour =
                    new JComboBox<>(
                            new DefaultScriptChangedBehaviour[] {
                                DefaultScriptChangedBehaviour.ASK_EACH_TIME,
                                DefaultScriptChangedBehaviour.KEEP,
                                DefaultScriptChangedBehaviour.REPLACE
                            });
        }
        return defaultScriptChangedBehaviour;
    }

    private JPanel getCodeStylePanel() {
        if (codeStylePanel == null) {
            codeStylePanel = new JPanel(new GridBagLayout());
            codeStylePanel.setBorder(
                    new TitledBorder(
                            Constant.messages.getString("scripts.options.codeStyle.title")));
            int row = 0;
            var tabSizeLabel =
                    new JLabel(Constant.messages.getString("scripts.options.codeStyle.tabSize"));
            codeStylePanel.add(
                    tabSizeLabel, LayoutHelper.getGBC(0, ++row, 1, 0.5, new Insets(2, 4, 2, 2)));
            codeStylePanel.add(
                    getTabSizeSpinner(),
                    LayoutHelper.getGBC(1, row, 1, 0.5, new Insets(2, 2, 2, 4)));
            codeStylePanel.add(
                    getUseTabCharacterCheckBox(),
                    LayoutHelper.getGBC(0, ++row, 2, 1.0, new Insets(2, 4, 4, 4)));
        }
        return codeStylePanel;
    }

    private ZapNumberSpinner getTabSizeSpinner() {
        if (tabSizeSpinner == null) {
            tabSizeSpinner = new ZapNumberSpinner(1, 4, 16);
        }
        return tabSizeSpinner;
    }

    private JCheckBox getUseTabCharacterCheckBox() {
        if (useTabCharacterCheckBox == null) {
            useTabCharacterCheckBox = new JCheckBox();
            useTabCharacterCheckBox.setText(
                    Constant.messages.getString("scripts.options.codeStyle.useTabCharacter"));
        }
        return useTabCharacterCheckBox;
    }
}
