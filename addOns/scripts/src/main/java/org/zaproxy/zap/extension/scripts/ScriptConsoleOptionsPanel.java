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
import javax.swing.JComboBox;
import javax.swing.JLabel;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.zap.extension.scripts.ScriptConsoleOptions.DefaultScriptChangedBehaviour;
import org.zaproxy.zap.view.LayoutHelper;

public class ScriptConsoleOptionsPanel extends AbstractParamPanel {

    private static final long serialVersionUID = 1L;

    private static final String NAME =
            Constant.messages.getString("scripts.console.options.panelName");

    private JComboBox<DefaultScriptChangedBehaviour> defaultScriptChangedBehaviour;

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
    }

    @Override
    public void saveParam(Object mainOptions) throws Exception {
        ScriptConsoleOptions options = getScriptConsoleOptions(mainOptions);
        options.setDefaultScriptChangedBehaviour(
                (DefaultScriptChangedBehaviour)
                        getDefaultScriptChangedBehaviour().getSelectedItem());
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
}
