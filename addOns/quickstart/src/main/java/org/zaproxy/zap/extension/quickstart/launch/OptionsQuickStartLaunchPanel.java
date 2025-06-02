/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.quickstart.launch;

import java.awt.GridBagLayout;
import java.awt.Insets;
import java.net.URL;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.border.EmptyBorder;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.zap.extension.quickstart.QuickStartParam;
import org.zaproxy.zap.view.LayoutHelper;

public class OptionsQuickStartLaunchPanel extends AbstractParamPanel {

    private static final long serialVersionUID = -1L;

    /** The name of the options panel. */
    private static final String NAME =
            Constant.messages.getString("quickstart.launch.optionspanel.name");

    private JComboBox<String> startPageOption;
    private JTextField startUrl;

    public OptionsQuickStartLaunchPanel() {
        super();
        setName(NAME);

        setLayout(new GridBagLayout());

        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(new EmptyBorder(2, 2, 2, 2));

        JLabel startOptionLabel =
                new JLabel(Constant.messages.getString("quickstart.launch.start.option.label"));
        startOptionLabel.setLabelFor(getStartPageOption());
        panel.add(startOptionLabel, LayoutHelper.getGBC(0, 0, 1, 1.0, new Insets(2, 2, 2, 2)));
        panel.add(getStartPageOption(), LayoutHelper.getGBC(1, 0, 1, 1.0, new Insets(2, 2, 2, 2)));

        JLabel startUrlLabel =
                new JLabel(Constant.messages.getString("quickstart.launch.start.url.label"));
        startOptionLabel.setLabelFor(getStartUrl());
        panel.add(startUrlLabel, LayoutHelper.getGBC(0, 1, 1, 1.0, new Insets(2, 2, 2, 2)));
        panel.add(getStartUrl(), LayoutHelper.getGBC(1, 1, 1, 1.0, new Insets(2, 2, 2, 2)));

        add(panel, LayoutHelper.getGBC(0, 0, 1, 1.0));
        add(new JLabel(), LayoutHelper.getGBC(0, 10, 1, 1.0, 1.0)); // Spacer
    }

    @Override
    public void initParam(Object obj) {
        final OptionsParam options = (OptionsParam) obj;
        final QuickStartParam param = options.getParamSet(QuickStartParam.class);

        if (param.isLaunchZapStartPage()) {
            getStartPageOption().setSelectedIndex(0);
        } else if (param.isLaunchBlankStartPage()) {
            getStartPageOption().setSelectedIndex(1);
        } else {
            getStartPageOption().setSelectedIndex(2);
            getStartUrl().setText(param.getLaunchStartPage());
        }
    }

    @Override
    public void validateParam(Object obj) throws Exception {
        if (getStartPageOption().getSelectedIndex() == 2) {
            try {
                // Validate the url
                new URL(getStartUrl().getText());
            } catch (Exception e) {
                getStartUrl().requestFocus();
                throw new IllegalArgumentException(
                        Constant.messages.getString("quickstart.launch.start.url.warn"));
            }
        }
    }

    @Override
    public void saveParam(Object obj) throws Exception {
        final OptionsParam options = (OptionsParam) obj;
        final QuickStartParam param = options.getParamSet(QuickStartParam.class);

        switch (getStartPageOption().getSelectedIndex()) {
            case 0:
                param.setLaunchZapStartPage();
                break;
            case 1:
                param.setLaunchBlankStartPage();
                break;
            case 2:
                param.setLaunchStartPage(new URL(getStartUrl().getText()));
                break;
            default:
                param.setLaunchZapStartPage();
                break;
        }
    }

    @Override
    public String getHelpIndex() {
        return "quickstart.launch.options";
    }

    private JComboBox<String> getStartPageOption() {
        if (startPageOption == null) {
            startPageOption = new JComboBox<>();
            /*
             * Note that the indexes are explicitly used in setUrlFieldState()
             * initParam(Object obj) validateParam(Object obj)
             */
            startPageOption.addItem(
                    Constant.messages.getString("quickstart.launch.start.pulldown.zap"));
            startPageOption.addItem(
                    Constant.messages.getString("quickstart.launch.start.pulldown.blank"));
            startPageOption.addItem(
                    Constant.messages.getString("quickstart.launch.start.pulldown.url"));
            startPageOption.addActionListener(e -> setUrlFieldState());
        }
        return startPageOption;
    }

    private void setUrlFieldState() {
        switch (startPageOption.getSelectedIndex()) {
            case 0:
                getStartUrl().setEnabled(false);
                break;
            case 1:
                getStartUrl().setEnabled(false);
                break;
            case 2:
                getStartUrl().setEnabled(true);
                break;
            default:
                getStartUrl().setEnabled(false);
                break;
        }
    }

    private JTextField getStartUrl() {
        if (startUrl == null) {
            startUrl = new JTextField();
        }
        return startUrl;
    }
}
