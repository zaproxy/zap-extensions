/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.zap.extension.requester;

import java.awt.CardLayout;
import java.awt.GridBagLayout;
import java.awt.Insets;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.zap.view.LayoutHelper;

public class RequesterOptionsPanel extends AbstractParamPanel {

    private static final long serialVersionUID = 1L;

    private JCheckBox checkBoxAutoFocus = null;

    public RequesterOptionsPanel() {
        super();
        setName(Constant.messages.getString("requester.optionspanel.name"));

        this.setLayout(new CardLayout());

        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(new EmptyBorder(2, 2, 2, 2));

        panel.add(
                getCheckBoxAutoFocus(), LayoutHelper.getGBC(0, 0, 2, 1.0, new Insets(2, 2, 2, 2)));

        panel.add(new JLabel(), LayoutHelper.getGBC(0, 10, 1, 0.5D, 1.0D)); // Spacer

        add(panel);
    }

    private JCheckBox getCheckBoxAutoFocus() {
        if (checkBoxAutoFocus == null) {
            checkBoxAutoFocus =
                    new JCheckBox(
                            Constant.messages.getString(
                                    "requester.optionspanel.option.autoFocus.label"));
        }
        return checkBoxAutoFocus;
    }

    @Override
    public void initParam(Object obj) {
        final OptionsParam options = (OptionsParam) obj;
        final RequesterParam param = options.getParamSet(RequesterParam.class);

        getCheckBoxAutoFocus().setSelected(param.isAutoFocus());
    }

    @Override
    public void validateParam(Object obj) throws Exception {
        // Currently nothing to validate
    }

    @Override
    public void saveParam(Object obj) throws Exception {
        final OptionsParam options = (OptionsParam) obj;
        final RequesterParam param = options.getParamSet(RequesterParam.class);

        param.setAutoFocus(getCheckBoxAutoFocus().isSelected());
    }

    @Override
    public String getHelpIndex() {
        return null;
    }
}
