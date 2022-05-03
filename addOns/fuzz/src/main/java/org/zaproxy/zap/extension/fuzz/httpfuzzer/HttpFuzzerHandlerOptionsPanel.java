/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.fuzz.httpfuzzer;

import javax.swing.GroupLayout;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.fuzz.FuzzerOptions;
import org.zaproxy.zap.extension.fuzz.impl.FuzzerHandlerOptionsPanel;

public class HttpFuzzerHandlerOptionsPanel implements FuzzerHandlerOptionsPanel<HttpFuzzerOptions> {

    private final JPanel optionsPanel;

    private final JCheckBox followRedirectsCheckBox;
    private final JCheckBox showRedirectMessagesCheckBox;

    public HttpFuzzerHandlerOptionsPanel() {
        optionsPanel = new JPanel();

        followRedirectsCheckBox = new JCheckBox();
        JLabel followRedirectsLabel =
                new JLabel(
                        Constant.messages.getString(
                                "fuzz.httpfuzzer.options.label.followredirects"));
        followRedirectsLabel.setLabelFor(followRedirectsCheckBox);

        showRedirectMessagesCheckBox = new JCheckBox();
        JLabel showRedirectMessagesLabel =
                new JLabel(
                        Constant.messages.getString("fuzz.httpfuzzer.options.label.showredirects"));
        showRedirectMessagesLabel.setLabelFor(showRedirectMessagesCheckBox);

        GroupLayout layout = new GroupLayout(optionsPanel);
        optionsPanel.setLayout(layout);
        layout.setAutoCreateGaps(true);

        layout.setHorizontalGroup(
                layout.createSequentialGroup()
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                        .addComponent(followRedirectsLabel))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                        .addComponent(followRedirectsCheckBox)));

        layout.setVerticalGroup(
                layout.createSequentialGroup()
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(followRedirectsLabel)
                                        .addComponent(followRedirectsCheckBox)));
    }

    @Override
    public JPanel getPanel() {
        return optionsPanel;
    }

    @Override
    public boolean validate(FuzzerOptions baseOptions) {
        return true;
    }

    @Override
    public HttpFuzzerOptions getOptions(FuzzerOptions baseOptions) {
        return new HttpFuzzerOptions(baseOptions, followRedirectsCheckBox.isSelected(), false, 100);
    }

    @Override
    public void reset() {
        followRedirectsCheckBox.setSelected(false);
    }
}
