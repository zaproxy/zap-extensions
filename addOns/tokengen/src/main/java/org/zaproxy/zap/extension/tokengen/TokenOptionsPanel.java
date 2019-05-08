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
package org.zaproxy.zap.extension.tokengen;

import javax.swing.GroupLayout;
import javax.swing.JLabel;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.zap.utils.ZapNumberSpinner;

/**
 * The options panel.
 *
 * <p>It allows to change the following options:
 *
 * <ul>
 *   <li>Number of threads for the token generation;
 *   <li>The request delay;
 * </ul>
 *
 * @see TokenParam
 */
public class TokenOptionsPanel extends AbstractParamPanel {

    private static final long serialVersionUID = 1L;

    /** The name of the options panel. */
    private static final String NAME = Constant.messages.getString("tokengen.optionspanel.name");

    /** The label for the threads per scan option. */
    private static final String THREADS_PER_SCAN_LABEL =
            Constant.messages.getString("tokengen.optionspanel.option.threadsperscan");

    /** The label for the request delay option. */
    private static final String REQUEST_DELAY_LABEL =
            Constant.messages.getString("tokengen.optionspanel.option.requestdelay");

    /** The number spinner for the number of threads per scan. */
    private ZapNumberSpinner threadsPerScanNumberSpinner;

    /** The number spinner for the request delay. */
    private ZapNumberSpinner requestDelayNumberSpinner;

    public TokenOptionsPanel() {
        super();

        JLabel threadsPerScanLabel = new JLabel(THREADS_PER_SCAN_LABEL);
        threadsPerScanNumberSpinner =
                new ZapNumberSpinner(1, TokenParam.DEFAULT_THREADS_PER_SCAN, 50);

        JLabel requestDelayLabel = new JLabel(REQUEST_DELAY_LABEL);
        requestDelayNumberSpinner =
                new ZapNumberSpinner(0, TokenParam.DEFAULT_REQUEST_DELAY_IN_MS, Integer.MAX_VALUE);

        setName(NAME);

        GroupLayout layout = new GroupLayout(this);
        setLayout(layout);

        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        layout.setHorizontalGroup(
                layout.createSequentialGroup()
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                        .addComponent(threadsPerScanLabel)
                                        .addComponent(requestDelayLabel))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                        .addComponent(threadsPerScanNumberSpinner)
                                        .addComponent(requestDelayNumberSpinner)));

        layout.setVerticalGroup(
                layout.createSequentialGroup()
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(threadsPerScanLabel)
                                        .addComponent(threadsPerScanNumberSpinner))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(requestDelayLabel)
                                        .addComponent(requestDelayNumberSpinner)));
    }

    @Override
    public void initParam(Object obj) {
        TokenParam options = ((OptionsParam) obj).getParamSet(TokenParam.class);

        threadsPerScanNumberSpinner.setValue(options.getThreadsPerScan());
        requestDelayNumberSpinner.setValue(options.getRequestDelayInMs());
    }

    @Override
    public void saveParam(Object obj) throws Exception {
        TokenParam options = ((OptionsParam) obj).getParamSet(TokenParam.class);

        options.setThreadsPerScan(threadsPerScanNumberSpinner.getValue());
        options.setRequestDelayInMs(requestDelayNumberSpinner.getValue());
    }

    @Override
    public String getHelpIndex() {
        return "tokengen.options";
    }
}
