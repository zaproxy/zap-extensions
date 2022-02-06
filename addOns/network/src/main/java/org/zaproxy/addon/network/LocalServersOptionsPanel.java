/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.network;

import javax.swing.GroupLayout;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.addon.network.internal.ui.PassThroughTableModel;
import org.zaproxy.addon.network.internal.ui.PassThroughTablePanel;

class LocalServersOptionsPanel extends AbstractParamPanel {

    private static final long serialVersionUID = 1L;

    private final PassThroughPanel passThroughPanel;

    public LocalServersOptionsPanel(ExtensionNetwork extensionNetwork) {
        passThroughPanel = new PassThroughPanel();

        setName(Constant.messages.getString("network.ui.options.localservers.name"));

        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.add(
                Constant.messages.getString("network.ui.options.passthrough.tab"),
                passThroughPanel.getPanel());

        GroupLayout mainLayout = new GroupLayout(this);
        setLayout(mainLayout);
        mainLayout.setAutoCreateGaps(true);
        mainLayout.setAutoCreateContainerGaps(true);

        mainLayout.setHorizontalGroup(mainLayout.createParallelGroup().addComponent(tabbedPane));
        mainLayout.setVerticalGroup(mainLayout.createSequentialGroup().addComponent(tabbedPane));
    }

    @Override
    public void initParam(Object mainOptions) {
        LocalServersOptions options = getLocalServersOptions(mainOptions);

        passThroughPanel.init(options);
    }

    private static LocalServersOptions getLocalServersOptions(Object mainOptions) {
        return ((OptionsParam) mainOptions).getParamSet(LocalServersOptions.class);
    }

    @Override
    public void saveParam(Object mainOptions) throws Exception {
        LocalServersOptions options = getLocalServersOptions(mainOptions);

        passThroughPanel.save(options);
    }

    @Override
    public String getHelpIndex() {
        return "addon.network.options.localservers";
    }

    private static class PassThroughPanel {

        private final PassThroughTableModel tableModel;
        private final PassThroughTablePanel tablePanel;
        private final JPanel panel;

        PassThroughPanel() {
            tableModel = new PassThroughTableModel();
            tablePanel = new PassThroughTablePanel(tableModel);

            panel = new JPanel();
            GroupLayout layout = new GroupLayout(panel);
            panel.setLayout(layout);
            layout.setAutoCreateGaps(true);
            layout.setAutoCreateContainerGaps(true);

            layout.setHorizontalGroup(layout.createParallelGroup().addComponent(tablePanel));

            layout.setVerticalGroup(layout.createSequentialGroup().addComponent(tablePanel));
        }

        JPanel getPanel() {
            return panel;
        }

        void init(LocalServersOptions options) {
            tableModel.setPassThroughs(options.getPassThroughs());
            tablePanel.setRemoveWithoutConfirmation(!options.isConfirmRemovePassThrough());
        }

        void save(LocalServersOptions options) {
            options.setPassThroughs(tableModel.getElements());
            options.setConfirmRemovePassThrough(!tablePanel.isRemoveWithoutConfirmation());
        }
    }
}
