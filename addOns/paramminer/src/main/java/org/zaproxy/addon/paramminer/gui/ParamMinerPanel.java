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
package org.zaproxy.addon.paramminer.gui;

import java.awt.GridBagLayout;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextPane;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
import org.zaproxy.addon.paramminer.ExtensionParamMiner;
import org.zaproxy.zap.view.LayoutHelper;

public class ParamMinerPanel extends AbstractPanel {

    private static final long serialVersionUID = 1L;
    private final JTabbedPane tabbedPane;
    private final JTextPane outputArea;
    private final JTable historyTable;
    private final ExtensionParamMiner ext;

    public ParamMinerPanel(ExtensionParamMiner ext) {
        this.ext = ext;
        this.setName(Constant.messages.getString("paramminer.panel.title"));
        this.setIcon(ExtensionParamMiner.getIcon());
        this.setLayout(new GridBagLayout());

        historyTable = new ParamMinerResultsTable(new ParamMinerHistoryTableModel());
        outputArea = new JTextPane();
        outputArea.setEditable(false);

        tabbedPane = new JTabbedPane();
        tabbedPane.addTab(
                Constant.messages.getString("paramminer.panel.tab.history"),
                new JScrollPane(historyTable));
        tabbedPane.addTab(
                Constant.messages.getString("paramminer.panel.tab.output"),
                new JScrollPane(outputArea));
        this.add(tabbedPane, LayoutHelper.getGBC(0, 0, 1, 1.0, 1.0));
    }
}
