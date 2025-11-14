/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.addon.insights.internal;

import java.awt.CardLayout;
import java.util.List;
import javax.swing.ImageIcon;
import javax.swing.JScrollPane;
import javax.swing.border.EmptyBorder;
import org.jdesktop.swingx.JXTable;
import org.jdesktop.swingx.decorator.BorderHighlighter;
import org.jdesktop.swingx.table.TableColumnExt;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
import org.zaproxy.addon.insights.ExtensionInsights;
import org.zaproxy.zap.view.ZapTable;

@SuppressWarnings("serial")
public class InsightsPanel extends AbstractPanel {

    private static final long serialVersionUID = 1L;

    private InsightsTableModel model = new InsightsTableModel();
    private JXTable table;
    private boolean packed;

    public InsightsPanel() {
        setName(Constant.messages.getString(ExtensionInsights.PREFIX + ".panel.title"));
        setIcon(new ImageIcon(ExtensionInsights.getResource("magnifier--exclamation.png")));

        this.setLayout(new CardLayout());
        JScrollPane pane = new JScrollPane();
        pane.setName("InsightsPane");

        table = getInsightsTable(model);
        pane.setViewportView(table);

        this.add(pane);
    }

    public void setInsights(List<Insight> insights) {
        model.setInsights(insights);
        pack();
    }

    public void insightChanged(int index, boolean added) {
        model.insightChanged(index, added);
        pack();
    }

    private void pack() {
        if (!this.packed && model.getRowCount() > 0) {
            table.packAll();
            this.packed = true;
        }
    }

    private JXTable getInsightsTable(InsightsTableModel model) {
        JXTable table = new ZapTable(model);

        TableColumnExt col0Ext = table.getColumnExt(0);
        col0Ext.addHighlighter(new InsightLevelTableCellIHighlighter(0));
        col0Ext.addHighlighter(new BorderHighlighter(new EmptyBorder(0, 10, 0, 0)));

        return table;
    }
}
