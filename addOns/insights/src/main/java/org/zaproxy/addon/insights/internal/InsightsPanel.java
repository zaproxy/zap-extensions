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
import javax.swing.SwingConstants;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableCellRenderer;
import org.jdesktop.swingx.JXTable;
import org.jdesktop.swingx.decorator.BorderHighlighter;
import org.jdesktop.swingx.table.TableColumnExt;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
import org.zaproxy.addon.insights.ExtensionInsights;
import org.zaproxy.addon.insights.InsightListener;
import org.zaproxy.zap.utils.ThreadUtils;
import org.zaproxy.zap.view.ZapTable;

@SuppressWarnings("serial")
public class InsightsPanel extends AbstractPanel implements InsightListener {

    private static final long serialVersionUID = 1L;

    private InsightsTableModel model = new InsightsTableModel();
    private JXTable table;
    private boolean packed;
    private boolean haveSwitched;

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
        ThreadUtils.invokeLater(() -> model.setInsights(insights));
    }

    private JXTable getInsightsTable(InsightsTableModel model) {
        JXTable table = new ZapTable(model);

        TableColumnExt col0Ext = table.getColumnExt(0);
        col0Ext.addHighlighter(new InsightLevelTableCellIHighlighter(0));
        col0Ext.addHighlighter(new BorderHighlighter(new EmptyBorder(0, 10, 0, 0)));

        TableCellRenderer rightAlignedRenderer =
                new DefaultTableCellRenderer() {
                    {
                        setHorizontalAlignment(SwingConstants.RIGHT);
                    }
                };

        table.getColumnExt(2).setCellRenderer(rightAlignedRenderer);

        return table;
    }

    public InsightsTableModel getModel() {
        return model;
    }

    @Override
    public void recordInsight(Insight ins) {
        ThreadUtils.invokeLater(
                () -> {
                    int rowCount = model.getRowCount();
                    if (rowCount == 1 || rowCount == 10 || rowCount == 20) {
                        // Horrible way to make sure the table is sensibly sized
                        table.packAll();
                    }

                    if (Insight.Level.HIGH.equals(ins.getLevel()) && !haveSwitched) {
                        setTabFocus();
                        // Always select the first one, it will have the highest level
                        table.setRowSelectionInterval(0, 0);
                        haveSwitched = true;
                    }
                });
    }
}
