/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.plugnhack;

import java.awt.CardLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import javax.swing.BorderFactory;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.border.EtchedBorder;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.zap.view.LayoutHelper;
import org.zaproxy.zap.view.SingleColumnTableModel;

@SuppressWarnings("serial")
public class SessionMonitoredClientsPanel extends AbstractParamPanel {

    public static final String PANEL_NAME = Constant.messages.getString("plugnhack.session.title");
    private static final long serialVersionUID = -8337361808959321380L;

    private JPanel panelSession = null;
    private JCheckBox allInScope = null;
    private JTable tableInclude = null;
    private JScrollPane includeScrollPane = null;
    private SingleColumnTableModel includeModel = null;
    private JTable tableExclude = null;
    private JScrollPane excludeScrollPane = null;
    private SingleColumnTableModel excludeModel = null;
    private MonitoredPagesManager mpm;

    // These are used to tell if the user made any changes
    private ArrayList<String> includeCache = new ArrayList<>();
    private ArrayList<String> excludeCache = new ArrayList<>();

    public SessionMonitoredClientsPanel(MonitoredPagesManager mpm) {
        super();
        this.mpm = mpm;
        initialize();
        this.mpm.setSessionPanel(this);
    }

    /** This method initializes this */
    private void initialize() {
        this.setLayout(new CardLayout());
        this.setName(PANEL_NAME);
        this.add(getPanelSession(), getPanelSession().getName());
    }

    /**
     * This method initializes panelSession
     *
     * @return javax.swing.JPanel
     */
    private JPanel getPanelSession() {
        if (panelSession == null) {

            panelSession = new JPanel();
            panelSession.setLayout(new GridBagLayout());
            panelSession.setName("pnhMonitoredClients");

            panelSession.add(this.getAllInScope(), LayoutHelper.getGBC(0, 0, 1, 1.0, 0.0));

            panelSession.add(
                    new JLabel(Constant.messages.getString("plugnhack.session.label.include")),
                    LayoutHelper.getGBC(0, 1, 1, 0.0D, new Insets(10, 0, 5, 0)));
            panelSession.add(
                    getIncludeScrollPane(),
                    LayoutHelper.getGBC(0, 2, 1, 1.0, 1.0, GridBagConstraints.BOTH, null));

            panelSession.add(
                    new JLabel(Constant.messages.getString("plugnhack.session.label.exclude")),
                    LayoutHelper.getGBC(0, 3, 1, 0.0D, new Insets(10, 0, 5, 0)));
            panelSession.add(
                    getExcludeScrollPane(),
                    LayoutHelper.getGBC(0, 4, 1, 1.0, 1.0, GridBagConstraints.BOTH, null));
        }
        return panelSession;
    }

    @Override
    public void initParam(Object obj) {
        this.refresh();
    }

    @Override
    public void validateParam(Object obj) {
        // Check for valid regexs
        for (String regex : getIncludeModel().getLines()) {
            if (regex.trim().length() > 0) {
                Pattern.compile(regex.trim(), Pattern.CASE_INSENSITIVE);
            }
        }
        for (String regex : getExcludeModel().getLines()) {
            if (regex.trim().length() > 0) {
                Pattern.compile(regex.trim(), Pattern.CASE_INSENSITIVE);
            }
        }
    }

    @Override
    public void saveParam(Object obj) throws Exception {
        boolean changed = false;

        if (this.getAllInScope().isSelected() != this.mpm.isMonitorAllInScope()) {
            this.mpm.setMonitorAllInScope(this.getAllInScope().isSelected());
            changed = true;
        }

        if (!this.equals(this.getIncludeModel().getLines(), this.includeCache)) {
            this.mpm.setIncludeRegexes(this.getIncludeModel().getLines());
            changed = true;
        }
        if (!this.equals(this.getExcludeModel().getLines(), this.excludeCache)) {
            this.mpm.setExcludeRegexes(this.getExcludeModel().getLines());
            changed = true;
        }
        if (changed) {
            // Refresh the tree - too hard to work out excactly what has changed
            this.mpm.setMonitorFlags();
        }
    }

    private boolean equals(List<String> list1, List<String> list2) {
        if (list1.size() != list2.size()) {
            return false;
        }
        for (String str : list1) {
            if (!list2.contains(str)) {
                return false;
            }
        }

        return true;
    }

    private JCheckBox getAllInScope() {
        if (allInScope == null) {
            allInScope =
                    new JCheckBox(Constant.messages.getString("plugnhack.session.label.inscope"));
        }

        return allInScope;
    }

    private JTable getTableInclude() {
        if (tableInclude == null) {
            tableInclude = new JTable();
            tableInclude.setModel(getIncludeModel());
            tableInclude.setRowHeight(18);
        }
        return tableInclude;
    }

    private JScrollPane getIncludeScrollPane() {
        if (includeScrollPane == null) {
            includeScrollPane = new JScrollPane();
            includeScrollPane.setViewportView(getTableInclude());
            includeScrollPane.setBorder(BorderFactory.createEtchedBorder(EtchedBorder.RAISED));
        }
        return includeScrollPane;
    }

    private SingleColumnTableModel getIncludeModel() {
        if (includeModel == null) {
            includeModel =
                    new SingleColumnTableModel(
                            Constant.messages.getString("plugnhack.session.table.header.include"));
        }
        return includeModel;
    }

    private JTable getTableExclude() {
        if (tableExclude == null) {
            tableExclude = new JTable();
            tableExclude.setModel(getExcludeModel());
            tableExclude.setRowHeight(18);
        }
        return tableExclude;
    }

    private JScrollPane getExcludeScrollPane() {
        if (excludeScrollPane == null) {
            excludeScrollPane = new JScrollPane();
            excludeScrollPane.setViewportView(getTableExclude());
            excludeScrollPane.setBorder(BorderFactory.createEtchedBorder(EtchedBorder.RAISED));
        }
        return excludeScrollPane;
    }

    private SingleColumnTableModel getExcludeModel() {
        if (excludeModel == null) {
            excludeModel =
                    new SingleColumnTableModel(
                            Constant.messages.getString("plugnhack.session.table.header.exclude"));
        }
        return excludeModel;
    }

    @Override
    public String getHelpIndex() {
        return "ui.dialogs.sessprop";
    }

    @SuppressWarnings("unchecked")
    public void refresh() {
        this.getAllInScope().setSelected(this.mpm.isMonitorAllInScope());
        this.getIncludeModel().setLines(mpm.getIncludeRegexes());
        this.getExcludeModel().setLines(mpm.getExcludeRegexes());

        this.includeCache =
                (ArrayList<String>) ((ArrayList<String>) this.includeModel.getLines()).clone();
        this.excludeCache =
                (ArrayList<String>) ((ArrayList<String>) this.excludeModel.getLines()).clone();
    }
}
