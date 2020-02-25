/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.zap.extension.zest;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import javax.swing.BorderFactory;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ScrollPaneConstants;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.zap.view.LayoutHelper;

public class OptionsZestPanel extends AbstractParamPanel {

    private static final long serialVersionUID = 1L;
    private JTable tableIgnoreHeaders = null;
    private JCheckBox incResps = null;
    private JScrollPane jScrollPane = null;
    private OptionsZestIgnoreHeadersTableModel ignoreHeadersModel = null;

    /** */
    public OptionsZestPanel(ExtensionZest ext) {
        super();
        initialize();
    }

    /** This method initializes this */
    private void initialize() {
        this.setLayout(new GridBagLayout());
        this.setSize(409, 268);
        this.setName(Constant.messages.getString("zest.options.title"));
        this.add(this.getIncResps(), LayoutHelper.getGBC(0, 0, 1, 1.0, new Insets(0, 0, 5, 0)));
        this.add(
                new JLabel(Constant.messages.getString("zest.options.label.ignoreheaders")),
                LayoutHelper.getGBC(0, 1, 1, 1.0, new Insets(0, 0, 5, 0)));
        this.add(
                getJScrollPane(),
                LayoutHelper.getGBC(
                        0,
                        2,
                        1,
                        1.0,
                        1.0,
                        GridBagConstraints.BOTH,
                        GridBagConstraints.NORTHWEST,
                        new Insets(0, 0, 0, 0)));
    }

    @Override
    public void initParam(Object obj) {
        OptionsParam optionsParam = (OptionsParam) obj;
        ZestParam param = optionsParam.getParamSet(ZestParam.class);
        getIncResps().setSelected(param.isIncludeResponses());
        getModel().setAllHeaders(param.getAllHeaders());
        getModel().setIgnoredHeaders(param.getIgnoredHeaders());
    }

    @Override
    public void validateParam(Object obj) throws Exception {}

    @Override
    public void saveParam(Object obj) throws Exception {
        OptionsParam optionsParam = (OptionsParam) obj;
        ZestParam param = optionsParam.getParamSet(ZestParam.class);
        param.setIncludeResponses(getIncResps().isSelected());
        param.setIgnoredHeaders(getModel().getIgnoredHeaders());
    }

    private JCheckBox getIncResps() {
        if (incResps == null) {
            incResps =
                    new JCheckBox(Constant.messages.getString("zest.options.label.incresponses"));
        }
        return incResps;
    }

    /**
     * This method initializes tableIgnoreHeaders
     *
     * @return javax.swing.JTable
     */
    private JTable getTableIgnoreHeaders() {
        if (tableIgnoreHeaders == null) {
            tableIgnoreHeaders = new JTable();
            tableIgnoreHeaders.setModel(getModel());
            tableIgnoreHeaders.setRowHeight(18);
            tableIgnoreHeaders.getColumnModel().getColumn(0).setPreferredWidth(40);
            tableIgnoreHeaders.getColumnModel().getColumn(1).setPreferredWidth(300);
        }
        return tableIgnoreHeaders;
    }
    /**
     * This method initializes jScrollPane
     *
     * @return javax.swing.JScrollPane
     */
    private JScrollPane getJScrollPane() {
        if (jScrollPane == null) {
            jScrollPane = new JScrollPane();
            jScrollPane.setViewportView(getTableIgnoreHeaders());
            jScrollPane.setHorizontalScrollBarPolicy(
                    ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
            jScrollPane.setVerticalScrollBarPolicy(
                    ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
            jScrollPane.setBorder(
                    BorderFactory.createEtchedBorder(javax.swing.border.EtchedBorder.RAISED));
        }
        return jScrollPane;
    }

    private OptionsZestIgnoreHeadersTableModel getModel() {
        if (ignoreHeadersModel == null) {
            ignoreHeadersModel = new OptionsZestIgnoreHeadersTableModel();
        }
        return ignoreHeadersModel;
    }

    @Override
    public String getHelpIndex() {
        // TODO - write the options help page
        return null;
    }
}
