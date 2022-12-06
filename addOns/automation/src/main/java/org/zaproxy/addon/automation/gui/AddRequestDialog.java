/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.automation.gui;

import java.awt.Component;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JButton;
import javax.swing.JOptionPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.addon.automation.jobs.RequestorJob;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.ZapNumberSpinner;
import org.zaproxy.zap.utils.ZapTextArea;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class AddRequestDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String[] TAB_LABELS = {
        "automation.dialog.addreq.tab.title", "automation.dialog.addreq.tab.header"
    };

    private static final String TITLE = "automation.dialog.addreq.title";
    private static final String URL_PARAM = "automation.dialog.addreq.url";
    private static final String NAME_PARAM = "automation.dialog.addreq.name";
    private static final String METHOD_PARAM = "automation.dialog.addreq.method";
    private static final String HTTP_VERSION_PARAM = "automation.dialog.addreq.httpversion";
    private static final String DATA_PARAM = "automation.dialog.addreq.data";
    private static final String CODE_PARAM = "automation.dialog.addreq.responsecode";

    private JButton addHeaderButton;
    private JButton modifyHeaderButton;
    private JButton removeHeaderButton;

    private JTable headersTable;
    private HeadersTableModel headersModel;
    private RequestorJob.Request rule;
    private boolean addRequest = false;
    private int tableIndex;
    private RequestsTableModel model;

    public AddRequestDialog(RequestsTableModel model) {
        this(model, null, 0);
    }

    public AddRequestDialog(RequestsTableModel model, RequestorJob.Request rule, int tableIndex) {
        super(
                View.getSingleton().getMainFrame(),
                TITLE,
                DisplayUtils.getScaledDimension(550, 400),
                TAB_LABELS);
        if (rule == null) {
            rule = new RequestorJob.Request();
            this.addRequest = true;
        }
        this.rule = rule;
        this.model = model;
        this.tableIndex = tableIndex;

        // Cannot select the node as it might not be present in the Sites tree
        this.addNodeSelectField(0, URL_PARAM, null, true, false);
        Component urlField = this.getField(URL_PARAM);
        if (urlField instanceof JTextField) {
            ((JTextField) urlField).setText(rule.getUrl());
        }

        this.addTextField(0, NAME_PARAM, rule.getName());
        this.addTextField(0, METHOD_PARAM, rule.getMethod());
        this.addTextField(0, HTTP_VERSION_PARAM, rule.getHttpVersion());
        this.addMultilineField(0, DATA_PARAM, rule.getData());
        this.addNumberField(
                0, CODE_PARAM, 0, Integer.MAX_VALUE, JobUtils.unBox(rule.getResponseCode()));

        List<JButton> headerButtons = new ArrayList<>();
        headerButtons.add(getAddHeaderButton());
        headerButtons.add(getRemoveHeaderButton());
        headerButtons.add(getModifyHeaderButton());
        JTable table1 = getHeadersTable();
        this.addTableField(1, table1, headerButtons);
    }

    @Override
    public void siteNodeSelected(String field, SiteNode node) {
        // Fill in the rest of the fields from the node selected
        HistoryReference hr = node.getHistoryReference();
        if (hr != null) {
            ((ZapTextField) this.getField(METHOD_PARAM)).setText(hr.getMethod());
            ((ZapNumberSpinner) this.getField(CODE_PARAM)).setValue(hr.getStatusCode());
            try {
                HttpMessage msg = hr.getHttpMessage();
                setFieldValue(HTTP_VERSION_PARAM, msg.getRequestHeader().getVersion());
                ((ZapTextArea) this.getField(DATA_PARAM)).setText(msg.getRequestBody().toString());
            } catch (Exception e) {
                // Ignore
            }
        }
    }

    @Override
    public void save() {
        rule.setUrl(this.getStringValue(URL_PARAM));
        rule.setName(this.getStringValue(NAME_PARAM));
        rule.setMethod(this.getStringValue(METHOD_PARAM));
        rule.setHttpVersion(getStringValue(HTTP_VERSION_PARAM));
        rule.setData(this.getStringValue(DATA_PARAM));
        rule.setHeadersList(this.getHeadersModel().getHeaders());
        if (this.getIntValue(CODE_PARAM) == 0) {
            rule.setResponseCode(null);
        } else {
            rule.setResponseCode(this.getIntValue(CODE_PARAM));
        }

        if (addRequest) {
            this.model.add(rule);
        } else {
            this.model.update(tableIndex, rule);
        }
    }

    @Override
    public String validateFields() {
        // TODO check url present & ok
        if (!RequestorJob.isValidHttpVersion(getStringValue(HTTP_VERSION_PARAM))) {
            return Constant.messages.getString("automation.dialog.addreq.error.httpversion");
        }
        return null;
    }

    private JButton getAddHeaderButton() {
        if (this.addHeaderButton == null) {
            this.addHeaderButton =
                    new JButton(Constant.messages.getString("automation.dialog.button.add"));
            this.addHeaderButton.addActionListener(
                    e -> {
                        AddHeaderDialog dialog = new AddHeaderDialog(this);
                        dialog.setVisible(true);
                    });
        }
        return this.addHeaderButton;
    }

    private JButton getModifyHeaderButton() {
        if (this.modifyHeaderButton == null) {
            this.modifyHeaderButton =
                    new JButton(Constant.messages.getString("automation.dialog.button.modify"));
            modifyHeaderButton.setEnabled(false);
            this.modifyHeaderButton.addActionListener(
                    e -> {
                        int row = getHeadersTable().getSelectedRow();
                        AddHeaderDialog dialog =
                                new AddHeaderDialog(this, this.headersModel.getHeaders().get(row));
                        dialog.setVisible(true);
                    });
        }
        return this.modifyHeaderButton;
    }

    private JButton getRemoveHeaderButton() {
        if (this.removeHeaderButton == null) {
            this.removeHeaderButton =
                    new JButton(Constant.messages.getString("automation.dialog.button.remove"));
            this.removeHeaderButton.setEnabled(false);
            final AddRequestDialog parent = this;
            this.removeHeaderButton.addActionListener(
                    e -> {
                        if (JOptionPane.OK_OPTION
                                == View.getSingleton()
                                        .showConfirmDialog(
                                                parent,
                                                Constant.messages.getString(
                                                        "automation.dialog.header.remove.confirm"))) {
                            getHeadersModel().remove(getHeadersTable().getSelectedRow());
                        }
                    });
        }
        return this.removeHeaderButton;
    }

    private JTable getHeadersTable() {
        if (headersTable == null) {
            headersTable = new JTable();
            headersTable.setModel(getHeadersModel());
            headersTable
                    .getColumnModel()
                    .getColumn(0)
                    .setPreferredWidth(DisplayUtils.getScaledSize(80));
            headersTable
                    .getColumnModel()
                    .getColumn(1)
                    .setPreferredWidth(DisplayUtils.getScaledSize(240));
            headersTable
                    .getSelectionModel()
                    .addListSelectionListener(
                            e -> {
                                boolean singleRowSelected =
                                        getHeadersTable().getSelectedRowCount() == 1;
                                modifyHeaderButton.setEnabled(singleRowSelected);
                                removeHeaderButton.setEnabled(singleRowSelected);
                            });
            headersTable.addMouseListener(
                    new MouseAdapter() {
                        @Override
                        public void mouseClicked(MouseEvent me) {
                            if (me.getClickCount() == 2) {
                                int row = headersTable.getSelectedRow();
                                if (row == -1) {
                                    return;
                                }
                                AddHeaderDialog dialog =
                                        new AddHeaderDialog(
                                                AddRequestDialog.this,
                                                headersModel.getHeaders().get(row));
                                dialog.setVisible(true);
                            }
                        }
                    });
        }
        return headersTable;
    }

    private HeadersTableModel getHeadersModel() {
        if (headersModel == null) {
            headersModel = new HeadersTableModel();
            headersModel.setHeaders(rule.getHeaders());
        }
        return headersModel;
    }

    public void addHeader(RequestorJob.Request.Header header) {
        getHeadersModel().add(header);
    }
}
