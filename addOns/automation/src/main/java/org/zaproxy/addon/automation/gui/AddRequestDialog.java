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
import javax.swing.JTextField;
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

    private static final String TITLE = "automation.dialog.addreq.title";
    private static final String URL_PARAM = "automation.dialog.addreq.url";
    private static final String NAME_PARAM = "automation.dialog.addreq.name";
    private static final String METHOD_PARAM = "automation.dialog.addreq.method";
    private static final String DATA_PARAM = "automation.dialog.addreq.data";
    private static final String CODE_PARAM = "automation.dialog.addreq.responsecode";

    private RequestorJob.Request rule;
    private boolean addRequest = false;
    private int tableIndex;
    private RequestsTableModel model;

    public AddRequestDialog(RequestsTableModel model) {
        this(model, null, -1);
    }

    public AddRequestDialog(RequestsTableModel model, RequestorJob.Request rule, int tableIndex) {
        super(View.getSingleton().getMainFrame(), TITLE, DisplayUtils.getScaledDimension(550, 400));
        if (rule == null) {
            rule = new RequestorJob.Request();
            this.addRequest = true;
        }
        this.rule = rule;
        this.model = model;
        this.tableIndex = tableIndex;

        // Cannot select the node as it might not be present in the Sites tree
        this.addNodeSelectField(URL_PARAM, null, true, false);
        Component urlField = this.getField(URL_PARAM);
        if (urlField instanceof JTextField) {
            ((JTextField) urlField).setText(rule.getUrl());
        }

        this.addTextField(NAME_PARAM, rule.getName());
        this.addTextField(METHOD_PARAM, rule.getMethod());
        this.addMultilineField(DATA_PARAM, rule.getData());
        this.addNumberField(
                CODE_PARAM, 0, Integer.MAX_VALUE, JobUtils.unBox(rule.getResponseCode()));
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
        rule.setData(this.getStringValue(DATA_PARAM));
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
        return null;
    }
}
