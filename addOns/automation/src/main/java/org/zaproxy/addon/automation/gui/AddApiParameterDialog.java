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

import org.parosproxy.paros.view.View;
import org.zaproxy.addon.automation.jobs.ApiJob;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

public class AddApiParameterDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String TITLE = "automation.dialog.api.apiparameter.title";
    private static final String NAME_PARAM = "automation.dialog.api.apiparameter.title.name";
    private static final String VALUE_PARAM = "automation.dialog.api.apiparameter.title.value";

    private ApiJob.ApiParameter apiParameter;
    private int tableIndex;
    private ApiParameterTableModel model;

    public AddApiParameterDialog(ApiParameterTableModel model) {
        this(model, null, -1);
    }

    public AddApiParameterDialog(
            ApiParameterTableModel model, ApiJob.ApiParameter apiParameter, int tableIndex) {
        super(View.getSingleton().getMainFrame(), TITLE, DisplayUtils.getScaledDimension(400, 200));
        this.apiParameter = apiParameter;
        this.model = model;
        this.tableIndex = tableIndex;

        String name = "";
        if (apiParameter != null) {
            name = apiParameter.getName();
        }
        this.addTextField(NAME_PARAM, name);

        String value = "";
        if (apiParameter != null) {
            value = apiParameter.getValue();
        }
        this.addTextField(VALUE_PARAM, value);

        this.addPadding();
    }

    @Override
    public void save() {
        String name = getStringValue(NAME_PARAM);
        String value = getStringValue(VALUE_PARAM);
        if (apiParameter == null) {
            apiParameter = new ApiJob.ApiParameter();
            apiParameter.setName(name);
            apiParameter.setValue(value);
            this.model.add(apiParameter);
        } else {
            apiParameter.setName(name);
            apiParameter.setValue(value);
            this.model.update(tableIndex, apiParameter);
        }
    }

    @Override
    public String validateFields() {
        // Nothing to do
        return null;
    }
}
