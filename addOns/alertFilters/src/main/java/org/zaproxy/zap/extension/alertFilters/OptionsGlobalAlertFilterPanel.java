/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.zap.extension.alertFilters;

import java.awt.BorderLayout;
import java.awt.Window;
import java.util.ArrayList;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;

public class OptionsGlobalAlertFilterPanel extends AbstractParamPanel {

    private static final long serialVersionUID = 1L;

    private final AlertFilterTableModel alertFilterModel = new AlertFilterTableModel();
    private final AlertFiltersMultipleOptionsPanel alertFilterOptionsPanel;

    public OptionsGlobalAlertFilterPanel(ExtensionAlertFilters extension, Window owner) {
        super();
        this.setName(Constant.messages.getString("alertFilters.global.options.title"));
        this.setLayout(new BorderLayout());
        alertFilterOptionsPanel =
                new AlertFiltersMultipleOptionsPanel(extension, owner, alertFilterModel);
        this.add(alertFilterOptionsPanel);
    }

    @Override
    public void initParam(Object obj) {
        OptionsParam optionsParam = (OptionsParam) obj;
        GlobalAlertFilterParam param = optionsParam.getParamSet(GlobalAlertFilterParam.class);
        alertFilterModel.setAlertFilters(new ArrayList<>(param.getGlobalAlertFilters()));
        alertFilterOptionsPanel.setRemoveWithoutConfirmation(!param.isConfirmRemoveFilter());
    }

    @Override
    public void saveParam(Object obj) throws Exception {
        OptionsParam optionsParam = (OptionsParam) obj;
        GlobalAlertFilterParam param = optionsParam.getParamSet(GlobalAlertFilterParam.class);
        param.setGlobalAlertFilters(alertFilterModel.getElements());
        param.setConfirmRemoveFilter(!alertFilterOptionsPanel.isRemoveWithoutConfirmation());
    }

    @Override
    public String getHelpIndex() {
        return "addon.globalAlertFilter";
    }

    protected AlertFilter showAddDialogue(AlertFilter alertFilter) {
        return this.alertFilterOptionsPanel.showAddDialogue(alertFilter);
    }
}
