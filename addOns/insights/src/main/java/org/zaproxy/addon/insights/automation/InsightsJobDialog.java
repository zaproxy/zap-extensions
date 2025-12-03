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
package org.zaproxy.addon.insights.automation;

import java.util.Vector;
import javax.swing.ComboBoxModel;
import javax.swing.DefaultComboBoxModel;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class InsightsJobDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String TITLE = "insights.dialog.insights.title";
    private static final String NAME_PARAM = "automation.dialog.all.name";
    private static final String EXIT_AUTO_ON_HIGH_PARAM = "insights.options.exitAutoOnHigh";
    private static final String MSG_LOW_PARAM = "insights.options.msgLowThreshold";
    private static final String MSG_HIGH_PARAM = "insights.options.msgHighThreshold";
    private static final String MEM_LOW_PARAM = "insights.options.memLowThreshold";
    private static final String MEM_HIGH_PARAM = "insights.options.memHighThreshold";
    private static final String SLOW_RESP_PARAM = "insights.options.slowResponse";

    private InsightsJob job;

    public InsightsJobDialog(InsightsJob job) {
        super(View.getSingleton().getMainFrame(), TITLE, DisplayUtils.getScaledDimension(400, 320));
        this.job = job;

        this.addTextField(NAME_PARAM, this.job.getData().getName());
        this.addCheckBoxField(EXIT_AUTO_ON_HIGH_PARAM, this.job.getParameters().isExitAutoOnHigh());
        this.addNumberField(
                MSG_LOW_PARAM, 0, 100, this.job.getParameters().getMessagesLowThreshold());
        this.addNumberField(
                MSG_HIGH_PARAM, 0, 100, this.job.getParameters().getMessagesHighThreshold());
        this.addNumberField(
                MEM_LOW_PARAM, 0, 100, this.job.getParameters().getMemoryLowThreshold());
        this.addNumberField(
                MEM_HIGH_PARAM, 0, 100, this.job.getParameters().getMemoryHighThreshold());

        Vector<Integer> v = new Vector<>();
        for (int i = 128; i <= 8192; i <<= 1) {
            v.add(Integer.valueOf(i));
        }
        @SuppressWarnings({"rawtypes", "unchecked"})
        ComboBoxModel<Integer> model = new DefaultComboBoxModel(v);
        model.setSelectedItem(this.job.getParameters().getSlowResponse());
        this.addComboField(SLOW_RESP_PARAM, model);

        this.addPadding();
    }

    @Override
    public void save() {
        this.job.getData().setName(this.getStringValue(NAME_PARAM));
        this.job.getParameters().setExitAutoOnHigh(this.getBoolValue(EXIT_AUTO_ON_HIGH_PARAM));
        this.job.getParameters().setMessagesLowThreshold(this.getIntValue(MSG_LOW_PARAM));
        this.job.getParameters().setMessagesHighThreshold(this.getIntValue(MSG_HIGH_PARAM));
        this.job.getParameters().setMemoryLowThreshold(this.getIntValue(MEM_LOW_PARAM));
        this.job.getParameters().setMemoryHighThreshold(this.getIntValue(MEM_HIGH_PARAM));
        this.job.getParameters().setSlowResponse(this.getIntValue(SLOW_RESP_PARAM));
        this.job.resetAndSetChanged();
    }

    @Override
    public String validateFields() {
        return null;
    }
}
