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

import java.text.ParseException;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.automation.HhMmSs;
import org.zaproxy.addon.automation.jobs.DelayJob;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class DelayJobDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String TITLE = "automation.dialog.delay.title";
    private static final String NAME_PARAM = "automation.dialog.all.name";
    private static final String TIME_PARAM = "automation.dialog.delay.time";
    private static final String FILENAME_PARAM = "automation.dialog.delay.fileName";

    private DelayJob job;

    public DelayJobDialog(DelayJob job) {
        super(View.getSingleton().getMainFrame(), TITLE, DisplayUtils.getScaledDimension(300, 200));
        this.job = job;

        this.addTextField(NAME_PARAM, this.job.getData().getName());
        this.addTextField(TIME_PARAM, this.job.getData().getParameters().getTime());
        this.addTextField(FILENAME_PARAM, this.job.getData().getParameters().getFileName());
        this.addPadding();
    }

    @Override
    public void save() {
        this.job.getData().setName(this.getStringValue(NAME_PARAM));
        this.job.getParameters().setTime(this.getStringValue(TIME_PARAM));
        this.job.getParameters().setFileName(this.getStringValue(FILENAME_PARAM));
        this.job.resetAndSetChanged();
    }

    @Override
    public String validateFields() {
        try {
            new HhMmSs(this.getStringValue(TIME_PARAM));
        } catch (ParseException | NumberFormatException e) {
            return Constant.messages.getString("automation.dialog.delay.error.time");
        }
        return null;
    }
}
