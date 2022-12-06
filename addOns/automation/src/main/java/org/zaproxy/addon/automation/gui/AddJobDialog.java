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

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationJobException;
import org.zaproxy.addon.automation.AutomationPlan;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class AddJobDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String TITLE = "automation.dialog.addjob.title";
    private static final String JOB_PARAM = "automation.dialog.all.name";

    private AutomationPlan plan;
    private ExtensionAutomation ext;

    private static final Logger LOG = LogManager.getLogger(AddJobDialog.class);

    public AddJobDialog(AutomationPlan plan) {
        super(View.getSingleton().getMainFrame(), TITLE, DisplayUtils.getScaledDimension(300, 200));
        this.plan = plan;

        ext = Control.getSingleton().getExtensionLoader().getExtension(ExtensionAutomation.class);
        List<AutomationJob> jobs =
                ext.getAutomationJobs().values().stream()
                        .filter(j -> !j.isDataJob())
                        .filter(j -> j.getClass().getAnnotation(Deprecated.class) == null)
                        .collect(Collectors.toList());

        Collections.sort(jobs);

        this.addComboField(
                JOB_PARAM,
                jobs.stream().map(AutomationJob::getName).collect(Collectors.toList()),
                "");
        this.addPadding();
    }

    @Override
    public void save() {
        String jobName = this.getStringValue(JOB_PARAM);
        AutomationJob jobTemplate = this.ext.getAutomationJob(jobName);

        try {
            AutomationJob job = jobTemplate.newJob();
            this.plan.addJob(job);
            job.showDialog();
        } catch (AutomationJobException e) {
            LOG.error(e.getMessage(), e);
            View.getSingleton()
                    .showWarningDialog(
                            thisDialog,
                            Constant.messages.getString(
                                    "automation.dialog.error.misc", e.getMessage()));
        }
    }

    @Override
    public String validateFields() {
        // Nothing to do
        return null;
    }
}
