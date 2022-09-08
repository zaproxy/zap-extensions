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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import javax.swing.DefaultListModel;
import javax.swing.JComboBox;
import javax.swing.JList;
import javax.swing.JScrollPane;
import javax.swing.ListSelectionModel;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.automation.AutomationEventPublisher;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationPlan;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.addon.automation.jobs.ActiveScanJob;
import org.zaproxy.addon.automation.jobs.PassiveScanConfigJob;
import org.zaproxy.addon.automation.jobs.PassiveScanWaitJob;
import org.zaproxy.addon.automation.jobs.SpiderJob;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class NewPlanDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String TITLE = "automation.dialog.newplan.title";
    private static final String COMTEXTS_PARAM = "automation.dialog.newplan.contexts";
    private static final String PROFILE_PARAM = "automation.dialog.newplan.profile";
    private static final String JOBS_PARAM = "automation.dialog.newplan.jobs";

    private static final String CUSTOM_PROFILE_NAME = "automation.dialog.newplan.profile.custom";
    private static final String BASELINE_PROFILE_NAME =
            "automation.dialog.newplan.profile.baseline";
    private static final String IMPORT_PROFILE_NAME = "automation.dialog.newplan.profile.import";
    private static final String OPENAPI_PROFILE_NAME = "automation.dialog.newplan.profile.openapi";
    private static final String GRAPHQL_PROFILE_NAME = "automation.dialog.newplan.profile.graphql";
    private static final String SOAP_PROFILE_NAME = "automation.dialog.newplan.profile.soap";
    private static final String FULL_SCAN_PROFILE_NAME = "automation.dialog.newplan.profile.full";
    private static final String REPORT_JOB_NAME = "report";

    private static final String[] BASELINE_PROFILE = {
        PassiveScanConfigJob.JOB_NAME,
        SpiderJob.JOB_NAME,
        "spiderAjax",
        PassiveScanWaitJob.JOB_NAME,
        REPORT_JOB_NAME
    };
    private static final String[] IMPORT_PROFILE = {
        PassiveScanConfigJob.JOB_NAME,
        "import",
        SpiderJob.JOB_NAME,
        "spiderAjax",
        PassiveScanWaitJob.JOB_NAME,
        ActiveScanJob.JOB_NAME,
        REPORT_JOB_NAME
    };
    private static final String[] OPENAPI_PROFILE = {
        PassiveScanConfigJob.JOB_NAME,
        "openapi",
        PassiveScanWaitJob.JOB_NAME,
        ActiveScanJob.JOB_NAME,
        REPORT_JOB_NAME
    };
    private static final String[] GRAPHQL_PROFILE = {
        PassiveScanConfigJob.JOB_NAME,
        "graphql",
        PassiveScanWaitJob.JOB_NAME,
        ActiveScanJob.JOB_NAME,
        REPORT_JOB_NAME
    };
    private static final String[] SOAP_PROFILE = {
        PassiveScanConfigJob.JOB_NAME,
        "soap",
        PassiveScanWaitJob.JOB_NAME,
        ActiveScanJob.JOB_NAME,
        REPORT_JOB_NAME
    };
    private static final String[] FULL_SCAN_PROFILE = {
        PassiveScanConfigJob.JOB_NAME,
        SpiderJob.JOB_NAME,
        "spiderAjax",
        PassiveScanWaitJob.JOB_NAME,
        ActiveScanJob.JOB_NAME,
        REPORT_JOB_NAME
    };

    private JList<String> contextList;
    private JList<String> jobList;
    private DefaultListModel<String> jobListModel;

    private ExtensionAutomation ext;

    private static final Logger LOG = LogManager.getLogger(NewPlanDialog.class);

    public NewPlanDialog() {
        super(View.getSingleton().getMainFrame(), TITLE, DisplayUtils.getScaledDimension(300, 450));

        ext = Control.getSingleton().getExtensionLoader().getExtension(ExtensionAutomation.class);

        DefaultListModel<String> contextListModel = new DefaultListModel<>();
        Model.getSingleton().getSession().getContexts().stream()
                .forEach(c -> contextListModel.addElement(c.getName()));
        contextList = new JList<>(contextListModel);
        contextList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        contextList.setVisibleRowCount(4);
        if (contextListModel.getSize() > 0) {
            contextList.setSelectedIndex(0);
        }
        this.addCustomComponent(COMTEXTS_PARAM, new JScrollPane(contextList));

        List<AutomationJob> jobs =
                ext.getAutomationJobs().values().stream()
                        .filter(j -> !j.isDataJob())
                        .filter(j -> j.getClass().getAnnotation(Deprecated.class) == null)
                        .collect(Collectors.toList());

        Collections.sort(jobs);

        List<String> jobNames =
                jobs.stream().map(AutomationJob::getName).collect(Collectors.toList());
        List<String> profiles = new ArrayList<>();

        profiles.add(Constant.messages.getString(CUSTOM_PROFILE_NAME));
        profiles.add(Constant.messages.getString(BASELINE_PROFILE_NAME));
        // Only add the following profiles if the key jobs are present
        if (jobNames.contains("import")) {
            profiles.add(Constant.messages.getString(IMPORT_PROFILE_NAME));
        }
        if (jobNames.contains("graphql")) {
            profiles.add(Constant.messages.getString(GRAPHQL_PROFILE_NAME));
        }
        if (jobNames.contains("openapi")) {
            profiles.add(Constant.messages.getString(OPENAPI_PROFILE_NAME));
        }
        if (jobNames.contains("soap")) {
            profiles.add(Constant.messages.getString(SOAP_PROFILE_NAME));
        }
        profiles.add(Constant.messages.getString(FULL_SCAN_PROFILE_NAME));

        this.addComboField(PROFILE_PARAM, profiles, CUSTOM_PROFILE_NAME);

        @SuppressWarnings("unchecked")
        JComboBox<String> field = (JComboBox<String>) this.getField(PROFILE_PARAM);
        field.addActionListener(
                e -> {
                    String selected = field.getSelectedItem().toString();
                    if (selected.equals(Constant.messages.getString(CUSTOM_PROFILE_NAME))) {
                        jobList.clearSelection();
                    } else if (selected.equals(
                            Constant.messages.getString(BASELINE_PROFILE_NAME))) {
                        setJobs(BASELINE_PROFILE);
                    } else if (selected.equals(Constant.messages.getString(IMPORT_PROFILE_NAME))) {
                        setJobs(IMPORT_PROFILE);
                    } else if (selected.equals(Constant.messages.getString(OPENAPI_PROFILE_NAME))) {
                        setJobs(OPENAPI_PROFILE);
                    } else if (selected.equals(Constant.messages.getString(GRAPHQL_PROFILE_NAME))) {
                        setJobs(GRAPHQL_PROFILE);
                    } else if (selected.equals(Constant.messages.getString(SOAP_PROFILE_NAME))) {
                        setJobs(SOAP_PROFILE);
                    } else if (selected.equals(
                            Constant.messages.getString(FULL_SCAN_PROFILE_NAME))) {
                        setJobs(FULL_SCAN_PROFILE);
                    }
                });

        jobListModel = new DefaultListModel<>();
        jobs.stream().forEach(j -> jobListModel.addElement(j.getName()));
        jobList = new JList<>(jobListModel);
        jobList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        jobList.setVisibleRowCount(12);
        this.addCustomComponent(JOBS_PARAM, new JScrollPane(jobList));
    }

    private void setJobs(String[] jobs) {
        jobList.clearSelection();
        jobList.setSelectedIndices(
                Arrays.stream(jobs).map(j -> jobListModel.indexOf(j)).mapToInt(x -> x).toArray());
    }

    @Override
    public void save() {
        try {
            AutomationPlan plan = new AutomationPlan();

            for (String contextName : contextList.getSelectedValuesList()) {
                plan.getEnv().addContext(Model.getSingleton().getSession().getContext(contextName));
            }

            for (String jobName : jobList.getSelectedValuesList()) {
                AutomationJob job = ext.getAutomationJob(jobName).newJob();
                plan.addJob(job);
                job.addDefaultTests(plan.getProgress());
            }
            ext.registerPlan(plan);
            ext.displayPlan(plan);
            plan.setChanged();
            AutomationEventPublisher.publishEvent(
                    AutomationEventPublisher.PLAN_CREATED, plan, null);
        } catch (Exception e) {
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
        if (jobList.getSelectedValuesList().isEmpty()) {
            return Constant.messages.getString("automation.dialog.newplan.error.nojobs");
        }
        return null;
    }
}
