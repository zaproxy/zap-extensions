/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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

import org.apache.commons.lang3.ArrayUtils;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.addon.automation.jobs.ExitStatusJob;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class ExitStatusJobDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String TITLE = "automation.dialog.exitstatus.title";
    private static final String NAME_PARAM = "automation.dialog.all.name";
    private static final String ERROR_LEVEL_PARAM = "automation.dialog.exitstatus.errorLevel";
    private static final String WARN_LEVEL_PARAM = "automation.dialog.exitstatus.warnLevel";
    private static final String OK_EXIT_VALUE_PARAM = "automation.dialog.exitstatus.okExitValue";
    private static final String WARN_EXIT_VALUE_PARAM =
            "automation.dialog.exitstatus.warnExitValue";
    private static final String ERROR_EXIT_VALUE_PARAM =
            "automation.dialog.exitstatus.errorExitValue";

    private ExitStatusJob job;

    private static String[] getRiskOptions() {
        return ArrayUtils.add(Alert.MSG_RISK, "");
    }

    public ExitStatusJobDialog(ExitStatusJob job) {
        super(View.getSingleton().getMainFrame(), TITLE, DisplayUtils.getScaledDimension(300, 270));
        this.job = job;

        this.addTextField(NAME_PARAM, this.job.getData().getName());
        this.addComboField(
                ERROR_LEVEL_PARAM,
                getRiskOptions(),
                this.job.getData().getParameters().getErrorLevel());
        this.addComboField(
                WARN_LEVEL_PARAM,
                getRiskOptions(),
                this.job.getData().getParameters().getWarnLevel());
        this.addNumberField(
                OK_EXIT_VALUE_PARAM,
                0,
                255,
                getInt(
                        this.job.getParameters().getOkExitValue(),
                        ExtensionAutomation.OK_EXIT_VALUE));
        this.addNumberField(
                WARN_EXIT_VALUE_PARAM,
                0,
                255,
                getInt(
                        this.job.getParameters().getWarnExitValue(),
                        ExtensionAutomation.WARN_EXIT_VALUE));
        this.addNumberField(
                ERROR_EXIT_VALUE_PARAM,
                0,
                255,
                getInt(
                        this.job.getParameters().getErrorExitValue(),
                        ExtensionAutomation.ERROR_EXIT_VALUE));

        this.addPadding();
    }

    private int getInt(Integer integer, int defaultValue) {
        if (integer == null) {
            return defaultValue;
        }
        return integer.intValue();
    }

    private Integer getInteger(int i, int defaultValue) {
        if (i == defaultValue) {
            return null;
        }
        return Integer.valueOf(i);
    }

    @Override
    public void save() {
        this.job.getData().setName(this.getStringValue(NAME_PARAM));
        this.job.getParameters().setErrorLevel(this.getStringValue(ERROR_LEVEL_PARAM));
        this.job.getParameters().setWarnLevel(this.getStringValue(WARN_LEVEL_PARAM));
        this.job
                .getParameters()
                .setOkExitValue(
                        getInteger(
                                this.getIntValue(OK_EXIT_VALUE_PARAM),
                                ExtensionAutomation.OK_EXIT_VALUE));
        this.job
                .getParameters()
                .setWarnExitValue(
                        getInteger(
                                this.getIntValue(WARN_EXIT_VALUE_PARAM),
                                ExtensionAutomation.WARN_EXIT_VALUE));
        this.job
                .getParameters()
                .setErrorExitValue(
                        getInteger(
                                this.getIntValue(ERROR_EXIT_VALUE_PARAM),
                                ExtensionAutomation.ERROR_EXIT_VALUE));
        this.job.resetAndSetChanged();
    }

    @Override
    public String validateFields() {
        Integer errorRisk = JobUtils.parseAlertRisk(this.getStringValue(ERROR_LEVEL_PARAM));
        Integer warnRisk = JobUtils.parseAlertRisk(this.getStringValue(WARN_LEVEL_PARAM));
        if (warnRisk != null && errorRisk != null && warnRisk > errorRisk) {
            return Constant.messages.getString(
                    "automation.exitstatus.error.badlevels",
                    this.getStringValue(ERROR_LEVEL_PARAM),
                    this.getStringValue(WARN_LEVEL_PARAM));
        }
        return null;
    }
}
