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
package org.zaproxy.addon.reports.automation;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.addon.reports.ExtensionReports;
import org.zaproxy.addon.reports.ReportData;
import org.zaproxy.addon.reports.ReportParam;
import org.zaproxy.addon.reports.Template;

public class ReportJob extends AutomationJob {

    private static final String JOB_NAME = "report";

    private static final String RESOURCES_DIR = "/org/zaproxy/addon/reports/resources/";

    private static final String PARAM_TEMPLATE = "template";
    private static final String PARAM_REPORT_DIR = "reportDir";
    private static final String PARAM_REPORT_FILE = "reportFile";
    private static final String PARAM_REPORT_TITLE = "reportTitle";
    private static final String PARAM_REPORT_DESC = "reportDescription";
    private static final String PARAM_DISPLAY_REPORT = "displayReport";

    private String templateName = "traditional-html";
    private String reportDir = null;
    private String reportFile = ReportParam.DEFAULT_NAME_PATTERN;
    private String reportTitle = null;
    private String reportDesc = null;
    private boolean displayReport = false;

    private ExtensionReports extReport;

    @Override
    public void runJob(
            AutomationEnvironment env, LinkedHashMap<?, ?> jobData, AutomationProgress progress) {
        ReportData reportData = new ReportData();
        Template template = getExtReport().getTemplateByConfigName(templateName);

        // Work out the file name based on the pattern
        String fileName =
                ExtensionReports.getNameFromPattern(
                                reportFile, env.getUrlStringForContext(env.getDefaultContext()))
                        + "."
                        + template.getExtension();

        File file;
        if (reportDir != null && reportDir.length() > 0) {
            file = new File(reportDir, fileName);
        } else {
            file = new File(fileName);
        }
        reportData.setTitle(this.reportTitle);
        reportData.setDescription(this.reportDesc);
        reportData.setAlertTreeRootNode(getExtReport().getFilteredAlertTree(reportData));
        reportData.setContexts(env.getContexts());

        try {
            file =
                    getExtReport()
                            .generateReport(
                                    reportData, template, file.getAbsolutePath(), displayReport);
            progress.info(
                    Constant.messages.getString(
                            "reports.automation.info.reportgen",
                            this.getName(),
                            file.getAbsolutePath()));
        } catch (Exception e) {
            progress.error(
                    Constant.messages.getString(
                            "reports.automation.error.generate", this.getName(), e.getMessage()));
        }
    }

    private ExtensionReports getExtReport() {
        if (extReport == null) {
            extReport =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionReports.class);
        }
        return extReport;
    }

    public boolean applyCustomParameter(String name, String value) {
        switch (name) {
            case PARAM_TEMPLATE:
                templateName = value;
                return true;
            case PARAM_REPORT_DIR:
                reportDir = value;
                return true;
            case PARAM_REPORT_FILE:
                reportFile = value;
                return true;
            case PARAM_REPORT_TITLE:
                reportTitle = value;
                return true;
            case PARAM_REPORT_DESC:
                reportDesc = value;
                return true;
            case PARAM_DISPLAY_REPORT:
                displayReport = Boolean.parseBoolean(value);
                return true;
            default:
                // Ignore
                break;
        }
        return false;
    }

    @Override
    public Map<String, String> getCustomConfigParameters() {
        Map<String, String> map = super.getCustomConfigParameters();
        map.put(PARAM_TEMPLATE, templateName);
        map.put(PARAM_REPORT_DIR, null);
        map.put(PARAM_REPORT_FILE, this.reportFile);
        map.put(PARAM_REPORT_TITLE, this.reportTitle);
        map.put(PARAM_REPORT_DESC, this.reportDesc);
        map.put(PARAM_DISPLAY_REPORT, Boolean.toString(displayReport));
        return map;
    }

    public static String getResourceAsString(String name) {
        try (InputStream in = ExtensionAutomation.class.getResourceAsStream(RESOURCES_DIR + name)) {
            return new BufferedReader(new InputStreamReader(in))
                            .lines()
                            .collect(Collectors.joining("\n"))
                    + "\n";
        } catch (Exception e) {
            CommandLine.error(
                    Constant.messages.getString("automation.error.nofile", RESOURCES_DIR + name));
        }
        return "";
    }

    public String getTemplateDataMin() {
        return getResourceAsString(this.getType() + "-min.yaml");
    }

    public String getTemplateDataMax() {
        return getResourceAsString(this.getType() + "-max.yaml");
    }

    @Override
    public String getType() {
        return JOB_NAME;
    }

    @Override
    public Order getOrder() {
        return Order.REPORT;
    }

    @Override
    public Object getParamMethodObject() {
        return null;
    }

    @Override
    public String getParamMethodName() {
        return null;
    }
}
