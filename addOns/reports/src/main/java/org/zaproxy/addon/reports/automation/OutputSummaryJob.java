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

import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import net.sf.json.JSONObject;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.jobs.PassiveScanJobResultData;
import org.zaproxy.addon.automation.jobs.PassiveScanJobResultData.RuleData;
import org.zaproxy.addon.reports.ExtensionReports;
import org.zaproxy.addon.reports.HttpStatusReason;
import org.zaproxy.zap.extension.alert.AlertNode;

public class OutputSummaryJob extends AutomationJob {

    public static final String JOB_NAME = "outputSummary";

    private static final String PARAM_FORMAT = "format";
    private static final String PARAM_SUMMARY_FILE = "summaryFile";

    private ExtensionReportAutomation extReportAuto;
    private PrintStream out = System.out;

    private enum Format {
        NONE,
        SHORT,
        LONG
    };

    private enum Result {
        IGNORE,
        INFO,
        WARN_NEW,
        FAIL_NEW
    }

    private Format format = Format.NONE;
    private String summaryFile;

    private ExtensionReports extReport;
    private AlertNode root;

    private List<Integer> ignoreIds = new ArrayList<>();
    private List<Integer> infoIds = new ArrayList<>();
    private List<Integer> failIds = new ArrayList<>();

    /**
     * Prints a summary to std out as per the packaged scans. The output is deliberately not
     * internationalised as neither was the output of the packaged scans.
     */
    @Override
    public void runJob(
            AutomationEnvironment env, LinkedHashMap<?, ?> jobData, AutomationProgress progress) {
        if (Format.NONE.equals(format)) {
            return;
        }

        int pass = 0;
        int warnNew = 0;
        int failNew = 0;
        int ignore = 0;
        int info = 0;

        if (jobData != null) {
            // Load rule data
            Object o = jobData.get("rules");
            if (o instanceof ArrayList<?>) {
                ArrayList<?> ruleData = (ArrayList<?>) o;
                for (Object rule : ruleData) {
                    if (rule instanceof LinkedHashMap<?, ?>) {
                        LinkedHashMap<?, ?> ruleMap = (LinkedHashMap<?, ?>) rule;
                        Integer id = (Integer) ruleMap.get("id");
                        String action = (String) ruleMap.get("action");
                        if ("IGNORE".equals(action)) {
                            ignoreIds.add(id);
                        } else if ("INFO".equals(action)) {
                            infoIds.add(id);
                        } else if ("FAIL".equals(action)) {
                            failIds.add(id);
                        } else {
                            // Default to WARN
                        }
                    }
                }
            }
        }

        // Number of URLs, as per logic behind the core.urls API endpoint
        int numUrls = getExtReportAuto().countNumberOfUrls();
        if (numUrls == 0) {
            out.println(
                    "No URLs found - is the target URL accessible? Local services may not be accessible from a Docker container");
        } else {
            if (Format.LONG.equals(format)) {
                out.println("Total of " + numUrls + " URLs");
            }

            // Passing rules, for now just passive, ordered by id
            PassiveScanJobResultData pscanData =
                    (PassiveScanJobResultData) progress.getJobResultData("passiveScanData");
            if (pscanData != null) {
                Collection<RuleData> pscanRuleData = pscanData.getAllRuleData();
                Map<Integer, Integer> alertCounts = getExtReport().getAlertCountsByRule();

                RuleData[] pscanRuleArray = new RuleData[pscanRuleData.size()];
                pscanRuleData.toArray(pscanRuleArray);
                Arrays.sort(
                        pscanRuleArray,
                        new Comparator<RuleData>() {

                            @Override
                            public int compare(RuleData o1, RuleData o2) {
                                // Compare as strings, for backwards compatibility
                                return Integer.toString(o1.getId())
                                        .compareTo(Integer.toString(o2.getId()));
                            }
                        });

                for (RuleData rule : pscanRuleArray) {
                    if (!alertCounts.containsKey(rule.getId())) {
                        if (Format.LONG.equals(format)) {
                            out.println("PASS: " + rule.getName() + " [" + rule.getId() + "]");
                        }
                        pass++;
                    }
                }

                // Output the results in the expected order
                ignore = outputResults(pscanRuleArray, alertCounts, Result.IGNORE);
                info = outputResults(pscanRuleArray, alertCounts, Result.INFO);
                warnNew = outputResults(pscanRuleArray, alertCounts, Result.WARN_NEW);
                failNew = outputResults(pscanRuleArray, alertCounts, Result.FAIL_NEW);
            }

            // Obviously most of these are not supported yet :)
            out.println(
                    "FAIL-NEW: "
                            + failNew
                            + "\tFAIL-INPROG: 0\tWARN-NEW: "
                            + warnNew
                            + "\tWARN-INPROG: 0\tINFO: "
                            + info
                            + "\tIGNORE: "
                            + ignore
                            + "\tPASS: "
                            + pass);

            if (summaryFile != null) {
                JSONObject summary = new JSONObject();
                summary.put("pass", pass);
                summary.put("warn", warnNew);
                summary.put("fail", failNew);

                try {
                    Files.write(Paths.get(summaryFile), summary.toString().getBytes("utf-8"));
                } catch (IOException e) {
                    progress.error(
                            Constant.messages.getString(
                                    "reports.automation.error.badsummaryfile",
                                    this.getName(),
                                    e.getMessage()));
                }
            }
        }
    }

    private int outputResults(
            RuleData[] pscanRuleArray, Map<Integer, Integer> alertCounts, Result result) {
        int total = 0;
        String resStr;
        for (RuleData rule : pscanRuleArray) {
            if (alertCounts.containsKey(rule.getId())) {
                if (ignoreIds.contains(rule.getId())) {
                    if (!Result.IGNORE.equals(result)) {
                        continue;
                    }
                    resStr = "IGNORE";
                } else if (infoIds.contains(rule.getId())) {
                    if (!Result.INFO.equals(result)) {
                        continue;
                    }
                    resStr = "INFO";
                } else if (failIds.contains(rule.getId())) {
                    if (!Result.FAIL_NEW.equals(result)) {
                        continue;
                    }
                    resStr = "FAIL-NEW";
                } else {
                    if (!Result.WARN_NEW.equals(result)) {
                        continue;
                    }
                    resStr = "WARN-NEW";
                }
                total++;
                int count = alertCounts.get(rule.getId());
                out.println(
                        resStr
                                + ": "
                                + getAlertName(rule.getId(), rule.getName())
                                + " ["
                                + rule.getId()
                                + "] x "
                                + count
                                + " ");
                if (Format.LONG.equals(format)) {
                    for (HttpMessage msg : getExtReport().getHttpMessagesForRule(rule.getId(), 5)) {
                        int code = msg.getResponseHeader().getStatusCode();
                        out.println(
                                "\t"
                                        + msg.getRequestHeader().getURI()
                                        + " ("
                                        + code
                                        + " "
                                        + HttpStatusReason.get(code)
                                        + ")");
                    }
                }
            }
        }
        return total;
    }

    /**
     * Get the name to use for the given alert. This is done by finding the first raised alert with
     * the given ID. If multiple sites are being scanned then this will not work so well, but for
     * the packaged scans it should be fine.
     */
    private String getAlertName(int pluginId, String defaultName) {
        AlertNode node = this.getAlertNode(pluginId);
        if (node != null) {
            if (node.getChildCount() > 0) {
                return ((AlertNode) node.getFirstChild()).getUserObject().getName();
            }
        }
        return defaultName;
    }

    private AlertNode getAlertNode(int pluginId) {
        try {
            if (root == null) {
                root = this.getExtReport().getRootAlertNode();
            }
            if (root.getChildCount() > 0) {
                AlertNode child = (AlertNode) root.getFirstChild();
                while (child != null) {
                    if (child.getUserObject().getPluginId() == pluginId) {
                        return child;
                    }
                    child = (AlertNode) root.getChildAfter(child);
                }
            }
        } catch (Exception e) {
            // Ignore
        }
        return null;
    }

    /** Only to be used for the unit tests. */
    void setOutput(PrintStream ps) {
        this.out = ps;
    }

    @Override
    public boolean verifyCustomParameter(String name, String value, AutomationProgress progress) {
        switch (name) {
            case PARAM_FORMAT:
                try {
                    Format.valueOf(value.toUpperCase(Locale.ROOT));
                } catch (Exception e) {
                    progress.error(
                            Constant.messages.getString(
                                    "reports.automation.error.badformat",
                                    this.getName(),
                                    value,
                                    Format.values()));
                }
                return true;
            case PARAM_SUMMARY_FILE:
                File parent = new File(value).getParentFile();
                if (!parent.exists()) {
                    progress.error(
                            Constant.messages.getString(
                                    "reports.automation.error.noparent",
                                    this.getName(),
                                    parent.getAbsolutePath()));
                } else if (!parent.canWrite()) {
                    progress.error(
                            Constant.messages.getString(
                                    "reports.automation.error.roparent",
                                    this.getName(),
                                    parent.getAbsolutePath()));
                }
                return true;
            default:
                // Ignore
                break;
        }
        return false;
    }

    @Override
    public boolean applyCustomParameter(String name, String value) {
        switch (name) {
            case PARAM_FORMAT:
                format = Format.valueOf(value.toUpperCase(Locale.ROOT));
                return true;
            case PARAM_SUMMARY_FILE:
                summaryFile = value;
                return true;
            default:
                // Ignore
                break;
        }
        return false;
    }

    public String getFormat() {
        return format.name();
    }

    @Override
    public Map<String, String> getCustomConfigParameters() {
        Map<String, String> map = super.getCustomConfigParameters();
        map.put(PARAM_FORMAT, Format.NONE.name());
        return map;
    }

    private ExtensionReportAutomation getExtReportAuto() {
        if (extReportAuto == null) {
            extReportAuto =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionReportAutomation.class);
        }
        return extReportAuto;
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

    @Override
    public String getTemplateDataMin() {
        return ExtensionReportAutomation.getResourceAsString(this.getType() + "-min.yaml");
    }

    @Override
    public String getTemplateDataMax() {
        return ExtensionReportAutomation.getResourceAsString(this.getType() + "-max.yaml");
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
