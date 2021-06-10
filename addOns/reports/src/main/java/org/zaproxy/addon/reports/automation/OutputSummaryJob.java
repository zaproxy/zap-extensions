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
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashMap;
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

public class OutputSummaryJob extends AutomationJob {

    public static final String JOB_NAME = "outputSummary";

    private static final String PARAM_FORMAT = "format";
    private static final String PARAM_SUMMARY_FILE = "summaryFile";

    private ExtensionReportAutomation ext;
    private PrintStream out = System.out;

    private enum Format {
        NONE,
        SHORT,
        LONG
    };

    private Format format = Format.NONE;
    private String summaryFile;

    private ExtensionReports extReport;

    public OutputSummaryJob(ExtensionReportAutomation ext) {
        this.ext = ext;
    }

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
        int warn = 0;

        // Number of URLs, as per logic behind the core.urls API endpoint
        int numUrls = ext.countNumberOfUrls();
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

                // Warning rules, for now just passive, ordered by id
                for (RuleData rule : pscanRuleArray) {
                    if (alertCounts.containsKey(rule.getId())) {
                        int count = alertCounts.get(rule.getId());
                        out.println(
                                "WARN-NEW: "
                                        + rule.getName()
                                        + " ["
                                        + rule.getId()
                                        + "] x "
                                        + count);
                        if (Format.LONG.equals(format)) {
                            for (HttpMessage msg :
                                    getExtReport().getHttpMessagesForRule(rule.getId(), 5)) {
                                out.println(
                                        "\t"
                                                + msg.getRequestHeader().getURI()
                                                + " ("
                                                + msg.getResponseHeader().getStatusCode()
                                                + ")");
                            }
                        }
                        warn++;
                    }
                }
            }

            // Obviously most of these are not supported yet :)
            out.println(
                    "FAIL-NEW: 0\tFAIL-INPROG: 0\tWARN-NEW: "
                            + warn
                            + "\tWARN-INPROG: 0\tINFO: 0\tIGNORE: 0\tPASS: "
                            + pass);

            if (summaryFile != null) {
                JSONObject summary = new JSONObject();
                summary.put("pass", pass);
                summary.put("warn", warn);
                summary.put("fail", 0); // Not yet supported

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

    /** Only to be used for the unit tests. */
    void setOutput(PrintStream ps) {
        this.out = ps;
    }

    @Override
    public void verifyCustomParameter(String name, String value, AutomationProgress progress) {
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
                break;
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
                break;
            default:
                // Ignore
                break;
        }
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
