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
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.addon.automation.JobResultData;
import org.zaproxy.addon.reports.ExtensionReports;
import org.zaproxy.addon.reports.ExtensionReports.ReportDataHandler;
import org.zaproxy.addon.reports.ReportData;
import org.zaproxy.zap.model.SessionStructure;
import org.zaproxy.zap.model.StructuralNode;

public class ExtensionReportAutomation extends ExtensionAdaptor {

    public static final String NAME = "ExtensionReportAutomation";

    private static final List<Class<? extends Extension>> DEPENDENCIES;

    private static final String RESOURCES_DIR = "/org/zaproxy/addon/reports/resources/";

    private ReportJob reportJob;
    private OutputSummaryJob outputSummaryJob;

    private ReportDataHandler reportDataHandler;

    static {
        List<Class<? extends Extension>> dependencies = new ArrayList<>(2);
        dependencies.add(ExtensionAutomation.class);
        DEPENDENCIES = Collections.unmodifiableList(dependencies);
    }

    public ExtensionReportAutomation() {
        super(NAME);
    }

    @Override
    public boolean supportsDb(String type) {
        return true;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        ExtensionAutomation extAuto =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionAutomation.class);
        reportJob = new ReportJob();
        extAuto.registerAutomationJob(reportJob);
        outputSummaryJob = new OutputSummaryJob();
        extAuto.registerAutomationJob(outputSummaryJob);
        reportDataHandler = new ReportDataHandlerImpl(extAuto);
        Control.getSingleton()
                .getExtensionLoader()
                .getExtension(ExtensionReports.class)
                .setReportDataHandler(reportDataHandler);
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        ExtensionAutomation extAuto =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionAutomation.class);

        extAuto.unregisterAutomationJob(reportJob);
        extAuto.unregisterAutomationJob(outputSummaryJob);
        Control.getSingleton()
                .getExtensionLoader()
                .getExtension(ExtensionReports.class)
                .setReportDataHandler(null);
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("reports.automation.desc");
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("reports.automation.name");
    }

    public int countNumberOfUrls() {
        Set<String> urls = new HashSet<>();
        collectUrls(SessionStructure.getRootNode(Model.getSingleton()), urls);
        return urls.size();
    }

    private void collectUrls(StructuralNode node, Set<String> urls) {
        Iterator<StructuralNode> iter = node.getChildIterator();
        while (iter.hasNext()) {
            StructuralNode childNode = iter.next();
            urls.add(childNode.getURI().toString());
            collectUrls(childNode, urls);
        }
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

    private static class ReportDataHandlerImpl implements ReportDataHandler {

        private final ExtensionAutomation extAuto;

        ReportDataHandlerImpl(ExtensionAutomation extAuto) {
            this.extAuto = extAuto;
        }

        @Override
        public void handle(ReportData reportData) {
            for (JobResultData jobData : extAuto.getJobResultData()) {
                reportData.addReportObjects(jobData.getKey(), jobData);
            }
        }
    }
}
