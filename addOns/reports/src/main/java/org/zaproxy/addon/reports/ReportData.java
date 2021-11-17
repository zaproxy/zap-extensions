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
package org.zaproxy.addon.reports;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.zap.extension.alert.AlertNode;
import org.zaproxy.zap.model.Context;

public class ReportData {

    private AlertNode alertTreeRootNode;
    private String title;
    private String description;
    private List<Context> contexts;
    private List<String> sites;
    private Map<String, Object> reportObjects = new HashMap<>();
    private boolean[] confidences = new boolean[Alert.MSG_CONFIDENCE.length];
    private boolean[] risks = new boolean[Alert.MSG_RISK.length];
    private List<String> sections = new ArrayList<>();
    private String theme;

    public ReportData() {}

    public ReportData(boolean allRisks, boolean allConfidences) {
        this.setIncludeAllRisks(allRisks);
        this.setIncludeAllConfidences(allConfidences);
    }

    public AlertNode getAlertTreeRootNode() {
        return alertTreeRootNode;
    }

    public void setAlertTreeRootNode(AlertNode alertTreeRootNode) {
        this.alertTreeRootNode = alertTreeRootNode;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public List<Context> getContexts() {
        return contexts;
    }

    public void setContexts(List<Context> contexts) {
        this.contexts = contexts;
    }

    public List<String> getSites() {
        return sites;
    }

    public void setSites(List<String> sites) {
        this.sites = sites;
    }

    public Map<String, Object> getReportObjects() {
        return reportObjects;
    }

    public void addReportObjects(String key, Object object) {
        this.reportObjects.put(key, object);
    }

    public void setIncludeConfidence(int confidence, boolean value) {
        if (confidence >= 0 && confidence < this.confidences.length) {
            this.confidences[confidence] = value;
        }
    }

    public boolean isIncludeConfidence(int confidence) {
        if (confidence >= 0 && confidence < this.confidences.length) {
            return this.confidences[confidence];
        }
        return false;
    }

    public void setIncludeAllRisks(boolean value) {
        Arrays.fill(risks, value);
    }

    public void setIncludeAllConfidences(boolean value) {
        Arrays.fill(confidences, value);
    }

    public void setIncludeRisk(int risk, boolean value) {
        if (risk >= 0 && risk < this.risks.length) {
            this.risks[risk] = value;
        }
    }

    public boolean isIncludeRisk(int risk) {
        if (risk >= 0 && risk < this.risks.length) {
            return this.risks[risk];
        }
        if (risk == -1) {
            // A false positive can be a risk and a confidence, a bit like a particle and a wave ;)
            return this.confidences[0];
        }
        return false;
    }

    public List<String> getSections() {
        return sections;
    }

    public void addSection(String section) {
        this.sections.add(section);
    }

    public void removeSection(String section) {
        this.sections.remove(section);
    }

    public boolean isIncludeSection(String section) {
        return this.sections.contains(section);
    }

    public void setSections(List<String> sections) {
        if (sections == null) {
            this.sections.clear();
        } else {
            this.sections = sections;
        }
    }

    public String getTheme() {
        return theme;
    }

    public void setTheme(String theme) {
        this.theme = theme;
    }
}
