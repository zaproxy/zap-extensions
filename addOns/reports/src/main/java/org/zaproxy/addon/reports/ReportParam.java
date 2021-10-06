/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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

import java.io.File;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.common.AbstractParam;

public class ReportParam extends AbstractParam {

    private static final Logger LOGGER = LogManager.getLogger(ReportParam.class);

    private static final String PARAM_BASE_KEY = "reports";
    private static final String PARAM_TITLE = PARAM_BASE_KEY + ".title";
    private static final String PARAM_DESCRIPTION = PARAM_BASE_KEY + ".description";
    private static final String PARAM_TEMPLATE = PARAM_BASE_KEY + ".template";
    private static final String PARAM_DISPLAY = PARAM_BASE_KEY + ".display";
    private static final String PARAM_TEMPLATE_DIRECTORY = PARAM_BASE_KEY + ".templateDir";
    private static final String PARAM_REPORT_DIRECTORY = PARAM_BASE_KEY + ".reportDir";
    private static final String PARAM_REPORT_NAME_PATTERN = PARAM_BASE_KEY + ".reportPattern";
    private static final String PARAM_INC_CONFIDENCE_0 = PARAM_BASE_KEY + ".confidence.fp";
    private static final String PARAM_INC_CONFIDENCE_1 = PARAM_BASE_KEY + ".confidence.low";
    private static final String PARAM_INC_CONFIDENCE_2 = PARAM_BASE_KEY + ".confidence.med";
    private static final String PARAM_INC_CONFIDENCE_3 = PARAM_BASE_KEY + ".confidence.high";
    private static final String PARAM_INC_CONFIDENCE_4 = PARAM_BASE_KEY + ".confidence.conf";
    private static final String PARAM_INC_RISK_0 = PARAM_BASE_KEY + ".risk.info";
    private static final String PARAM_INC_RISK_1 = PARAM_BASE_KEY + ".risk.low";
    private static final String PARAM_INC_RISK_2 = PARAM_BASE_KEY + ".risk.med";
    private static final String PARAM_INC_RISK_3 = PARAM_BASE_KEY + ".risk.high";
    private static final String PARAM_REPORT_SECTIONS_PREFIX = PARAM_BASE_KEY + ".report.sections.";
    private static final String PARAM_REPORT_THEME_PREFIX = PARAM_BASE_KEY + ".report.theme.";

    public static final String DEFAULT_TEMPLATE = "risk-confidence-html";
    public static final String DEFAULT_NAME_PATTERN = "{{yyyy-MM-dd}}-ZAP-Report-[[site]]";
    public static final String DEFAULT_TEMPLATES_DIR = Constant.getZapHome() + "/reports/";

    private String title;
    private String description;
    private String template;
    private String templateDirectory;
    private String reportDirectory;
    private String reportNamePattern;
    private boolean displayReport;
    private boolean incConfidence0;
    private boolean incConfidence1;
    private boolean incConfidence2;
    private boolean incConfidence3;
    private boolean incConfidence4;
    private boolean incRisk0;
    private boolean incRisk1;
    private boolean incRisk2;
    private boolean incRisk3;

    @Override
    protected void parse() {
        title = getString(PARAM_TITLE, Constant.messages.getString("reports.report.title"));
        description = getString(PARAM_DESCRIPTION, "");
        template = getString(PARAM_TEMPLATE, DEFAULT_TEMPLATE);

        templateDirectory = getString(PARAM_TEMPLATE_DIRECTORY, DEFAULT_TEMPLATES_DIR);
        File dir = new File(templateDirectory);
        if (!dir.exists() || !dir.isDirectory()) {
            LOGGER.error(
                    "Reports template directory cannot be read or is not a directory: {}",
                    dir.getAbsolutePath());
            templateDirectory = Constant.getZapHome() + "/reports/";
        }

        reportDirectory = getString(PARAM_REPORT_DIRECTORY, System.getProperty("user.home"));
        reportNamePattern = getString(PARAM_REPORT_NAME_PATTERN, DEFAULT_NAME_PATTERN);
        displayReport = getBoolean(PARAM_DISPLAY, true);

        incConfidence0 = getBoolean(PARAM_INC_CONFIDENCE_0, false);
        incConfidence1 = getBoolean(PARAM_INC_CONFIDENCE_1, true);
        incConfidence2 = getBoolean(PARAM_INC_CONFIDENCE_2, true);
        incConfidence3 = getBoolean(PARAM_INC_CONFIDENCE_3, true);
        incConfidence4 = getBoolean(PARAM_INC_CONFIDENCE_4, true);

        incRisk0 = getBoolean(PARAM_INC_RISK_0, true);
        incRisk1 = getBoolean(PARAM_INC_RISK_1, true);
        incRisk2 = getBoolean(PARAM_INC_RISK_2, true);
        incRisk3 = getBoolean(PARAM_INC_RISK_3, true);
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
        getConfig().setProperty(PARAM_TITLE, title);
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
        getConfig().setProperty(PARAM_DESCRIPTION, description);
    }

    public String getTemplate() {
        return template;
    }

    public void setTemplate(String template) {
        this.template = template;
        getConfig().setProperty(PARAM_TEMPLATE, template);
    }

    public String getTemplateDirectory() {
        return templateDirectory;
    }

    public void setTemplateDirectory(String templateDirectory) {
        this.templateDirectory = templateDirectory;
        getConfig().setProperty(PARAM_TEMPLATE_DIRECTORY, templateDirectory);
    }

    public String getReportDirectory() {
        return reportDirectory;
    }

    public void setReportDirectory(String reportDirectory) {
        this.reportDirectory = reportDirectory;
        getConfig().setProperty(PARAM_REPORT_DIRECTORY, reportDirectory);
    }

    public String getReportNamePattern() {
        return reportNamePattern;
    }

    public void setReportNamePattern(String reportNamePattern) {
        this.reportNamePattern = reportNamePattern;
        getConfig().setProperty(PARAM_REPORT_NAME_PATTERN, reportNamePattern);
    }

    public boolean isDisplayReport() {
        return displayReport;
    }

    public void setDisplayReport(boolean displayReport) {
        this.displayReport = displayReport;
        getConfig().setProperty(PARAM_DISPLAY, displayReport);
    }

    public boolean isIncConfidence0() {
        return incConfidence0;
    }

    public void setIncConfidence0(boolean confidence) {
        this.incConfidence0 = confidence;
        getConfig().setProperty(PARAM_INC_CONFIDENCE_0, confidence);
    }

    public boolean isIncConfidence1() {
        return incConfidence1;
    }

    public void setIncConfidence1(boolean confidence) {
        this.incConfidence1 = confidence;
        getConfig().setProperty(PARAM_INC_CONFIDENCE_1, confidence);
    }

    public boolean isIncConfidence2() {
        return incConfidence2;
    }

    public void setIncConfidence2(boolean confidence) {
        this.incConfidence2 = confidence;
        getConfig().setProperty(PARAM_INC_CONFIDENCE_2, confidence);
    }

    public boolean isIncConfidence3() {
        return incConfidence3;
    }

    public void setIncConfidence3(boolean confidence) {
        this.incConfidence3 = confidence;
        getConfig().setProperty(PARAM_INC_CONFIDENCE_3, confidence);
    }

    public boolean isIncConfidence4() {
        return incConfidence4;
    }

    public void setIncConfidence4(boolean confidence) {
        this.incConfidence4 = confidence;
        getConfig().setProperty(PARAM_INC_CONFIDENCE_4, confidence);
    }

    public boolean isIncRisk0() {
        return incRisk0;
    }

    public void setIncRisk0(boolean risk) {
        this.incRisk0 = risk;
        getConfig().setProperty(PARAM_INC_RISK_0, risk);
    }

    public boolean isIncRisk1() {
        return incRisk1;
    }

    public void setIncRisk1(boolean risk) {
        this.incRisk1 = risk;
        getConfig().setProperty(PARAM_INC_RISK_1, risk);
    }

    public boolean isIncRisk2() {
        return incRisk2;
    }

    public void setIncRisk2(boolean risk) {
        this.incRisk2 = risk;
        getConfig().setProperty(PARAM_INC_RISK_2, risk);
    }

    public boolean isIncRisk3() {
        return incRisk3;
    }

    public void setIncRisk3(boolean risk) {
        this.incRisk3 = risk;
        getConfig().setProperty(PARAM_INC_RISK_3, risk);
    }

    public void setSections(String report, List<String> sections) {
        getConfig().setProperty(PARAM_REPORT_SECTIONS_PREFIX + report, sections);
    }

    public List<Object> getSections(String report) {
        return getConfig().getList(PARAM_REPORT_SECTIONS_PREFIX + report);
    }

    public void setTheme(String report, String theme) {
        getConfig().setProperty(PARAM_REPORT_THEME_PREFIX + report, theme);
    }

    public String getTheme(String report) {
        return getConfig().getString(PARAM_REPORT_THEME_PREFIX + report, null);
    }
}
